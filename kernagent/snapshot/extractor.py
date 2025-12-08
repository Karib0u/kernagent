"""Snapshot extractor built on top of Ghidra/PyGhidra."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TaskProgressColumn,
)

from ..capa_runner import build_capa_summary
from ..log import get_logger

logger = get_logger(__name__)
console = Console()


class SnapshotError(RuntimeError):
    """Raised when snapshot extraction fails."""


try:  # pragma: no cover - requires Ghidra environment
    import pyghidra

    pyghidra.start()
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.model.symbol import RefType
    from ghidra.program.util import DefinedDataIterator, DefinedStringIterator
    from ghidra.util.task import ConsoleTaskMonitor
    from java.util import ArrayList

    _PYGHIDRA_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - handled at runtime
    pyghidra = None
    ConsoleTaskMonitor = None
    DecompInterface = None
    DecompileOptions = None
    RefType = None
    DefinedDataIterator = None
    DefinedStringIterator = None
    ArrayList = None
    _PYGHIDRA_IMPORT_ERROR = exc


class _ThreadLocalEnvironment(threading.local):
    """Thread-local Ghidra handles (decompiler, monitor, block model)."""

    def __init__(self):
        self.decompiler = None
        self.monitor = None
        self.bbm = None


class BinaryArchiveExtractor:
    """Extract comprehensive binary information for AI analysis"""

    def __init__(self, binary_path: Path, verbose: bool = False):
        if _PYGHIDRA_IMPORT_ERROR is not None:
            raise SnapshotError(
                "PyGhidra is required to build snapshots. "
                "Install pyghidra in an environment with Ghidra available."
            ) from _PYGHIDRA_IMPORT_ERROR

        self.binary_path = binary_path.resolve()
        self.verbose = verbose
        self.output_dir = self.binary_path.parent / f"{self.binary_path.stem}.snapshot"
        self.decompiler = None
        self._thread_env = _ThreadLocalEnvironment()
        self._write_lock = threading.Lock()

    def log(self, message: str):
        """Print log message if verbose mode enabled"""
        if self.verbose:
            logger.info(message)
        else:
            logger.debug(message)

    @contextmanager
    def status(self, message: str):
        """
        Show a transient status spinner when not in verbose mode.
        In verbose mode we just log once and proceed.
        """
        status = None
        if self.verbose:
            self.log(message)
            yield status
        else:
            with console.status(f"[cyan]{message}[/]") as status:
                yield status

    def _configure_decompiler(self, decompiler):
        """Configure decompiler for optimal performance."""
        opts = DecompileOptions()

        # Memory limits (slight increase from default 50MB)
        opts.setMaxPayloadMBytes(64)

        decompiler.setOptions(opts)
        return decompiler

    def _get_decompile_timeout(self, function) -> int:
        """
        Calculate appropriate decompilation timeout based on function size.

        Small functions rarely need more than a few seconds.
        Large functions may need the full timeout.
        """
        try:
            body = function.getBody()
            size = sum(r.getMaxAddress().subtract(r.getMinAddress()) + 1 for r in body)

            if size < 100:  # Tiny function (<100 bytes)
                return 5
            elif size < 500:  # Small function
                return 10
            elif size < 2000:  # Medium function
                return 20
            elif size < 10000:  # Large function
                return 45
            else:  # Very large function
                return 60

        except Exception:
            return 30  # Default fallback

    def _init_thread_worker(self, program):
        """Ensure thread-local decompiler, monitor, and block model are set."""
        if self._thread_env.decompiler is None:
            self._thread_env.decompiler = DecompInterface()
            self._thread_env.decompiler.openProgram(program)
            self._configure_decompiler(self._thread_env.decompiler)
        if self._thread_env.monitor is None:
            self._thread_env.monitor = ConsoleTaskMonitor()
        if self._thread_env.bbm is None:
            from ghidra.program.model.block import BasicBlockModel

            self._thread_env.bbm = BasicBlockModel(program)
        return self._thread_env

    def _decompile_single_function(self, func, program, timeout=None):
        """
        Decompile a single function (designed for parallel execution).

        Args:
            func: Ghidra Function object
            program: Ghidra Program object
            timeout: Decompilation timeout in seconds (None = adaptive)

        Returns:
            Tuple of (entry_point_str, decompiled_code_or_None)
        """
        try:
            decompiler = self._get_thread_decompiler(program)
            monitor = ConsoleTaskMonitor()

            # Use adaptive timeout if not specified
            if timeout is None:
                timeout = self._get_decompile_timeout(func)

            result = decompiler.decompileFunction(func, timeout, monitor)

            if result and result.decompileCompleted():
                decomp_func = result.getDecompiledFunction()
                if decomp_func:
                    return (str(func.getEntryPoint()), decomp_func.getC())

            return (str(func.getEntryPoint()), None)

        except Exception as e:
            logger.warning("Decompilation failed for %s: %s", func.getName(), e)
            return (str(func.getEntryPoint()), None)

    def _cleanup_thread_decompilers(self):
        """Dispose of any thread-local decompiler instances."""
        if self._thread_env.decompiler:
            try:
                self._thread_env.decompiler.dispose()
            except Exception:
                pass
            self._thread_env.decompiler = None
        self._thread_env.monitor = None
        self._thread_env.bbm = None

    def _build_xref_maps(self, program, monitor):
        """
        Build caller/callee maps for the entire program.

        Returns:
            Tuple of (callers_map, callees_map)
            callers_map: {ea: [list of caller eas]}
            callees_map: {ea: [list of {ea, name, type} dicts]}
        """
        self.log("Building cross-reference maps...")

        callers = {}  # ea -> list of caller eas
        callees = {}  # ea -> list of callee dicts

        func_mgr = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()

        for func in func_mgr.getFunctions(True):
            ea = str(func.getEntryPoint())
            callers[ea] = []
            callees[ea] = []

            # Get callers (references TO this function's entry point)
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                from_addr = ref.getFromAddress()
                caller = func_mgr.getFunctionContaining(from_addr)
                if caller:
                    caller_ea = str(caller.getEntryPoint())
                    if caller_ea not in callers[ea]:
                        callers[ea].append(caller_ea)

            # Get callees (call/jump refs FROM this function's body)
            body = func.getBody()
            seen_callees = set()

            for addr in body.getAddresses(True):
                for ref in ref_mgr.getReferencesFrom(addr):
                    ref_type = ref.getReferenceType()
                    if ref_type.isCall() or ref_type.isJump():
                        to_addr = ref.getToAddress()
                        callee = func_mgr.getFunctionAt(to_addr)
                        if callee:
                            callee_ea = str(to_addr)
                            if callee_ea not in seen_callees:
                                seen_callees.add(callee_ea)
                                callees[ea].append(
                                    {
                                        "ea": callee_ea,
                                        "name": callee.getName(),
                                        "type": str(ref_type),
                                    }
                                )

        return callers, callees

    def _run_selective_analysis(self, program, monitor):
        """
        Run only essential analyzers for decompilation.

        Essential analyzers (in recommended order):
        - Disassembly-related: Find code, create functions
        - Reference analysis: Track calls and data refs
        - Decompiler prep: Parameter identification

        Skipped analyzers (slow, non-essential):
        - DWARF, PDB (debug info - very slow if present)
        - Demangler (slow for C++ heavy binaries)
        - ASCII Strings (we extract strings separately)
        - Embedded Media, GCC/Windows exception handlers
        """
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager

        mgr = AutoAnalysisManager.getAnalysisManager(program)

        # Essential analyzers for quality decompilation
        essential = {
            "Disassembly",
            "Function Start Search",
            "Function Start Search After Code",
            "Function Start Search After Data",
            "Subroutine References",
            "Reference",
            "Entry Point",
            "External Entry References",
            "Shared Return Calls",
            "Stack",
            "Decompiler Parameter ID",
            "Non-Returning Functions - Discovered",
            "Non-Returning Functions - Known",
            "Call Convention Identification",
        }

        configured = False
        try:
            analyzer_mgr = mgr.getAnalyzerManager()
            for descriptor in analyzer_mgr.getAnalyzerDescriptors():
                name = descriptor.getName()
                analyzer_mgr.setEnabled(name, name in essential)
            configured = True
        except Exception:
            try:
                idx = 0
                while True:
                    analyzer = mgr.getAnalyzer(idx)
                    name = analyzer.getName()
                    analyzer.setEnabled(name in essential)
                    idx += 1
                configured = True
            except Exception:
                configured = False

        if configured:
            self.log("Selective analyzers configured")
        else:
            self.log("Analyzer configuration API unavailable; using defaults")

        mgr.startAnalysis(monitor)
        try:
            mgr.waitForAnalysis(None, monitor)
        except TypeError:
            mgr.waitForAnalysis(monitor)

    def sanitize_filename(
        self, func_name: str, address: str, max_length: int = 200
    ) -> str:
        """
        Create a safe filename from function name and address.

        Args:
            func_name: The function name (may be very long due to C++ mangling)
            address: The function address (unique identifier)
            max_length: Maximum filename length (excluding extension)

        Returns:
            A safe filename string
        """
        # Remove or replace problematic characters
        safe_name = func_name.replace(":", "_").replace("<", "_").replace(">", "_")
        safe_name = safe_name.replace("*", "_").replace("?", "_").replace('"', "_")
        safe_name = safe_name.replace("|", "_").replace("/", "_").replace("\\", "_")

        # Clean up the address (remove 0x prefix if present and any colons)
        clean_addr = address.replace("0x", "").replace(":", "")

        # If the name is short enough, use it directly with address
        # Reserve space for address, underscore, and extension (.c = 2 chars)
        addr_length = len(clean_addr)
        available_for_name = max_length - addr_length - 1  # -1 for underscore

        if len(safe_name) <= available_for_name:
            return f"{clean_addr}_{safe_name}.c"

        # Name is too long - truncate and add hash to ensure uniqueness
        truncate_length = (
            available_for_name - 9
        )  # Reserve 8 chars for hash + underscore
        if truncate_length < 10:
            truncate_length = 10

        truncated_name = safe_name[:truncate_length]

        # Create a short hash of the full name for uniqueness
        name_hash = hashlib.md5(func_name.encode()).hexdigest()[:8]

        return f"{clean_addr}_{truncated_name}_{name_hash}.c"

    def calculate_hashes(self) -> Dict[str, str]:
        """Calculate MD5, SHA256, and CRC32 hashes of the binary"""
        self.log("Calculating file hashes...")

        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(self.binary_path, "rb") as f:
            data = f.read()
            md5.update(data)
            sha256.update(data)

        import zlib

        crc32 = zlib.crc32(data) & 0xFFFFFFFF

        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
            "crc32": hex(crc32),
        }

    def extract_metadata(self, program) -> Dict[str, Any]:
        """Extract program metadata"""
        self.log("Extracting metadata...")

        hashes = self.calculate_hashes()

        # Get program info
        compiler_spec = program.getCompilerSpec()
        language = program.getLanguage()

        metadata = {
            "file_name": program.getName(),
            "file_path": str(self.binary_path),
            "image_base": str(program.getImageBase()),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress()),
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
            "crc32": hashes["crc32"],
            "file_size": self.binary_path.stat().st_size,
            "language": str(language.getLanguageID()),
            "compiler": (
                str(compiler_spec.getCompilerSpecID()) if compiler_spec else "Unknown"
            ),
            "endian": "big" if language.isBigEndian() else "little",
            "processor": str(language.getProcessor()),
            "executable_format": program.getExecutableFormat(),
            "creation_date": str(program.getCreationDate()),
        }

        # Get executable info
        exe_format = program.getExecutableFormat()
        if exe_format:
            metadata["format"] = exe_format

        return metadata

    def extract_instruction_info(self, instruction, program) -> Dict[str, Any]:
        """Extract detailed instruction information"""
        addr = instruction.getAddress()

        # Get instruction bytes
        instr_bytes = []
        try:
            num_bytes = instruction.getLength()
            for i in range(num_bytes):
                byte = program.getMemory().getByte(addr.add(i))
                instr_bytes.append(byte & 0xFF)
        except Exception:
            pass

        bytes_hex = "".join(f"{b:02x}" for b in instr_bytes)

        # Get operands
        operands = []
        num_operands = instruction.getNumOperands()
        for i in range(num_operands):
            op_str = instruction.getDefaultOperandRepresentation(i)
            operands.append(op_str)

        return {
            "ea": str(addr),
            "mnem": instruction.getMnemonicString(),
            "opstr": ", ".join(operands) if operands else "",
            "bytes": bytes_hex,
            "size": instruction.getLength(),
            "operands": operands,
        }

    def get_xrefs_to_function(self, function, program) -> List[str]:
        """Get cached cross-references TO this function (callers)"""
        ea = str(function.getEntryPoint())
        if hasattr(self, "callers_map") and ea in self.callers_map:
            return self.callers_map[ea]

        # Fallback to original implementation if maps not built
        xrefs_in = []
        entry_point = function.getEntryPoint()

        ref_mgr = program.getReferenceManager()
        references = ref_mgr.getReferencesTo(entry_point)

        for ref in references:
            from_addr = ref.getFromAddress()
            # Get the function containing this reference
            func_mgr = program.getFunctionManager()
            caller = func_mgr.getFunctionContaining(from_addr)
            if caller:
                xrefs_in.append(str(caller.getEntryPoint()))

        return list(set(xrefs_in))  # Remove duplicates

    def get_xrefs_from_function(self, function, program) -> List[Dict[str, str]]:
        """Get cached cross-references FROM this function (callees)"""
        ea = str(function.getEntryPoint())
        if hasattr(self, "callees_map") and ea in self.callees_map:
            return self.callees_map[ea]

        # Fallback to original implementation if maps not built
        xrefs_out = []

        body = function.getBody()
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()

        # Iterate through all addresses in function body
        addr_iter = body.getAddresses(True)
        for addr in addr_iter:
            refs = ref_mgr.getReferencesFrom(addr)
            for ref in refs:
                ref_type = ref.getReferenceType()
                # Only interested in call references
                if ref_type.isCall() or ref_type.isJump():
                    to_addr = ref.getToAddress()
                    callee = func_mgr.getFunctionAt(to_addr)
                    if callee:
                        xrefs_out.append(
                            {
                                "ea": str(to_addr),
                                "name": callee.getName(),
                                "type": str(ref_type),
                            }
                        )

        return xrefs_out

    def get_basic_blocks(self, function, program, monitor) -> List[Dict[str, Any]]:
        """Extract basic block information"""
        basic_blocks = []

        try:
            # Use cached BasicBlockModel if available
            if hasattr(self, "bbm") and self.bbm:
                bbm = self.bbm
            else:
                from ghidra.program.model.block import BasicBlockModel

                bbm = BasicBlockModel(program)

            # Get function body address set
            func_body = function.getBody()

            # Get all blocks in the program
            block_iter = bbm.getCodeBlocks(monitor)

            # Filter blocks that belong to this function
            while block_iter.hasNext():
                block = block_iter.next()
                block_start = block.getMinAddress()

                # Check if this block is within the function's address range
                if func_body.contains(block_start):
                    bb_info = {
                        "start": str(block.getMinAddress()),
                        "end": str(block.getMaxAddress()),
                    }
                    basic_blocks.append(bb_info)

        except Exception as e:
            logger.warning("Could not extract basic blocks: %s", e)

        return basic_blocks

    def extract_comments(self, function, program) -> List[Dict[str, str]]:
        """Extract all comments in a function"""
        comments = []

        body = function.getBody()
        listing = program.getListing()

        addr_iter = body.getAddresses(True)
        for addr in addr_iter:
            code_unit = listing.getCodeUnitAt(addr)
            if code_unit:
                # EOL comment
                eol = code_unit.getComment(0)  # EOL_COMMENT = 0
                if eol:
                    comments.append({"ea": str(addr), "kind": "eol", "text": eol})

                # Pre comment
                pre = code_unit.getComment(1)  # PRE_COMMENT = 1
                if pre:
                    comments.append({"ea": str(addr), "kind": "pre", "text": pre})

                # Post comment
                post = code_unit.getComment(2)  # POST_COMMENT = 2
                if post:
                    comments.append({"ea": str(addr), "kind": "post", "text": post})

                # Plate comment
                plate = code_unit.getComment(3)  # PLATE_COMMENT = 3
                if plate:
                    comments.append({"ea": str(addr), "kind": "plate", "text": plate})

        return comments

    def _process_single_function(self, function, program):
        """
        Extract function metadata and optionally decompile it.

        Returns:
            Tuple (func_data, decomp_filename_or_None, decomp_code_or_None)
        """
        env = self._init_thread_worker(program)
        entry_point = function.getEntryPoint()
        ea_str = str(entry_point)
        memory = program.getMemory()
        listing = program.getListing()

        func_data: Dict[str, Any] = {
            "ea": ea_str,
            "name": function.getName(),
            "ranges": [
                [str(addr_range.getMinAddress()), str(addr_range.getMaxAddress())]
                for addr_range in function.getBody()
            ],
            "xrefs_in": self.get_xrefs_to_function(function, program),
            "xrefs_out": self.get_xrefs_from_function(function, program),
        }

        signature = function.getSignature()
        if signature:
            func_data["prototype"] = str(signature.getPrototypeString())

        # Instructions (bulk memory reads)
        instructions = []
        for ins in listing.getInstructions(function.getBody(), True):
            addr = ins.getAddress()
            length = ins.getLength()
            buf = bytearray(length)
            try:
                read = memory.getBytes(addr, buf)
                if read != length:
                    buf = buf[: max(0, read)]
            except Exception:
                buf = bytearray()
            operands = [
                ins.getDefaultOperandRepresentation(i)
                for i in range(ins.getNumOperands())
            ]
            instructions.append(
                {
                    "ea": str(addr),
                    "mnem": ins.getMnemonicString(),
                    "opstr": ", ".join(operands) if operands else "",
                    "bytes": "".join(f"{b:02x}" for b in buf),
                    "size": length,
                    "operands": operands,
                }
            )
        func_data["insn"] = instructions

        # Function bytes (bulk)
        try:
            all_bytes = []
            for addr_range in function.getBody():
                start = addr_range.getMinAddress()
                length = addr_range.getMaxAddress().subtract(start) + 1
                buf = bytearray(length)
                read = memory.getBytes(start, buf)
                if read > 0:
                    all_bytes.append("".join(f"{b:02x}" for b in buf[:read]))
            func_data["bytes_concat"] = "".join(all_bytes)
        except Exception as exc:
            func_data["bytes_concat"] = ""
            logger.warning(
                "Could not extract function bytes for %s: %s", function.getName(), exc
            )

        # Metrics (inline to avoid extra passes)
        metrics: Dict[str, Any] = {}
        body = function.getBody()
        total_size = 0
        for addr_range in body:
            total_size += (
                addr_range.getMaxAddress().subtract(addr_range.getMinAddress()) + 1
            )
        metrics["size_bytes"] = total_size
        metrics["instruction_count"] = len(instructions)

        bb_count = 0
        edge_count = 0
        try:
            blocks = []
            block_iter = env.bbm.getCodeBlocks(env.monitor)
            while block_iter.hasNext():
                block = block_iter.next()
                if body.contains(block.getMinAddress()):
                    bb_count += 1
                    blocks.append(block)
            for block in blocks:
                dests = block.getDestinations(env.monitor)
                while dests.hasNext():
                    dest = dests.next()
                    if body.contains(dest.getDestinationAddress()):
                        edge_count += 1
            metrics["basic_block_count"] = bb_count
            metrics["cyclomatic_complexity"] = (
                max(1, edge_count - bb_count + 2) if bb_count else 1
            )
        except Exception as exc:
            metrics["basic_block_count"] = bb_count
            metrics["cyclomatic_complexity"] = 1
            logger.debug(
                "Basic block metrics failed for %s: %s", function.getName(), exc
            )

        if hasattr(self, "callers_map"):
            metrics["callers_count"] = len(self.callers_map.get(ea_str, []))
            metrics["callees_count"] = len(self.callees_map.get(ea_str, []))
        else:
            metrics["callers_count"] = len(
                self.get_xrefs_to_function(function, program)
            )
            metrics["callees_count"] = len(
                self.get_xrefs_from_function(function, program)
            )

        func_data["metrics"] = metrics

        # Basic blocks listing
        basic_blocks = []
        try:
            block_iter = env.bbm.getCodeBlocks(env.monitor)
            while block_iter.hasNext():
                block = block_iter.next()
                if body.contains(block.getMinAddress()):
                    basic_blocks.append(
                        {
                            "start": str(block.getMinAddress()),
                            "end": str(block.getMaxAddress()),
                        }
                    )
        except Exception as exc:
            logger.debug(
                "Failed to enumerate basic blocks for %s: %s", function.getName(), exc
            )
        func_data["bb"] = basic_blocks

        # Comments
        func_data["comments"] = self.extract_comments(function, program)

        # Decompile
        decomp_filename = None
        decomp_code = None
        try:
            timeout = self._get_decompile_timeout(function)
            result = env.decompiler.decompileFunction(function, timeout, env.monitor)
            if result and result.decompileCompleted():
                decomp = result.getDecompiledFunction()
                if decomp:
                    decomp_code = decomp.getC()
                    decomp_filename = self.sanitize_filename(function.getName(), ea_str)
                    func_data["decomp_path"] = f"decomp/{decomp_filename}"
        except Exception as exc:
            logger.warning("Decompilation failed for %s: %s", function.getName(), exc)
            func_data["decomp_path"] = None

        if decomp_code is None:
            func_data["decomp_path"] = None

        return func_data, decomp_filename, decomp_code

    def extract_strings(self, program) -> List[Dict[str, Any]]:
        """Extract all defined strings with their cross-references"""
        self.log("Extracting strings...")

        strings_data = []

        try:
            from ghidra.program.util import DefinedStringIterator

            # Use DefinedStringIterator to find strings
            string_iter = DefinedStringIterator.forProgram(program)

            ref_mgr = program.getReferenceManager()
            func_mgr = program.getFunctionManager()

            for string_data in string_iter:
                addr = string_data.getAddress()

                # Get string value
                try:
                    value = str(string_data.getValue())
                except Exception:
                    value = ""

                # Get cross-references to this string
                xrefs = []
                refs = ref_mgr.getReferencesTo(addr)
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    func = func_mgr.getFunctionContaining(from_addr)
                    xrefs.append(
                        {
                            "from": str(from_addr),
                            "function": func.getName() if func else None,
                        }
                    )

                strings_data.append(
                    {
                        "ea": str(addr),
                        "value": value,
                        "length": string_data.getLength(),
                        "xrefs": xrefs,
                    }
                )

        except Exception as e:
            logger.warning("Error extracting strings: %s", e)

        return strings_data

    def extract_imports_exports(self, program) -> Dict[str, List[Dict[str, Any]]]:
        """Extract import and export information"""
        self.log("Extracting imports and exports...")

        imports = []
        exports = []

        try:
            symbol_table = program.getSymbolTable()
            external_manager = program.getExternalManager()

            # Extract imports (external symbols)
            for ext_name in external_manager.getExternalLibraryNames():
                ext_locs = external_manager.getExternalLocations(ext_name)

                while ext_locs.hasNext():
                    ext_loc = ext_locs.next()

                    import_info = {
                        "name": ext_loc.getLabel(),
                        "library": ext_name,
                        "address": (
                            str(ext_loc.getAddress()) if ext_loc.getAddress() else None
                        ),
                        "ordinal": (
                            ext_loc.getAddress().getOffset()
                            if ext_loc.getAddress() and ext_loc.isFunction()
                            else None
                        ),
                    }

                    # Get function signature if available
                    func = ext_loc.getFunction()
                    if func:
                        import_info["type"] = "function"
                        sig = func.getSignature()
                        if sig:
                            import_info["signature"] = str(sig.getPrototypeString())
                    else:
                        import_info["type"] = "data"

                    imports.append(import_info)

            # Extract exports (public symbols)
            symbol_iter = symbol_table.getSymbolIterator()
            for symbol in symbol_iter:
                if symbol.isExternal():
                    continue

                # Check if symbol is exported (public/global)
                if symbol.isGlobal() or symbol.isExternalEntryPoint():
                    export_info = {
                        "name": symbol.getName(),
                        "address": str(symbol.getAddress()),
                        "type": str(symbol.getSymbolType()),
                    }

                    # If it's a function, get signature
                    if symbol.getSymbolType().toString() == "Function":
                        func_mgr = program.getFunctionManager()
                        func = func_mgr.getFunctionAt(symbol.getAddress())
                        if func:
                            sig = func.getSignature()
                            if sig:
                                export_info["signature"] = str(sig.getPrototypeString())

                    exports.append(export_info)

        except Exception as e:
            logger.warning("Error extracting imports/exports: %s", e)

        return {"imports": imports, "exports": exports}

    def extract_memory_sections(self, program) -> List[Dict[str, Any]]:
        """Extract memory section/segment information"""
        self.log("Extracting memory sections...")

        sections = []

        try:
            memory = program.getMemory()

            for block in memory.getBlocks():
                section_info = {
                    "name": block.getName(),
                    "start": str(block.getStart()),
                    "end": str(block.getEnd()),
                    "size": block.getSize(),
                    "permissions": {
                        "read": block.isRead(),
                        "write": block.isWrite(),
                        "execute": block.isExecute(),
                    },
                    "initialized": block.isInitialized(),
                    "type": str(block.getType()),
                    "comment": block.getComment() if block.getComment() else None,
                }

                sections.append(section_info)

        except Exception as e:
            logger.warning("Error extracting memory sections: %s", e)

        return sections

    def calculate_cyclomatic_complexity(self, function, program, monitor) -> int:
        """Calculate cyclomatic complexity for a function"""
        try:
            # Use cached BasicBlockModel if available
            if hasattr(self, "bbm") and self.bbm:
                bbm = self.bbm
            else:
                from ghidra.program.model.block import BasicBlockModel

                bbm = BasicBlockModel(program)

            func_body = function.getBody()

            # Count basic blocks in this function
            block_iter = bbm.getCodeBlocks(monitor)
            block_count = 0
            edge_count = 0

            blocks_in_func = []
            while block_iter.hasNext():
                block = block_iter.next()
                if func_body.contains(block.getMinAddress()):
                    block_count += 1
                    blocks_in_func.append(block)

            # Count edges (destinations from each block)
            for block in blocks_in_func:
                dests = block.getDestinations(monitor)
                while dests.hasNext():
                    dest = dests.next()
                    if func_body.contains(dest.getDestinationAddress()):
                        edge_count += 1

            # Cyclomatic complexity: M = E - N + 2P (P=1 for single connected component)
            if block_count > 0:
                complexity = edge_count - block_count + 2
                return max(1, complexity)  # Minimum complexity is 1
            else:
                return 1

        except Exception:
            return 0

    def extract_function_metrics(self, function, program, monitor) -> Dict[str, Any]:
        """Extract metrics for a function"""
        metrics = {}

        try:
            # Basic size metrics
            body = function.getBody()
            total_size = 0
            for addr_range in body:
                total_size += (
                    addr_range.getMaxAddress().subtract(addr_range.getMinAddress()) + 1
                )

            metrics["size_bytes"] = total_size

            # Count instructions
            listing = program.getListing()
            instr_count = 0
            addr_iter = body.getAddresses(True)
            for addr in addr_iter:
                if listing.getInstructionAt(addr):
                    instr_count += 1

            metrics["instruction_count"] = instr_count

            # Count basic blocks
            from ghidra.program.model.block import BasicBlockModel

            bbm = BasicBlockModel(program)
            block_iter = bbm.getCodeBlocks(monitor)
            bb_count = 0

            while block_iter.hasNext():
                block = block_iter.next()
                if body.contains(block.getMinAddress()):
                    bb_count += 1

            metrics["basic_block_count"] = bb_count

            # Cyclomatic complexity
            metrics["cyclomatic_complexity"] = self.calculate_cyclomatic_complexity(
                function, program, monitor
            )

            # Count incoming and outgoing calls (use cached maps if available)
            ea = str(function.getEntryPoint())
            if hasattr(self, "callers_map"):
                metrics["callers_count"] = len(self.callers_map.get(ea, []))
                metrics["callees_count"] = len(self.callees_map.get(ea, []))
            else:
                metrics["callers_count"] = len(
                    self.get_xrefs_to_function(function, program)
                )
                metrics["callees_count"] = len(
                    self.get_xrefs_from_function(function, program)
                )

        except Exception as e:
            logger.warning(
                "Error calculating metrics for %s: %s", function.getName(), e
            )

        return metrics

    def extract_call_graph(self, program) -> List[Dict[str, str]]:
        """Extract call graph edges (caller -> callee relationships)"""
        self.log("Extracting call graph...")

        edges = []
        seen_edges = set()

        try:
            func_manager = program.getFunctionManager()
            functions = func_manager.getFunctions(True)

            for func in functions:
                caller_addr = str(func.getEntryPoint())
                caller_name = func.getName()

                # Get all functions this one calls
                xrefs_out = self.get_xrefs_from_function(func, program)

                for xref in xrefs_out:
                    callee_addr = xref["ea"]
                    callee_name = xref["name"]

                    # Create unique edge identifier to avoid duplicates
                    edge_id = f"{caller_addr}->{callee_addr}"

                    if edge_id not in seen_edges:
                        seen_edges.add(edge_id)
                        edges.append(
                            {
                                "from": caller_addr,
                                "from_name": caller_name,
                                "to": callee_addr,
                                "to_name": callee_name,
                                "type": xref.get("type", "call"),
                            }
                        )

        except Exception as e:
            logger.warning("Error extracting call graph: %s", e)

        return edges

    def extract_equates(self, program) -> List[Dict[str, Any]]:
        """Extract equate (named constant) definitions"""
        self.log("Extracting equates...")

        equates = []

        try:
            equate_table = program.getEquateTable()
            equate_iter = equate_table.getEquates()

            for equate in equate_iter:
                equate_info = {
                    "name": equate.getName(),
                    "value": equate.getValue(),
                    "reference_count": equate.getReferenceCount(),
                }

                # Get a few reference addresses (limit to 10 for size)
                refs = []
                ref_iter = equate.getReferences()
                count = 0
                while ref_iter.hasNext() and count < 10:
                    ref = ref_iter.next()
                    refs.append(str(ref))
                    count += 1

                equate_info["references"] = refs
                equates.append(equate_info)

        except Exception as e:
            logger.warning("Error extracting equates: %s", e)

        return equates

    def extract_data_sections(self, program) -> List[Dict[str, Any]]:
        """Extract defined data (globals, arrays, etc.)"""
        self.log("Extracting data sections...")

        data_list = []

        try:
            listing = program.getListing()
            memory = program.getMemory()

            # Iterate through all memory blocks
            for block in memory.getBlocks():
                # Skip executable blocks
                if block.isExecute():
                    continue

                # Get data in this block
                data_iter = listing.getDefinedData(block.getStart(), True)

                for data in data_iter:
                    if block.contains(data.getAddress()):
                        addr = data.getAddress()

                        data_info = {
                            "ea": str(addr),
                            "name": None,
                            "type": (
                                str(data.getDataType().getName())
                                if data.getDataType()
                                else "undefined"
                            ),
                            "length": data.getLength(),
                        }

                        # Get symbol/name if exists
                        symbol_table = program.getSymbolTable()
                        symbols = symbol_table.getSymbols(addr)
                        if symbols:
                            for symbol in symbols:
                                data_info["name"] = symbol.getName()
                                break

                        # Try to get value
                        try:
                            value = data.getValue()
                            if value is not None:
                                data_info["value"] = str(value)
                        except Exception:
                            pass

                        data_list.append(data_info)

        except Exception as e:
            logger.warning("Error extracting data: %s", e)

        return data_list

    def extract_all(self) -> Path:
        """Main extraction routine."""
        if self.verbose:
            logger.info("Starting snapshot extraction for %s", self.binary_path)
        else:
            console.print(
                f"[bold cyan]Starting snapshot extraction:[/] {self.binary_path.name}"
            )

        self.output_dir.mkdir(exist_ok=True)
        decomp_dir = self.output_dir / "decomp"
        decomp_dir.mkdir(exist_ok=True)

        summary: Dict[str, Any] | None = None
        metadata: Dict[str, Any] | None = None
        meta_path = self.output_dir / "meta.json"
        capa_summary_path: Path | None = None

        try:
            with pyghidra.open_program(self.binary_path, analyze=True) as flat_api:
                with self.status("Loading program..."):
                    program = flat_api.getCurrentProgram()
                    monitor = ConsoleTaskMonitor()
                    self.log(f"Program loaded: {program.getName()}")
                if not self.verbose:
                    console.print("[green]✓[/] Program analyzed and loaded")

                # Build xref maps once
                with self.status("Building cross-reference maps..."):
                    self.callers_map, self.callees_map = self._build_xref_maps(
                        program, monitor
                    )
                if not self.verbose:
                    total_refs = sum(len(v) for v in self.callers_map.values())
                    console.print(
                        f"[green]✓[/] Built xref maps ([bold]{total_refs}[/bold] references)"
                    )

                # Phase 2: Extract metadata
                with self.status("Extracting metadata..."):
                    metadata = self.extract_metadata(program)
                    with open(meta_path, "w", encoding="utf-8") as f:
                        json.dump(metadata, f, indent=2)
                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Binary metadata extracted ([dim]{metadata.get('executable_format', 'unknown')}[/dim])"
                    )
                self.log(f"Metadata extracted (SHA256: {metadata['sha256']})")

                # Phase 3: Extract sections
                with self.status("Extracting memory sections..."):
                    sections = self.extract_memory_sections(program)
                    with open(
                        self.output_dir / "sections.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump(sections, f, indent=2)
                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Found [bold]{len(sections)}[/bold] memory sections"
                    )

                # Phase 4: Extract imports/exports
                with self.status("Extracting imports/exports..."):
                    imports_exports = self.extract_imports_exports(program)
                    with open(
                        self.output_dir / "imports_exports.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump(imports_exports, f, indent=2)
                if not self.verbose:
                    imp_count = len(imports_exports.get("imports", []))
                    exp_count = len(imports_exports.get("exports", []))
                    console.print(
                        f"[green]✓[/] Found [bold]{imp_count}[/bold] imports and [bold]{exp_count}[/bold] exports"
                    )

                # Phase 5: Extract equates
                with self.status("Extracting equates..."):
                    equates = self.extract_equates(program)
                    with open(
                        self.output_dir / "equates.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump(equates, f, indent=2)
                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Extracted [bold]{len(equates)}[/bold] equates"
                    )

                # Phase 6: Process functions (parallel, streaming)
                func_manager = program.getFunctionManager()
                functions = list(func_manager.getFunctions(True))
                if not functions:
                    raise SnapshotError("No functions discovered after analysis.")

                num_workers = min(8, max(4, os.cpu_count() or 4))
                self.log(f"Using {num_workers} threads for function processing")

                functions_path = self.output_dir / "functions.jsonl"
                index_map = {"by_name": {}, "by_ea": {}}
                decomp_count = 0
                processed_count = 0

                progress_ctx = Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    transient=True,
                    refresh_per_second=4,
                )

                if self.verbose:
                    progress_ctx = None

                def _write_function(func_data, decomp_filename, decomp_code, idx):
                    nonlocal decomp_count
                    if decomp_filename and decomp_code:
                        decomp_path = decomp_dir / decomp_filename
                        with open(decomp_path, "w", encoding="utf-8") as f:
                            f.write(decomp_code)
                        decomp_count += 1
                    # Update index
                    index_map["by_name"][func_data["name"]] = func_data["ea"]
                    index_map["by_ea"][func_data["ea"]] = idx
                    with open(functions_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(func_data) + "\n")

                # Ensure functions file is empty
                functions_path.write_text("", encoding="utf-8")

                if progress_ctx:
                    with progress_ctx as progress:
                        task_id = progress.add_task(
                            f"[cyan]Processing {len(functions)} functions ({num_workers} threads)...",
                            total=len(functions),
                        )
                        with ThreadPoolExecutor(max_workers=num_workers) as executor:
                            futures = {
                                executor.submit(
                                    self._process_single_function, func, program
                                ): idx
                                for idx, func in enumerate(functions)
                            }
                            for future in as_completed(futures):
                                func_data, decomp_filename, decomp_code = (
                                    future.result()
                                )
                                idx = futures[future]
                                with self._write_lock:
                                    _write_function(
                                        func_data, decomp_filename, decomp_code, idx
                                    )
                                    processed_count += 1
                                progress.update(task_id, advance=1)
                else:
                    with ThreadPoolExecutor(max_workers=num_workers) as executor:
                        futures = {
                            executor.submit(
                                self._process_single_function, func, program
                            ): idx
                            for idx, func in enumerate(functions)
                        }
                        for completed, future in enumerate(as_completed(futures), 1):
                            func_data, decomp_filename, decomp_code = future.result()
                            idx = futures[future]
                            with self._write_lock:
                                _write_function(
                                    func_data, decomp_filename, decomp_code, idx
                                )
                                processed_count += 1
                            if completed % 50 == 0:
                                self.log(
                                    f"Processed {completed}/{len(functions)} functions"
                                )

                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Decompiled [bold]{decomp_count}[/bold] of [bold]{len(functions)}[/bold] functions"
                    )

                # Phase 7: Extract call graph
                with self.status("Extracting call graph..."):
                    call_graph = self.extract_call_graph(program)
                    with open(
                        self.output_dir / "callgraph.jsonl", "w", encoding="utf-8"
                    ) as f:
                        for edge in call_graph:
                            f.write(json.dumps(edge) + "\n")
                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Extracted [bold]{len(call_graph)}[/bold] call graph edges"
                    )

                # Phase 8: Create index
                with self.status("Creating index..."):
                    with open(
                        self.output_dir / "index.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump(index_map, f, indent=2)
                if not self.verbose:
                    console.print("[green]✓[/] Function index created")

                # Phase 9: Extract strings
                with self.status("Extracting strings..."):
                    strings_data = self.extract_strings(program)
                    with open(
                        self.output_dir / "strings.jsonl", "w", encoding="utf-8"
                    ) as f:
                        for string_data in strings_data:
                            f.write(json.dumps(string_data) + "\n")
                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Found [bold]{len(strings_data)}[/bold] strings"
                    )

                # Phase 10: Extract data sections
                with self.status("Extracting data sections..."):
                    data_sections = self.extract_data_sections(program)
                    with open(
                        self.output_dir / "data.jsonl", "w", encoding="utf-8"
                    ) as f:
                        for data_item in data_sections:
                            f.write(json.dumps(data_item) + "\n")

                    data_index = {"by_name": {}}
                    for data_item in data_sections:
                        if data_item.get("name"):
                            data_index["by_name"][data_item["name"]] = data_item["ea"]

                    with open(
                        self.output_dir / "data_index.json", "w", encoding="utf-8"
                    ) as f:
                        json.dump(data_index, f, indent=2)
                if not self.verbose:
                    console.print(
                        f"[green]✓[/] Extracted [bold]{len(data_sections)}[/bold] data items"
                    )

                summary = {
                    "functions_total": len(functions),
                    "functions_decompiled": decomp_count,
                    "sections": len(sections),
                    "imports": len(imports_exports["imports"]),
                    "exports": len(imports_exports["exports"]),
                    "call_edges": len(call_graph),
                    "equates": len(equates),
                    "strings": len(strings_data),
                    "data_items": len(data_sections),
                }
        except Exception as exc:  # pragma: no cover - depends on Ghidra runtime
            raise SnapshotError(f"Snapshot extraction failed: {exc}") from exc
        finally:
            if self.decompiler:
                self.decompiler.dispose()
            self._cleanup_thread_decompilers()

        # Phase 11: Build CAPA summary (outside Ghidra context)
        if metadata:
            try:
                if not self.verbose:
                    console.print("🔍 Running CAPA analysis...")
                capa_summary_path = build_capa_summary(
                    self.binary_path, self.output_dir, verbose=self.verbose
                )
                if capa_summary_path and not self.verbose:
                    # Read the summary to get stats
                    try:
                        with capa_summary_path.open() as f:
                            capa_data = json.load(f)
                            rules_count = capa_data.get("counts", {}).get("rules", 0)
                            attack_count = capa_data.get("counts", {}).get(
                                "attack_mappings", 0
                            )
                            console.print(
                                f"[green]✓[/] CAPA found [bold]{rules_count}[/bold] rules, [bold]{attack_count}[/bold] MITRE ATT&CK mappings"
                            )
                    except Exception:
                        console.print("[green]✓[/] CAPA analysis complete")
                elif not self.verbose:
                    console.print("[yellow]⚠[/] CAPA analysis produced no results")
            except Exception as exc:  # pragma: no cover - runtime specific
                logger.warning("capa summary generation failed: %s", exc)
                capa_summary_path = None

            if capa_summary_path:
                metadata.setdefault("artifacts", {})["capa_summary"] = (
                    capa_summary_path.name
                )
                with meta_path.open("w", encoding="utf-8") as f:
                    json.dump(metadata, f, indent=2)

        # Copy binary to snapshot
        if not self.verbose:
            console.print("📦 Finalizing snapshot...")
        shutil.copy2(self.binary_path, self.output_dir / self.binary_path.name)

        # Clean up temporary Ghidra project directory
        ghidra_temp_dir = self.binary_path.parent / f"{self.binary_path.name}_ghidra"
        if ghidra_temp_dir.exists():
            try:
                if not self.verbose:
                    console.print("🧹 Cleaning up temporary Ghidra files...")
                shutil.rmtree(ghidra_temp_dir)
                self.log(f"Removed temporary Ghidra directory: {ghidra_temp_dir}")
            except Exception as exc:
                logger.warning("Failed to remove temporary Ghidra directory: %s", exc)

        if self.verbose:
            logger.info("Snapshot extraction complete: %s", self.output_dir)
            if summary:
                logger.info(
                    "Functions=%s (decompiled %s) sections=%s imports=%s exports=%s "
                    "call_edges=%s equates=%s strings=%s data_items=%s",
                    summary["functions_total"],
                    summary["functions_decompiled"],
                    summary["sections"],
                    summary["imports"],
                    summary["exports"],
                    summary["call_edges"],
                    summary["equates"],
                    summary["strings"],
                    summary["data_items"],
                )
        else:
            console.print(
                f"[bold green]✓ Snapshot extraction complete:[/] {self.output_dir.name}"
            )

        return self.output_dir


def build_snapshot(
    binary_path: Path, output_dir: Path | None = None, verbose: bool = False
) -> Path:
    """
    Run analysis and produce a <binary>.snapshot directory.

    Args:
        binary_path: Input binary to analyze.
        output_dir: Optional directory to create (defaults to sibling <name>.snapshot).
        verbose: Enable verbose logging.

    Returns:
        Path to the completed snapshot directory.
    """

    binary_path = Path(binary_path)
    if not binary_path.exists():
        raise SnapshotError(f"Binary file not found: {binary_path}")

    extractor = BinaryArchiveExtractor(binary_path, verbose=verbose)
    if output_dir:
        extractor.output_dir = Path(output_dir)

    try:
        return extractor.extract_all()
    except SnapshotError:
        raise
    except Exception as exc:  # pragma: no cover - runtime specific
        raise SnapshotError(str(exc)) from exc
