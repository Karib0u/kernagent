"""Snapshot extractor built on top of Ghidra/PyGhidra."""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from ..capa_runner import build_capa_summary
from ..log import get_logger

logger = get_logger(__name__)


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
        self.output_dir = self.binary_path.parent / f"{self.binary_path.stem}_archive"
        self.decompiler = None

    def log(self, message: str):
        """Print log message if verbose mode enabled"""
        if self.verbose:
            logger.info(message)
        else:
            logger.debug(message)

    def sanitize_filename(self, func_name: str, address: str, max_length: int = 200) -> str:
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
        safe_name = func_name.replace(':', '_').replace('<', '_').replace('>', '_')
        safe_name = safe_name.replace('*', '_').replace('?', '_').replace('"', '_')
        safe_name = safe_name.replace('|', '_').replace('/', '_').replace('\\', '_')
        
        # Clean up the address (remove 0x prefix if present and any colons)
        clean_addr = address.replace('0x', '').replace(':', '')
        
        # If the name is short enough, use it directly with address
        # Reserve space for address, underscore, and extension (.c = 2 chars)
        addr_length = len(clean_addr)
        available_for_name = max_length - addr_length - 1  # -1 for underscore
        
        if len(safe_name) <= available_for_name:
            return f"{clean_addr}_{safe_name}.c"
        
        # Name is too long - truncate and add hash to ensure uniqueness
        truncate_length = available_for_name - 9  # Reserve 8 chars for hash + underscore
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
        except:
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
        """Get all cross-references TO this function (callers)"""
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
        """Get all cross-references FROM this function (callees)"""
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
            from ghidra.program.model.block import BasicBlockModel

            # Create a BasicBlockModel for the program
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

    def extract_function_data(self, function, program, monitor) -> Dict[str, Any]:
        """Extract comprehensive function information"""
        entry_point = function.getEntryPoint()

        # Basic function info
        func_data = {
            "ea": str(entry_point),
            "name": function.getName(),
            "ranges": [
                [str(addr_range.getMinAddress()), str(addr_range.getMaxAddress())]
                for addr_range in function.getBody()
            ],
            "xrefs_in": self.get_xrefs_to_function(function, program),
            "xrefs_out": self.get_xrefs_from_function(function, program),
        }

        # Function signature/prototype
        signature = function.getSignature()
        if signature:
            func_data["prototype"] = str(signature.getPrototypeString())

        # Function metrics
        func_data["metrics"] = self.extract_function_metrics(function, program, monitor)

        # Extract instructions
        instructions = []
        listing = program.getListing()
        body = function.getBody()

        addr_iter = body.getAddresses(True)
        for addr in addr_iter:
            instruction = listing.getInstructionAt(addr)
            if instruction:
                instr_info = self.extract_instruction_info(instruction, program)
                instructions.append(instr_info)

        func_data["insn"] = instructions

        # Concatenated bytes for the entire function
        try:
            all_bytes = []
            for addr_range in function.getBody():
                start = addr_range.getMinAddress()
                end = addr_range.getMaxAddress()
                length = end.subtract(start) + 1

                for i in range(length):
                    byte = program.getMemory().getByte(start.add(i))
                    all_bytes.append(byte & 0xFF)

            func_data["bytes_concat"] = "".join(f"{b:02x}" for b in all_bytes)
        except Exception as e:
            func_data["bytes_concat"] = ""
            logger.warning("Could not extract function bytes: %s", e)

        # Basic blocks
        func_data["bb"] = self.get_basic_blocks(function, program, monitor)

        # Comments
        func_data["comments"] = self.extract_comments(function, program)

        # Decompiled code
        decomp_result = self.decompiler.decompileFunction(function, 60, monitor)
        if decomp_result and decomp_result.decompileCompleted():
            decompiled = decomp_result.getDecompiledFunction()
            if decompiled:
                # Generate a safe filename that won't exceed filesystem limits
                safe_filename = self.sanitize_filename(function.getName(), str(entry_point))
                func_data["decomp_path"] = f"decomp/{safe_filename}"
                func_data["decompiled_code"] = decompiled.getC()
        else:
            func_data["decomp_path"] = None
            func_data["decompiled_code"] = None

        return func_data

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
                except:
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

        except Exception as e:
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

            # Count incoming and outgoing calls
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
                        except:
                            pass

                        data_list.append(data_info)

        except Exception as e:
            logger.warning("Error extracting data: %s", e)

        return data_list

    def create_index(self, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create index for fast lookups"""
        self.log("Creating index...")

        by_name = {}
        by_ea = {}

        for idx, func in enumerate(functions):
            name = func["name"]
            ea = func["ea"]

            by_name[name] = ea
            by_ea[ea] = idx

        return {"by_name": by_name, "by_ea": by_ea}

    def extract_all(self) -> Path:
        """Main extraction routine."""
        logger.info("Starting snapshot extraction for %s", self.binary_path)

        self.output_dir.mkdir(exist_ok=True)
        decomp_dir = self.output_dir / "decomp"
        decomp_dir.mkdir(exist_ok=True)

        summary: Dict[str, Any] | None = None
        metadata: Dict[str, Any] | None = None
        meta_path = self.output_dir / "meta.json"
        capa_summary_path: Path | None = None

        try:
            with pyghidra.open_program(self.binary_path, analyze=True) as flat_api:
                program = flat_api.getCurrentProgram()
                monitor = ConsoleTaskMonitor()

                self.log(f"Program loaded: {program.getName()}")
                self.log("Waiting for analysis to complete...")

                self.decompiler = DecompInterface()
                self.decompiler.openProgram(program)

                metadata = self.extract_metadata(program)
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(metadata, f, indent=2)

                self.log(f"Metadata extracted (SHA256: {metadata['sha256']})")

                sections = self.extract_memory_sections(program)
                with open(self.output_dir / "sections.json", "w", encoding="utf-8") as f:
                    json.dump(sections, f, indent=2)

                imports_exports = self.extract_imports_exports(program)
                with open(
                    self.output_dir / "imports_exports.json", "w", encoding="utf-8"
                ) as f:
                    json.dump(imports_exports, f, indent=2)

                equates = self.extract_equates(program)
                with open(self.output_dir / "equates.json", "w", encoding="utf-8") as f:
                    json.dump(equates, f, indent=2)

                func_manager = program.getFunctionManager()
                functions = list(func_manager.getFunctions(True))

                functions_data = []
                decomp_count = 0

                for i, func in enumerate(functions, 1):
                    if self.verbose and i % 50 == 0:
                        self.log(f"Processing function {i}/{len(functions)}...")

                    func_data = self.extract_function_data(func, program, monitor)

                    if func_data.get("decompiled_code"):
                        decomp_path = decomp_dir / Path(func_data["decomp_path"]).name
                        with open(decomp_path, "w", encoding="utf-8") as f:
                            f.write(func_data["decompiled_code"])
                        decomp_count += 1
                        del func_data["decompiled_code"]

                    functions_data.append(func_data)

                call_graph = self.extract_call_graph(program)
                with open(
                    self.output_dir / "callgraph.jsonl", "w", encoding="utf-8"
                ) as f:
                    for edge in call_graph:
                        f.write(json.dumps(edge) + "\n")

                index = self.create_index(functions_data)
                with open(self.output_dir / "index.json", "w", encoding="utf-8") as f:
                    json.dump(index, f, indent=2)

                with open(
                    self.output_dir / "functions.jsonl", "w", encoding="utf-8"
                ) as f:
                    for func_data in functions_data:
                        f.write(json.dumps(func_data) + "\n")

                strings_data = self.extract_strings(program)
                with open(
                    self.output_dir / "strings.jsonl", "w", encoding="utf-8"
                ) as f:
                    for string_data in strings_data:
                        f.write(json.dumps(string_data) + "\n")

                data_sections = self.extract_data_sections(program)
                with open(self.output_dir / "data.jsonl", "w", encoding="utf-8") as f:
                    for data_item in data_sections:
                        f.write(json.dumps(data_item) + "\n")

                data_index = {"by_name": {}}
                for data_item in data_sections:
                    if data_item.get("name"):
                        data_index["by_name"][data_item["name"]] = data_item["ea"]

                with open(self.output_dir / "data_index.json", "w", encoding="utf-8") as f:
                    json.dump(data_index, f, indent=2)

                summary = {
                    "functions_total": len(functions_data),
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

        if metadata:
            try:
                capa_summary_path = build_capa_summary(self.binary_path, self.output_dir)
            except Exception as exc:  # pragma: no cover - runtime specific
                logger.warning("capa summary generation failed: %s", exc)
                capa_summary_path = None

            if capa_summary_path:
                metadata.setdefault("artifacts", {})["capa_summary"] = capa_summary_path.name
                with meta_path.open("w", encoding="utf-8") as f:
                    json.dump(metadata, f, indent=2)

        shutil.copy2(self.binary_path, self.output_dir / self.binary_path.name)

        self.log("Creating ZIP archive...")
        zip_path = self.output_dir.parent / f"{self.binary_path.stem}_archive.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.output_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(self.output_dir.parent)
                    zipf.write(file_path, arcname)

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

        return self.output_dir


def build_snapshot(
    binary_path: Path, output_dir: Path | None = None, verbose: bool = False
) -> Path:
    """
    Run analysis and produce a <binary>_archive directory.

    Args:
        binary_path: Input binary to analyze.
        output_dir: Optional directory to create (defaults to sibling <name>_archive).
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
