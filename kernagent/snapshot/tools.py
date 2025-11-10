"""Snapshot querying utilities."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..log import get_logger

logger = get_logger(__name__)


class SnapshotTools:
    """Read-only helpers for navigating snapshot artifacts."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Snapshot root not found: {self.root}")
        if not self.root.is_dir():
            raise ValueError(f"Snapshot root must be a directory: {self.root}")

        self._cache: Dict[str, Any] = {
            "function_lookup": None,
            "decomp_index": None,
        }

    # -- helpers -----------------------------------------------------------------

    def _resolve(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        if not str(path).startswith(str(self.root)):
            raise ValueError("Access outside the snapshot root is not allowed")
        return path

    @staticmethod
    def _normalize_ea(value: Optional[Any]) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, int):
            value_int = value
        else:
            value_str = str(value).strip()
            if not value_str:
                return None
            if value_str.lower().startswith("0x"):
                value_str = value_str[2:]
            try:
                value_int = int(value_str, 16)
            except ValueError:
                return None
        return f"{value_int:x}".upper()

    @staticmethod
    def _ea_to_int(value: Optional[Any]) -> Optional[int]:
        normalized = SnapshotTools._normalize_ea(value)
        if normalized is None:
            return None
        return int(normalized, 16)

    @staticmethod
    def _has_value_field(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return value.strip() != ""
        if isinstance(value, (list, dict)):
            return len(value) > 0
        return True

    @staticmethod
    def _call_type_label(raw_type: Optional[str]) -> str:
        mapping = {
            "UNCONDITIONAL_CALL": "call",
            "CONDITIONAL_CALL": "call",
            "COMPUTED_CALL": "call",
            "UNCONDITIONAL_JUMP": "jump",
            "CONDITIONAL_JUMP": "jump",
            "COMPUTED_JUMP": "jump",
        }
        key = (raw_type or "").upper()
        return mapping.get(key, key.lower() or "code_ref")

    # -- cache helpers -----------------------------------------------------------

    def _function_lookup(self) -> Dict[str, str]:
        cached = self._cache.get("function_lookup")
        if cached is not None:
            return cached

        index = self.read_json("index.json")
        lookup: Dict[str, str] = {}
        if isinstance(index, dict):
            for name, ea in index.get("by_name", {}).items():
                normalized = self._normalize_ea(ea)
                if normalized:
                    lookup[normalized] = name

        self._cache["function_lookup"] = lookup
        return lookup

    def _decomp_index(self) -> Dict[str, Dict[str, Optional[str]]]:
        cached = self._cache.get("decomp_index")
        if cached is not None:
            return cached

        index: Dict[str, Dict[str, Optional[str]]] = {}
        path = self.root / "functions.jsonl"
        if path.exists():
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    decomp_path = entry.get("decomp_path")
                    if not decomp_path or not decomp_path.startswith("decomp/"):
                        continue
                    index[decomp_path] = {
                        "function_name": entry.get("name"),
                        "ea": self._normalize_ea(entry.get("ea")),
                    }

        self._cache["decomp_index"] = index
        return index

    def _get_function_entry(self, target_ea: Optional[str]) -> Optional[Dict[str, Any]]:
        if not target_ea:
            return None
        path = self.root / "functions.jsonl"
        if not path.exists():
            return None

        normalized = self._normalize_ea(target_ea)
        if normalized is None:
            return None

        with path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if self._normalize_ea(entry.get("ea")) == normalized:
                    return entry
        return None

    def _get_data_entry(self, target_ea: Optional[str]) -> Optional[Dict[str, Any]]:
        if not target_ea:
            return None
        path = self.root / "data.jsonl"
        if not path.exists():
            return None

        normalized = self._normalize_ea(target_ea)
        if normalized is None:
            return None

        with path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if self._normalize_ea(entry.get("ea")) == normalized:
                    return entry
        return None

    def _get_string_entry(self, target_ea: Optional[str]) -> Optional[Dict[str, Any]]:
        if not target_ea:
            return None
        path = self.root / "strings.jsonl"
        if not path.exists():
            return None

        normalized = self._normalize_ea(target_ea)
        if normalized is None:
            return None

        with path.open() as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if self._normalize_ea(entry.get("ea")) == normalized:
                    return entry
        return None

    # -- artifact readers --------------------------------------------------------

    def read_json(self, filepath: str) -> Dict[str, Any]:
        try:
            path = self._resolve(filepath)
            with path.open() as f:
                return json.load(f)
        except FileNotFoundError:
            return {"error": f"File not found: {filepath}"}
        except (json.JSONDecodeError, ValueError) as exc:
            return {"error": f"Invalid JSON in {filepath}: {exc}"}
        except ValueError as exc:
            return {"error": str(exc)}

    def get_capa_summary(self) -> Dict[str, Any]:
        """Return the CAPA summary artifact if present."""

        path = self.root / "capa_summary.json"
        if not path.exists():
            return {"error": "capa_summary.json not found"}

        try:
            with path.open() as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError) as exc:
            return {"error": f"Invalid JSON in capa_summary.json: {exc}"}

    def list_files(self, directory: str = ".", pattern: str = "*") -> Dict[str, Any]:
        try:
            root = self._resolve(".")
            path = self._resolve(directory)
            files = [f for f in path.glob(pattern) if f.is_file()]
            return {
                "files": [str(f.relative_to(root)) for f in files],
                "count": len(files),
            }
        except ValueError as exc:
            return {"error": str(exc)}

    def get_function_stats(self) -> Dict[str, Any]:
        stats = {
            "total": 0,
            "with_decomp": 0,
            "high_complexity": [],
            "large_functions": [],
        }

        path = self.root / "functions.jsonl"
        if not path.exists():
            return {"error": "functions.jsonl not found"}

        try:
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    func = json.loads(line)
                    stats["total"] += 1

                    if func.get("decomp_path"):
                        stats["with_decomp"] += 1

                    metrics = func.get("metrics", {})
                    complexity = metrics.get("cyclomatic_complexity", 0)
                    if complexity > 20:
                        stats["high_complexity"].append(
                            {"name": func["name"], "ea": func["ea"], "complexity": complexity}
                        )

                    size = metrics.get("size_bytes", 0)
                    if size > 1000:
                        stats["large_functions"].append(
                            {"name": func["name"], "ea": func["ea"], "size": size}
                        )

            stats["high_complexity"] = sorted(
                stats["high_complexity"], key=lambda x: x["complexity"], reverse=True
            )[:10]
            stats["large_functions"] = sorted(
                stats["large_functions"], key=lambda x: x["size"], reverse=True
            )[:10]

            return stats
        except Exception as exc:
            return {"error": str(exc)}

    def get_function(self, identifier: str) -> Dict[str, Any]:
        index = self.read_json("index.json")
        if "error" in index:
            return index

        if identifier in index.get("by_name", {}):
            target_ea = index["by_name"][identifier]
        elif identifier in index.get("by_ea", {}):
            target_ea = identifier
        else:
            return {"error": f"Function '{identifier}' not found in index"}

        path = self.root / "functions.jsonl"
        if not path.exists():
            return {"error": "functions.jsonl not found"}

        try:
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    func = json.loads(line)
                    if func["ea"] == target_ea:
                        if "insn" in func and len(func.get("insn", [])) > 50:
                            func["insn"] = func["insn"][:50] + [
                                {
                                    "note": "... truncated, use search_by_instruction for specific instructions"
                                }
                            ]
                        return func

            return {"error": f"Function at {target_ea} not found in functions.jsonl"}
        except Exception as exc:
            return {"error": str(exc)}

    def read_decompilation(self, decomp_path: str) -> Dict[str, Any]:
        try:
            path = self._resolve(decomp_path)
            with path.open() as f:
                code = f.read()
            return {"path": decomp_path, "code": code, "lines": len(code.splitlines())}
        except FileNotFoundError:
            return {"error": f"Decompilation file not found: {decomp_path}"}
        except ValueError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            return {"error": str(exc)}

    def search_functions(
        self,
        name_pattern: Optional[str] = None,
        min_complexity: Optional[int] = None,
        min_size: Optional[int] = None,
        has_decomp: Optional[bool] = None,
        callers_of: Optional[str] = None,
        callees_of: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        index = self.read_json("index.json")
        if "error" in index:
            return index

        path = self.root / "functions.jsonl"
        if not path.exists():
            return {"error": "functions.jsonl not found"}

        def resolve_identifier(identifier: str) -> str:
            if identifier in index.get("by_name", {}):
                return index["by_name"][identifier]
            if identifier in index.get("by_ea", {}):
                return identifier
            return identifier

        target_called_ea = resolve_identifier(callers_of) if callers_of else None
        target_caller_ea = resolve_identifier(callees_of) if callees_of else None

        results = []
        try:
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    func = json.loads(line)

                    if name_pattern and name_pattern.lower() not in func["name"].lower():
                        continue

                    metrics = func.get("metrics", {})
                    if min_complexity and metrics.get("cyclomatic_complexity", 0) < min_complexity:
                        continue

                    if min_size and metrics.get("size_bytes", 0) < min_size:
                        continue

                    if has_decomp is not None:
                        if has_decomp and not func.get("decomp_path"):
                            continue
                        if not has_decomp and func.get("decomp_path"):
                            continue

                    if target_called_ea:
                        callees = [x.get("ea") for x in func.get("xrefs_out", [])]
                        if target_called_ea not in callees:
                            continue

                    if target_caller_ea:
                        if target_caller_ea not in func.get("xrefs_in", []):
                            continue

                    results.append(
                        {
                            "ea": func["ea"],
                            "name": func["name"],
                            "prototype": func.get("prototype"),
                            "metrics": metrics,
                            "decomp_path": func.get("decomp_path"),
                            "xrefs_in_count": len(func.get("xrefs_in", [])),
                            "xrefs_out_count": len(func.get("xrefs_out", [])),
                        }
                    )

                    if len(results) >= limit:
                        break

            return {"results": results, "count": len(results), "limited": len(results) >= limit}
        except Exception as exc:
            return {"error": str(exc)}

    def search_strings(
        self, pattern: str, case_sensitive: bool = False, limit: int = 50
    ) -> Dict[str, Any]:
        path = self.root / "strings.jsonl"
        if not path.exists():
            return {"error": "strings.jsonl not found"}

        results = []
        pattern_cmp = pattern if case_sensitive else pattern.lower()

        try:
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    string_obj = json.loads(line)
                    value = string_obj.get("value", "")
                    value_cmp = value if case_sensitive else value.lower()

                    if pattern_cmp in value_cmp:
                        xrefs = string_obj.get("xrefs", [])
                        xref_functions = []
                        for xref in xrefs[:10]:
                            xref_functions.append(
                                {
                                    "from_address": xref.get("from"),
                                    "function": xref.get("function") or "unknown",
                                }
                            )

                        results.append(
                            {
                                "address": string_obj.get("ea"),
                                "value": value[:200],
                                "length": string_obj.get("length"),
                                "xref_count": len(xrefs),
                                "xref_functions": xref_functions,
                            }
                        )

                    if len(results) >= limit:
                        break

            return {"results": results, "count": len(results)}
        except Exception as exc:
            return {"error": str(exc)}

    def search_imports_exports(
        self,
        name_pattern: Optional[str] = None,
        library: Optional[str] = None,
        import_type: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        data = self.read_json("imports_exports.json")
        if "error" in data:
            return data

        if import_type == "import":
            search_list = data.get("imports", [])
        elif import_type == "export":
            search_list = data.get("exports", [])
        else:
            search_list = data.get("imports", []) + data.get("exports", [])

        results = []
        for entry in search_list:
            if library and library.lower() not in entry.get("library", "").lower():
                continue
            if name_pattern and name_pattern.lower() not in entry.get("name", "").lower():
                continue

            results.append(entry)
            if len(results) >= limit:
                break

        return {"results": results, "count": len(results), "limited": len(results) >= limit}

    def trace_calls(
        self, start: str, direction: str = "down", max_depth: int = 3, max_nodes: int = 200
    ) -> Dict[str, Any]:
        if max_nodes < 1:
            return {"error": "max_nodes must be at least 1"}

        index = self.read_json("index.json")
        if "error" in index:
            return index

        start_ea = index.get("by_name", {}).get(start, start)
        if direction not in {"down", "up"}:
            return {"error": "direction must be 'down' or 'up'"}

        path = self.root / "functions.jsonl"
        if not path.exists():
            return {"error": "functions.jsonl not found"}

        try:
            with path.open() as f:
                functions = {}
                for line in f:
                    if not line.strip():
                        continue
                    func = json.loads(line)
                    functions[func["ea"]] = func
        except Exception as exc:
            return {"error": str(exc)}

        visited = set()
        node_count = 0
        truncated = False

        def trace_recursive(ea: str, depth: int):
            nonlocal node_count, truncated

            if depth > max_depth or ea in visited:
                return None

            if node_count >= max_nodes:
                truncated = True
                return None

            func = functions.get(ea)
            if not func:
                return None

            visited.add(ea)
            node_count += 1

            node = {"ea": ea, "name": func.get("name"), "depth": depth}

            if direction == "down":
                child_key = "calls"
                child_targets = [xref.get("ea") for xref in func.get("xrefs_out", [])[:10]]
            else:
                child_key = "called_by"
                child_targets = func.get("xrefs_in", [])[:10]

            children = []
            for child_ea in child_targets:
                if child_ea is None:
                    continue
                if node_count >= max_nodes:
                    truncated = True
                    break
                child_node = trace_recursive(child_ea, depth + 1)
                if child_node:
                    children.append(child_node)

            if children:
                node[child_key] = children

            return node

        result = trace_recursive(start_ea, 0)
        if not result:
            return {"error": "Could not trace calls"}

        if truncated:
            result["truncated"] = True

        return result

    def search_equates(
        self, name_pattern: Optional[str] = None, value: Optional[str] = None, limit: int = 50
    ) -> Dict[str, Any]:
        equates = self.read_json("equates.json")
        if "error" in equates:
            return equates
        if not isinstance(equates, list):
            return {"error": "equates.json has unexpected format"}

        results = []
        target_value = None
        if value is not None:
            try:
                target_value = int(str(value), 0)
            except ValueError:
                target_value = value

        for entry in equates:
            if name_pattern and name_pattern.lower() not in entry.get("name", "").lower():
                continue

            if target_value is not None:
                equate_value = entry.get("value")
                if isinstance(target_value, int):
                    if equate_value != target_value:
                        continue
                else:
                    if str(equate_value) != str(target_value):
                        continue

            results.append(
                {
                    "name": entry.get("name"),
                    "value": entry.get("value"),
                    "reference_count": entry.get("reference_count", 0),
                    "references": entry.get("references", [])[:5],
                }
            )

            if len(results) >= limit:
                break

        return {"results": results, "count": len(results)}

    def get_memory_section(self, address: Optional[str] = None) -> Dict[str, Any]:
        sections = self.read_json("sections.json")
        if "error" in sections:
            return sections
        if not isinstance(sections, list):
            return {"error": "sections.json has unexpected format"}

        if address:
            try:
                addr_int = int(address, 16) if isinstance(address, str) else address
            except ValueError:
                return {"error": f"Invalid address format: {address}"}

            for section in sections:
                try:
                    start_int = int(section["start"], 16)
                    end_int = int(section["end"], 16)
                except (KeyError, ValueError):
                    continue

                if start_int <= addr_int <= end_int:
                    return {
                        "address": address,
                        "section": {
                            "name": section["name"],
                            "start": section["start"],
                            "end": section["end"],
                            "size": section["size"],
                            "permissions": section["permissions"],
                            "initialized": section["initialized"],
                            "type": section["type"],
                        },
                    }

            return {"error": f"Address {address} not found in any section"}

        return {
            "sections": [
                {
                    "name": s["name"],
                    "start": s["start"],
                    "end": s["end"],
                    "size": s["size"],
                    "permissions": s["permissions"],
                }
                for s in sections
            ],
            "count": len(sections),
        }

    def search_by_instruction(
        self, mnemonic: str, operand_pattern: Optional[str] = None, limit: int = 20
    ) -> Dict[str, Any]:
        path = self.root / "functions.jsonl"
        if not path.exists():
            return {"error": "functions.jsonl not found"}

        results = []
        mnemonic_lower = mnemonic.lower()
        operand_lower = operand_pattern.lower() if operand_pattern else None

        try:
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    func = json.loads(line)

                    matching_insns = []
                    for insn in func.get("insn", []):
                        if insn.get("mnem", "").lower() != mnemonic_lower:
                            continue
                        if operand_lower:
                            opstr = insn.get("opstr", "").lower()
                            if operand_lower not in opstr:
                                continue
                        matching_insns.append(
                            {
                                "address": insn.get("ea"),
                                "mnemonic": insn.get("mnem"),
                                "operands": insn.get("opstr"),
                                "bytes": insn.get("bytes"),
                            }
                        )

                    if matching_insns:
                        results.append(
                            {
                                "function": {
                                    "name": func["name"],
                                    "ea": func["ea"],
                                    "prototype": func.get("prototype"),
                                },
                                "instruction_matches": len(matching_insns),
                                "sample_instructions": matching_insns[:5],
                            }
                        )

                    if len(results) >= limit:
                        break

            return {"results": results, "count": len(results), "limited": len(results) >= limit}
        except Exception as exc:
            return {"error": str(exc)}

    def search_data(
        self,
        name_pattern: Optional[str] = None,
        type_pattern: Optional[str] = None,
        address_range: Optional[List[str]] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        has_value: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        if limit <= 0:
            return {"error": "limit must be greater than 0"}
        if offset < 0:
            return {"error": "offset cannot be negative"}

        start_addr = end_addr = None
        if address_range:
            if len(address_range) != 2:
                return {"error": "address_range must contain exactly two elements"}
            start_addr = self._ea_to_int(address_range[0])
            end_addr = self._ea_to_int(address_range[1])
            if start_addr is None or end_addr is None:
                return {"error": "address_range values must be valid hex addresses"}
            if start_addr > end_addr:
                start_addr, end_addr = end_addr, start_addr

        name_cmp = name_pattern.lower() if name_pattern else None
        type_cmp = type_pattern.lower() if type_pattern else None

        path = self.root / "data.jsonl"
        if not path.exists():
            return {"error": "data.jsonl not found"}

        results: List[Dict[str, Any]] = []
        total_matches = 0

        try:
            with path.open() as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)

                    entry_name = entry.get("name") or ""
                    entry_type = entry.get("type") or ""
                    entry_ea = self._normalize_ea(entry.get("ea")) or entry.get("ea")
                    entry_length = entry.get("length")
                    entry_value = entry.get("value")
                    entry_has_value = self._has_value_field(entry_value)

                    if name_cmp and name_cmp not in entry_name.lower():
                        continue

                    if type_cmp and type_cmp not in entry_type.lower():
                        continue

                    if start_addr is not None:
                        ea_int = self._ea_to_int(entry_ea)
                        if ea_int is None or not (start_addr <= ea_int <= end_addr):
                            continue

                    if (
                        min_length is not None
                        and entry_length is not None
                        and entry_length < min_length
                    ):
                        continue

                    if (
                        max_length is not None
                        and entry_length is not None
                        and entry_length > max_length
                    ):
                        continue

                    if has_value and not entry_has_value:
                        continue

                    total_matches += 1
                    if total_matches <= offset:
                        continue

                    summary = {
                        "ea": entry_ea,
                        "name": entry_name or None,
                        "type": entry_type or None,
                        "length": entry_length,
                        "section": entry.get("section"),
                        "has_value": entry_has_value,
                    }

                    if entry_has_value:
                        summary["value_preview"] = str(entry_value)[:160]

                    results.append(summary)

                    if len(results) >= limit:
                        break

            available = max(0, total_matches - offset)
            truncated = available > len(results)

            return {
                "results": results,
                "count": len(results),
                "total_matches": total_matches,
                "offset": offset,
                "limit": limit,
                "truncated": truncated,
            }
        except Exception as exc:
            return {"error": str(exc)}

    def resolve_symbol(self, query: str) -> Dict[str, Any]:
        query = (query or "").strip()
        if not query:
            return {"ambiguous": False, "candidates": [], "error": "query is required"}

        normalized_query_ea = self._normalize_ea(query)
        query_lower = query.lower()

        candidates: List[Tuple[int, int, Dict[str, Optional[str]]]] = []
        seen: set[Tuple[str, Optional[str], Optional[str]]] = set()
        sequence = 0

        def add_candidate(priority: int, kind: str, name: Optional[str], ea: Optional[str]):
            nonlocal sequence
            key = (kind, name, ea)
            if key in seen:
                return
            seen.add(key)
            candidates.append(
                (
                    priority,
                    sequence,
                    {"kind": kind, "name": name, "ea": self._normalize_ea(ea) if ea else ea},
                )
            )
            sequence += 1

        def match_priority(name: Optional[str], ea: Optional[str], base_priority: int) -> Optional[int]:
            if normalized_query_ea and ea and self._normalize_ea(ea) == normalized_query_ea:
                return base_priority
            if name and name.lower() == query_lower:
                return base_priority
            if name and query_lower and query_lower in name.lower():
                return base_priority + 1
            return None

        # Functions
        path = self.root / "functions.jsonl"
        if path.exists():
            try:
                with path.open() as f:
                    for line in f:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        name = entry.get("name")
                        ea = self._normalize_ea(entry.get("ea"))
                        priority = match_priority(name, ea, 0)
                        if priority is not None:
                            add_candidate(priority, "function", name, ea)
            except Exception:
                pass

        # Imports/exports
        imports_data = self.read_json("imports_exports.json")
        if isinstance(imports_data, dict):
            for category in ("imports", "exports"):
                base = 10 if category == "imports" else 12
                for entry in imports_data.get(category, []):
                    name = entry.get("name")
                    ea = self._normalize_ea(entry.get("address"))
                    priority = match_priority(name, ea, base)
                    if priority is not None:
                        kind = "import" if category == "imports" else "export"
                        add_candidate(priority, kind, name, ea)

        # Data
        path = self.root / "data.jsonl"
        if path.exists():
            try:
                with path.open() as f:
                    for line in f:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        name = entry.get("name")
                        ea = self._normalize_ea(entry.get("ea"))
                        priority = match_priority(name, ea, 20)
                        if priority is not None:
                            label = name or (ea and f"DATA_{ea}") or None
                            add_candidate(priority, "data", label, ea)
            except Exception:
                pass

        # Strings (match by EA only)
        if normalized_query_ea:
            path = self.root / "strings.jsonl"
            if path.exists():
                try:
                    with path.open() as f:
                        for line in f:
                            if not line.strip():
                                continue
                            entry = json.loads(line)
                            ea = self._normalize_ea(entry.get("ea"))
                            if ea == normalized_query_ea:
                                value = entry.get("name") or entry.get("value")
                                label = value[:80] if isinstance(value, str) else value
                                add_candidate(30, "string", label, ea)
                                break
                except Exception:
                    pass

        if not candidates:
            return {
                "ambiguous": False,
                "candidates": [],
                "error": f"No symbol found matching '{query}'",
            }

        candidates.sort(key=lambda item: (item[0], item[1]))
        best_priority = candidates[0][0]
        best_candidates = [item[2] for item in candidates if item[0] == best_priority][:50]
        ambiguous = len(best_candidates) > 1

        return {"ambiguous": ambiguous, "candidates": best_candidates}

    def get_xrefs(
        self,
        target: str,
        direction: str = "both",
        xref_type: str = "any",
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        direction = (direction or "both").lower()
        xref_type = (xref_type or "any").lower()

        if direction not in {"to", "from", "both"}:
            return {"error": "direction must be one of: to, from, both"}
        if xref_type not in {"code", "data", "any"}:
            return {"error": "xref_type must be one of: code, data, any"}
        if limit <= 0:
            return {"error": "limit must be greater than 0"}
        if offset < 0:
            return {"error": "offset cannot be negative"}

        resolution = self.resolve_symbol(target)
        candidates = resolution.get("candidates", [])
        if not candidates:
            return {"error": resolution.get("error") or f"Could not resolve target '{target}'"}

        selected = candidates[0]
        target_ea = self._normalize_ea(selected.get("ea"))
        target_name = selected.get("name")
        target_kind = selected.get("kind")

        result = {
            "resolved_target": {"name": target_name, "ea": target_ea, "kind": target_kind},
            "xrefs": [],
            "offset": offset,
            "limit": limit,
            "truncated": False,
        }

        if resolution.get("ambiguous") or len(candidates) > 1:
            choice = target_name or target_ea or "unknown"
            result["resolution_note"] = f"Multiple matches found; using '{choice}'."

        need_to = direction in {"to", "both"}
        need_from = direction in {"from", "both"}
        need_code = xref_type in {"code", "any"}
        need_data = xref_type in {"data", "any"}

        xrefs: List[Dict[str, Any]] = []
        seen: set[Tuple[Any, ...]] = set()
        func_lookup = self._function_lookup()
        target_label = target_name or target_ea
        target_name_lower = target_name.lower() if isinstance(target_name, str) else None

        def add_xref(entry: Dict[str, Any]):
            key = (
                entry.get("direction"),
                entry.get("kind"),
                entry.get("type"),
                entry.get("from_ea"),
                entry.get("to_ea"),
                entry.get("xref_address"),
            )
            if key in seen:
                return
            seen.add(key)
            xrefs.append(entry)

        def matches_target(name: Optional[str], ea: Optional[str]) -> bool:
            norm_ea = self._normalize_ea(ea)
            if target_ea and norm_ea == target_ea:
                return True
            if target_name_lower and name and name.lower() == target_name_lower:
                return True
            return False

        # Callgraph edges
        if need_code and (need_to or need_from):
            path = self.root / "callgraph.jsonl"
            if path.exists():
                try:
                    with path.open() as f:
                        for line in f:
                            if not line.strip():
                                continue
                            edge = json.loads(line)
                            from_ea = self._normalize_ea(edge.get("from"))
                            to_ea = self._normalize_ea(edge.get("to"))
                            call_type = self._call_type_label(edge.get("type"))

                            if need_to and matches_target(edge.get("to_name"), to_ea or edge.get("to")):
                                add_xref(
                                    {
                                        "direction": "to",
                                        "kind": "code",
                                        "type": call_type,
                                        "from_ea": from_ea or edge.get("from"),
                                        "from_function": edge.get("from_name")
                                        or func_lookup.get(from_ea or "", from_ea),
                                        "to_ea": target_ea or to_ea or edge.get("to"),
                                        "to_name": target_name or edge.get("to_name"),
                                    }
                                )

                            if need_from and matches_target(edge.get("from_name"), from_ea or edge.get("from")):
                                add_xref(
                                    {
                                        "direction": "from",
                                        "kind": "code",
                                        "type": call_type,
                                        "from_ea": target_ea or from_ea or edge.get("from"),
                                        "from_function": target_name,
                                        "to_ea": to_ea or edge.get("to"),
                                        "to_name": edge.get("to_name"),
                                    }
                                )
                except Exception:
                    pass

        # Function-local xrefs
        if target_kind == "function" and need_code:
            func_entry = self._get_function_entry(target_ea)
            if func_entry:
                if need_to:
                    for caller in func_entry.get("xrefs_in", []):
                        caller_ea = self._normalize_ea(caller)
                        add_xref(
                            {
                                "direction": "to",
                                "kind": "code",
                                "type": "call",
                                "from_ea": caller_ea or caller,
                                "from_function": func_lookup.get(caller_ea or "", caller_ea),
                                "to_ea": target_ea,
                                "to_name": target_name,
                            }
                        )
                if need_from:
                    for callee in func_entry.get("xrefs_out", []):
                        callee_ea = self._normalize_ea(callee.get("ea"))
                        add_xref(
                            {
                                "direction": "from",
                                "kind": "code",
                                "type": self._call_type_label(callee.get("type")),
                                "from_ea": target_ea,
                                "from_function": target_name,
                                "to_ea": callee_ea or callee.get("ea"),
                                "to_name": callee.get("name"),
                            }
                        )

        # Target function referencing data/strings
        if target_kind == "function" and need_from and need_data:
            for filename, entry_kind in (("strings.jsonl", "string"), ("data.jsonl", "data")):
                path = self.root / filename
                if not path.exists():
                    continue
                try:
                    with path.open() as f:
                        for line in f:
                            if not line.strip():
                                continue
                            entry = json.loads(line)
                            xrefs_list = entry.get("xrefs") or []
                            if not isinstance(xrefs_list, list):
                                continue
                            entry_ea = self._normalize_ea(entry.get("ea")) or entry.get("ea")
                            entry_label = entry.get("name")
                            if not entry_label:
                                if entry_kind == "string":
                                    value = entry.get("value")
                                    entry_label = value[:80] if isinstance(value, str) else value
                                else:
                                    entry_label = entry_ea and f"DATA_{entry_ea}" or "data_item"

                            for xref in xrefs_list:
                                from_ea = self._normalize_ea(xref.get("from"))
                                function_name = xref.get("function")
                                match = False
                                if target_ea and from_ea == target_ea:
                                    match = True
                                elif target_name_lower and function_name and function_name.lower() == target_name_lower:
                                    match = True
                                if not match:
                                    continue

                                entry_type = xref.get("type") or (
                                    "string_ref" if entry_kind == "string" else "data_ref"
                                )
                                add_xref(
                                    {
                                        "direction": "from",
                                        "kind": "data",
                                        "type": entry_type,
                                        "from_ea": target_ea or from_ea,
                                        "from_function": target_label,
                                        "to_ea": entry_ea,
                                        "to_name": entry_label,
                                        "xref_address": from_ea or xref.get("from"),
                                    }
                                )
                except Exception:
                    continue

        # References TO target data/string
        if need_to and need_data and target_kind in {"data", "string"}:
            if target_kind == "data":
                entry = self._get_data_entry(target_ea)
                default_type = "data_ref"
            else:
                entry = self._get_string_entry(target_ea)
                default_type = "string_ref"

            if entry:
                target_label = target_name or entry.get("name")
                if not target_label and target_kind == "string":
                    value = entry.get("value")
                    target_label = value[:80] if isinstance(value, str) else value
                if not target_label:
                    target_label = target_ea and f"DATA_{target_ea}" or "data_item"

                for xref in entry.get("xrefs", []):
                    from_ea = self._normalize_ea(xref.get("from"))
                    add_xref(
                        {
                            "direction": "to",
                            "kind": "data",
                            "type": xref.get("type") or default_type,
                            "from_ea": from_ea or xref.get("from"),
                            "from_function": xref.get("function"),
                            "to_ea": target_ea,
                            "to_name": target_label,
                            "xref_address": from_ea or xref.get("from"),
                        }
                    )

        total = len(xrefs)
        paginated = xrefs[offset : offset + limit] if offset < total else []
        truncated = total > offset + len(paginated)

        result["xrefs"] = paginated
        result["total_matches"] = total
        result["truncated"] = truncated
        return result

    def search_decomp(
        self,
        pattern: str,
        case_sensitive: bool = False,
        max_matches_per_function: int = 3,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        if not pattern:
            return {"error": "pattern is required"}
        if limit <= 0:
            return {"error": "limit must be greater than 0"}
        if offset < 0:
            return {"error": "offset cannot be negative"}
        if max_matches_per_function <= 0:
            max_matches_per_function = 1

        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error as exc:
            return {"error": f"Invalid pattern: {exc}"}

        index = self._decomp_index()
        if not index:
            return {
                "matches": [],
                "count": 0,
                "offset": offset,
                "limit": limit,
                "truncated": False,
            }

        matches: List[Dict[str, Any]] = []
        total_found = 0
        truncated = False

        for decomp_path, info in sorted(index.items()):
            recorded_for_file = 0
            file_path = self.root / decomp_path
            try:
                with file_path.open() as f:
                    for line_no, line in enumerate(f, start=1):
                        if regex.search(line):
                            total_found += 1
                            if total_found <= offset:
                                continue

                            if recorded_for_file >= max_matches_per_function:
                                continue

                            snippet = line.rstrip("\n")
                            matches.append(
                                {
                                    "function_name": info.get("function_name"),
                                    "ea": info.get("ea"),
                                    "decomp_path": decomp_path,
                                    "line": line_no,
                                    "snippet": snippet[:400],
                                }
                            )
                            recorded_for_file += 1

                            if len(matches) >= limit:
                                truncated = True
                                break
                if truncated:
                    break
            except FileNotFoundError:
                continue

        available = max(0, total_found - offset)
        truncated = truncated or available > len(matches)

        return {
            "matches": matches,
            "count": len(matches),
            "offset": offset,
            "limit": limit,
            "truncated": truncated,
        }


def build_tool_map(snapshot: SnapshotTools) -> Dict[str, Any]:
    """Return a mapping from tool name to bound method."""

    return {
        "read_json": snapshot.read_json,
        "list_files": snapshot.list_files,
        "get_function_stats": snapshot.get_function_stats,
        "search_functions": snapshot.search_functions,
        "get_function": snapshot.get_function,
        "read_decompilation": snapshot.read_decompilation,
        "search_strings": snapshot.search_strings,
        "search_imports_exports": snapshot.search_imports_exports,
        "trace_calls": snapshot.trace_calls,
        "search_equates": snapshot.search_equates,
        "get_memory_section": snapshot.get_memory_section,
        "search_by_instruction": snapshot.search_by_instruction,
        "search_data": snapshot.search_data,
        "resolve_symbol": snapshot.resolve_symbol,
        "get_xrefs": snapshot.get_xrefs,
        "search_decomp": snapshot.search_decomp,
        "get_capa_summary": snapshot.get_capa_summary,
    }
