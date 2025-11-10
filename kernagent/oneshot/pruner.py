"""
Deterministic pruning logic for the oneshot_insight feature.

`build_oneshot_summary()` ingests the snapshot archive produced by kernagent
and emits a compact, capability-focused JSON payload ready for the LLM.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..log import get_logger

logger = get_logger(__name__)

MAX_STRINGS = 150
MAX_KEY_FUNCTIONS = 40
CONFIG_PREVIEW_LIMIT = 160
SMALL_EXEC_SECTION_THRESHOLD = 512
LARGE_RWX_SECTION_THRESHOLD = 64 * 1024
GENERATION_VERSION = "oneshot_pruner_v1"

CAPABILITY_KEYWORDS: Mapping[str, Sequence[str]] = {
    "network": [
        r"wininet", r"winhttp", r"urlmon", r"cfnetwork", r"nsurlsession", r"inet",
        r"socket", r"connect", r"send", r"recv", r"bind", r"listen", r"accept",
        r"http", r"ws2_", r"gethostbyname", r"dns", r"getaddrinfo", r"curl", r"wget",
    ],
    "filesystem": [
        r"createfile", r"readfile", r"writefile", r"deletefile", r"copyfile",
        r"movefile", r"findfirst", r"findnext", r"setfile", r"getfile",
        r"fopen", r"fread", r"fwrite", r"unlink", r"stat", r"chmod", r"mkdir",
        r"rmdir", r"gettemp", r"shfileoperation",
    ],
    "process": [
        r"createprocess", r"createremotethread", r"openprocess", r"terminateprocess",
        r"shellexecute", r"winexec", r"ntcreateprocess", r"ntqueueapcthread",
        r"fork", r"execve", r"ptrace", r"task_for_pid", r"kill", r"launchapplication",
    ],
    "memory_injection": [
        r"virtualalloc", r"virtualallocex", r"virtualprotect", r"virtualquery",
        r"writeprocessmemory", r"readprocessmemory", r"mapviewoffile", r"unmapviewoffile",
        r"setthreadcontext", r"getthreadcontext", r"mprotect", r"dlopen", r"dlsym",
        r"mach_vm_", r"mach_port", r"mach_task_self",
    ],
    "crypto": [
        r"crypt", r"bcrypt", r"ncrypt", r"aes", r"des", r"sha", r"md5",
        r"hash", r"rsa", r"cccrypt", r"secrandom", r"commoncrypto",
    ],
    "persistence": [
        r"regsetvalue", r"regcreatekey", r"regopenkey", r"runonce", r"runservicestart",
        r"schtask", r"schedule", r"createservice", r"startservice", r"setservice",
        r"launchagent", r"launchdaemon", r"loginitem", r"initlaunch", r"nsbundle",
    ],
    "privilege": [
        r"adjusttokenprivileges", r"lookupprivilege", r"setthreadtoken",
        r"seteuid", r"setuid", r"seteuid", r"setreuid", r"chmod", r"chown",
        r"se", r"privilege", r"impersonat", r"token", r"authoriza", r"sudo",
    ],
    "anti_debug_vm": [
        r"isdebuggerpresent", r"checkremotedebuggerpresent", r"outputdebugstring",
        r"ntqueryinformationprocess", r"ntsetinformationthread", r"verifydebugger",
        r"gettickcount", r"queryperformancecounter", r"getlocaltime", r"rdtsc",
        r"cpuid", r"vmware", r"virtualbox", r"hyperv", r"sandbox", r"debugactiveprocess",
    ],
    "user_cred_phishing": [
        r"credui", r"credread", r"internetsetoption", r"setwindowsHook",
        r"getasynckeystate", r"setwinhookex", r"osascript", r"nsalert",
        r"nsapp", r"uiapplication", r"secitemcopy", r"credential", r"keychain",
    ],
    "scripting_shell": [
        r"cmd.exe", r"powershell", r"pwsh", r"wscript", r"cscript", r"mshta",
        r"shshell", r"system", r"popen", r"/bin/sh", r"/bin/bash", r"osascript",
        r"bash", r"python", r"perl", r"ruby", r"powershellscript",
    ],
    "ipc": [
        r"createnamedpipe", r"connectnamedpipe", r"createpipe", r"peeknamedpipe",
        r"waitnamedpipe", r"ncalrpc", r"alpc", r"mach_port", r"sndmsg",
        r"sharedmemory", r"shmget", r"messagequeue", r"mq_open",
    ],
}

CAPABILITY_ORDER = list(CAPABILITY_KEYWORDS.keys())
CAPABILITY_PATTERNS = {
    cap: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for cap, patterns in CAPABILITY_KEYWORDS.items()
}

STRING_KIND_TO_CAPS = {
    "url": {"network"},
    "domain": {"network"},
    "ip": {"network"},
    "path": {"filesystem"},
    "registry": {"persistence", "filesystem"},
    "command": {"scripting_shell", "process"},
    "auth": {"user_cred_phishing"},
    "keyword": set(),
    "other": set(),
}

URL_REGEX = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"\b[a-z0-9][a-z0-9\-._]{1,62}\.(com|net|org|io|ru|cn|xyz|top|info|biz|cc|pw|uk|ua|su|club|co|app|site|online)\b",
    re.IGNORECASE,
)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WIN_PATH_REGEX = re.compile(r"[A-Za-z]:\\")
POSIX_PATH_REGEX = re.compile(r"^/|/etc/|/var/|/usr/|/bin/|/sbin/|/home/|~/", re.IGNORECASE)
REGISTRY_REGEX = re.compile(r"HK(LM|CU|CR|U|CC)\\", re.IGNORECASE)

COMMAND_KEYWORDS = [
    "cmd.exe", "powershell", "pwsh", "wscript", "cscript", "mshta", "/bin/sh",
    "/bin/bash", "bash -c", "sh -c", "python ", "perl ", "ruby ", "osascript",
    "Invoke-Expression", "Invoke-WebRequest", "curl ", "wget ", "scp ",
]

AUTH_KEYWORDS = [
    "password", "passwd", "token", "secret", "apikey", "auth", "login", "credential",
    "otp", "pin", "passphrase",
]

SECURITY_KEYWORDS = [
    "sandbox", "virtualbox", "vmware", "hyper-v", "qemu", "debugger", "rdtsc",
    "antivirus", "av", "edr", "isdebuggerpresent", "xen", "kvm",
]

SUSPICIOUS_CMD_FRAGMENTS = [
    "chmod +x", "base64", "certutil", "bitsadmin", "whoami", "netstat", "tasklist",
    "sc ", "reg ", "schtasks", "powershell", "curl", "wget", "ldb.exe", "sh -c",
]

STANDARD_SECTION_NAMES = {
    "pe": {
        "headers", ".text", ".rdata", ".data", ".pdata", ".edata", ".idata",
        ".tls", ".bss", ".rsrc", ".reloc", ".textbss", ".didat", ".xdata",
    },
    "elf": {
        ".text", ".plt", ".plt.sec", ".plt.got", ".got", ".got.plt", ".rodata",
        ".data", ".data.rel.ro", ".bss", ".tbss", ".init", ".fini", ".ctors",
        ".dtors", ".eh_frame", ".init_array", ".fini_array", ".comment",
        ".note.gnu.build-id", ".interp",
    },
    "mach-o": {
        "__text", "__stubs", "__stub_helper", "__cstring", "__const", "__data",
        "__data_const", "__constdata", "__auth_const", "__objc_meth", "__objc_class",
        "__objc_data", "__bss", "__common", "__linkedit", "__la_symbol_ptr",
    },
    "default": {".text", ".data", ".bss", ".rodata", ".rdata", ".init", ".fini"},
}


class OneshotPruningError(RuntimeError):
    """Raised when required artifacts are missing."""


def _read_json(path: Path) -> Any:
    if not path.exists():
        raise OneshotPruningError(f"Required artifact missing: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _read_optional_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _normalize_hex(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    try:
        intval = int(value, 16)
        return f"0x{intval:0x}"
    except ValueError:
        return value


def _normalize_format(fmt: Optional[str]) -> str:
    if not fmt:
        return "unknown"
    fmt_lower = fmt.lower()
    if "portable executable" in fmt_lower or fmt_lower.startswith("pe") or "coff" in fmt_lower:
        return "pe"
    if "elf" in fmt_lower:
        return "elf"
    if "mach" in fmt_lower:
        return "mach-o"
    return "unknown"


def _rule_rank_for_capa(rule: Dict[str, Any]) -> int:
    """Simple heuristic to rank CAPA rules in the oneshot summary."""

    score = 0
    attack = rule.get("attack") or []
    mbc = rule.get("mbc") or []
    score += min(len(attack), 3) * 5
    score += min(len(mbc), 3) * 3
    score += min(rule.get("match_count", 0), 10)
    namespace = (rule.get("namespace") or "").lower()
    if any(keyword in namespace for keyword in ("network", "process", "persistence", "credential", "crypto")):
        score += 2
    return score


def _summarize_capa_for_oneshot(capa_summary: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Extract high-signal CAPA data for the oneshot payload."""

    if not capa_summary:
        return None

    rules = capa_summary.get("rules") or []
    if not rules:
        return None

    ranked = sorted(
        rules,
        key=lambda rule: (-_rule_rank_for_capa(rule), rule.get("namespace") or "", rule.get("name") or ""),
    )[:8]

    top_rules = []
    for rule in ranked:
        locations = rule.get("locations") or []
        top_rules.append(
            {
                "name": rule.get("name"),
                "namespace": rule.get("namespace"),
                "scope": rule.get("scope"),
                "description": rule.get("description"),
                "first_location": locations[0] if locations else None,
                "attack": rule.get("attack") or [],
                "mbc": rule.get("mbc") or [],
            }
        )

    highlights = capa_summary.get("highlights") or {}

    return {
        "counts": capa_summary.get("counts"),
        "capa_version": capa_summary.get("capa_version"),
        "rules_source": capa_summary.get("rules_source"),
        "highlights": {
            "top_attack_ids": highlights.get("top_attack_ids", []),
            "top_tactics": highlights.get("top_tactics", []),
            "top_namespaces": highlights.get("top_namespaces", []),
        },
        "top_rules": top_rules,
    }
    if "coff" in fmt_lower:
        return "pe"
    return "unknown"


def _determine_arch(meta: Dict[str, Any]) -> str:
    language = (meta.get("language") or "").lower()
    processor = (meta.get("processor") or "").lower()
    if "x86:le:64" in language or "x86_64" in processor:
        return "x86_64"
    if "x86:le:32" in language or "x86" in processor:
        return "x86"
    if "arm:le:64" in language or "aarch64" in processor or "arm64" in processor:
        return "arm64"
    if "arm:le:32" in language or processor.startswith("arm"):
        return "arm"
    if "mips" in language or "mips" in processor:
        return "mips"
    if "ppc" in processor:
        return "ppc"
    return processor or "unknown"


def _section_permission_string(perms: Dict[str, Any]) -> str:
    read = "r" if perms.get("read") else "-"
    write = "w" if perms.get("write") else "-"
    execute = "x" if perms.get("execute") else "-"
    return f"{read}{write}{execute}"


def _analyze_sections(sections: List[Dict[str, Any]], fmt: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    has_rwx = False
    suspicious: List[Dict[str, Any]] = []
    standard_names = STANDARD_SECTION_NAMES.get(fmt, STANDARD_SECTION_NAMES["default"])

    for section in sections:
        perms = section.get("permissions", {})
        read = bool(perms.get("read"))
        write = bool(perms.get("write"))
        execute = bool(perms.get("execute"))
        perm_str = _section_permission_string(perms)

        if read and write and execute:
            has_rwx = True

        name = (section.get("name") or "").lower()
        is_non_standard = name not in {n.lower() for n in standard_names}
        size = section.get("size") or 0
        exec_small = execute and size > 0 and size < SMALL_EXEC_SECTION_THRESHOLD
        large_rwx = write and execute and size >= LARGE_RWX_SECTION_THRESHOLD

        if is_non_standard or (read and write and execute) or exec_small or large_rwx:
            suspicious.append(
                {
                    "name": section.get("name"),
                    "start": _normalize_hex(section.get("start")),
                    "end": _normalize_hex(section.get("end")),
                    "size": size,
                    "permissions": perm_str,
                }
            )

    return {"has_rwx": has_rwx, "suspicious": suspicious[:15]}, suspicious


def _match_capabilities(func_name: str, library: Optional[str]) -> List[str]:
    target = f"{(library or '').lower()}::{func_name.lower()}"
    matches: List[str] = []
    for capability, patterns in CAPABILITY_PATTERNS.items():
        if any(pattern.search(target) for pattern in patterns):
            matches.append(capability)
    return matches


def _build_import_capabilities(imports_exports: Dict[str, Any]) -> Tuple[Dict[str, List[str]], Dict[str, set]]:
    bucketed: Dict[str, List[str]] = {cap: [] for cap in CAPABILITY_ORDER}
    api_cap_map: Dict[str, set] = defaultdict(set)

    def consume(entries: Iterable[Dict[str, Any]]):
        for entry in entries:
            name = entry.get("name")
            if not name:
                continue
            library = entry.get("library")
            matches = _match_capabilities(name, library)
            if not matches:
                continue
            label = f"{library}!{name}" if library else name
            for capability in matches:
                if label not in bucketed[capability]:
                    if len(bucketed[capability]) < 30:
                        bucketed[capability].append(label)
                api_cap_map[name.lower()].add(capability)

    consume(imports_exports.get("imports", []))
    consume(imports_exports.get("exports", []))
    return bucketed, api_cap_map


def _classify_string(value: str) -> Optional[str]:
    if not value or len(value) < 4:
        return None

    trimmed = value.strip()
    lower = trimmed.lower()

    if URL_REGEX.search(trimmed):
        return "url"

    ip_match = IP_REGEX.search(trimmed)
    if ip_match:
        ip = ip_match.group(0)
        # Check for private IP ranges: 10.0.0.0/8, 127.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
        if ip.startswith(("10.", "127.", "192.168.", "0.", "255.")):
            pass  # Skip private/reserved IPs
        elif ip.startswith("172."):
            # Handle 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
            parts = ip.split(".")
            if len(parts) >= 2:
                try:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        pass  # Skip private range
                    else:
                        return "ip"
                except ValueError:
                    return "ip"
        else:
            return "ip"

    if DOMAIN_REGEX.search(trimmed):
        return "domain"

    if REGISTRY_REGEX.search(trimmed):
        return "registry"

    if WIN_PATH_REGEX.search(trimmed) or POSIX_PATH_REGEX.search(trimmed):
        return "path"

    for keyword in COMMAND_KEYWORDS:
        if keyword.lower() in lower:
            return "command"

    for fragment in SUSPICIOUS_CMD_FRAGMENTS:
        if fragment.lower() in lower:
            return "command"

    for keyword in AUTH_KEYWORDS:
        if keyword in lower:
            return "auth"

    for keyword in SECURITY_KEYWORDS:
        if keyword in lower:
            return "keyword"

    if "://" in trimmed:
        return "url"

    return None


def _dedup_preserve(seq: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for item in seq:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _resolve_function_refs(
    xrefs: Optional[List[Dict[str, Any]]],
    name_by_ea: Dict[str, str],
    ea_by_name: Dict[str, str],
) -> Tuple[List[Dict[str, str]], List[str]]:
    refs: List[Dict[str, str]] = []
    eas: List[str] = []
    if not xrefs:
        return refs, eas
    for entry in xrefs:
        func_name = entry.get("function")
        ea = entry.get("from")
        if not ea and func_name:
            ea = ea_by_name.get(func_name)
        resolved_name = func_name
        if not resolved_name and ea:
            resolved_name = name_by_ea.get(ea, ea)
        if not ea and resolved_name and resolved_name in ea_by_name:
            ea = ea_by_name[resolved_name]
        refs.append({"name": resolved_name or ea, "ea": ea})
        if ea:
            eas.append(ea)
    return refs, eas


def _build_callgraph_maps(callgraph_path: Path, name_by_ea: Dict[str, str]) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, str]]]:
    callers: Dict[str, Dict[str, str]] = defaultdict(dict)
    callees: Dict[str, Dict[str, str]] = defaultdict(dict)
    if not callgraph_path.exists():
        return callers, callees

    for entry in _iter_jsonl(callgraph_path):
        src = entry.get("from")
        dst = entry.get("to")
        if not src or not dst:
            continue
        if src.startswith("EXTERNAL") or dst.startswith("EXTERNAL"):
            continue
        src_name = entry.get("from_name") or name_by_ea.get(src) or src
        dst_name = entry.get("to_name") or name_by_ea.get(dst) or dst
        callees[src][dst] = dst_name
        callers[dst][src] = src_name
    return callers, callees


def _parse_address(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def _find_section_name(addr: Optional[int], sections: List[Dict[str, Any]]) -> Optional[str]:
    if addr is None:
        return None
    for section in sections:
        start = _parse_address(section.get("start"))
        end = _parse_address(section.get("end"))
        if start is None or end is None:
            continue
        if start <= addr <= end:
            return section.get("name")
    return None


def _score_function(
    record: Dict[str, Any],
    entrypoint_names: set,
    exported_names: set,
    suspicious_section_names: set,
    func_capabilities: Dict[str, set],
    func_has_strings: set,
) -> int:
    score = 0
    name_lower = (record["name"] or "").lower()
    ea = record["ea"]
    metrics = record.get("metrics") or {}
    complexity = metrics.get("cyclomatic_complexity") or 0
    size = metrics.get("size_bytes") or 0
    fan_out = len(record.get("xrefs_out") or [])
    fan_in = len(record.get("xrefs_in") or [])
    section_name = record.get("section_name")

    if name_lower in entrypoint_names or record["name"] in exported_names:
        score += 5
    if complexity >= 20:
        score += 3
    if size >= 800:
        score += 2
    if func_capabilities.get(ea):
        score += 3
    if ea in func_has_strings:
        score += 3
    if fan_out >= 8 or fan_in >= 5:
        score += 2
    if section_name and section_name.lower() in suspicious_section_names:
        score += 2
    return score


def _format_call_refs(refs: Mapping[str, str], limit: int = 5) -> List[Dict[str, str]]:
    ordered = sorted(refs.items(), key=lambda item: item[1] or item[0])
    result = []
    for ea, name in ordered[:limit]:
        result.append({"name": name or ea, "ea": ea})
    return result


def _looks_like_config(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lower = value.lower()
    if any(token in lower for token in ["server=", "host=", "domain=", "token=", "key=", "url=", "api=", "user="]):
        return True
    stripped = lower.strip()
    if stripped.startswith(("{", "[", "<?xml", "<config")):
        return True
    if ("http://" in lower or "https://" in lower) and len(value) >= 16:
        return True
    if "&" in value and "=" in value:
        return True
    return False


def _build_suspicion_signals(
    imports_by_cap: Dict[str, List[str]],
    sections_info: Dict[str, Any],
    string_kind_counts: Counter,
    file_size: int,
    key_functions: List[Dict[str, Any]],
) -> Dict[str, bool]:
    def has_any(cap: str) -> bool:
        return bool(imports_by_cap.get(cap))

    interesting_caps = {"network", "filesystem", "process", "memory_injection", "persistence", "privilege", "user_cred_phishing", "scripting_shell"}
    complex_func = any(
        (func.get("cyclomatic_complexity") or 0) >= 30 or (func.get("size_bytes") or 0) >= 2000
        for func in key_functions
    )

    return {
        "uses_network": has_any("network") or any(string_kind_counts.get(kind, 0) for kind in ("url", "domain", "ip")),
        "uses_filesystem": has_any("filesystem") or string_kind_counts.get("path", 0) > 0,
        "spawns_processes_or_shell": has_any("process") or has_any("scripting_shell") or string_kind_counts.get("command", 0) > 0,
        "allocates_remote_or_rwx_memory": has_any("memory_injection") or bool(sections_info.get("has_rwx")),
        "has_persistence_indicators": has_any("persistence") or string_kind_counts.get("registry", 0) > 0,
        "has_credential_theft_indicators": has_any("user_cred_phishing") or string_kind_counts.get("auth", 0) > 0,
        "has_anti_debug_vm_indicators": has_any("anti_debug_vm") or string_kind_counts.get("keyword", 0) > 0,
        "has_suspicious_urls_or_ips": any(string_kind_counts.get(kind, 0) for kind in ("url", "domain", "ip")),
        "has_overlay_or_ui_cred_strings": has_any("user_cred_phishing") or string_kind_counts.get("auth", 0) > 0,
        "is_unusually_small_but_complex": (file_size or 0) <= 200_000 and complex_func,
        "has_shell_execution_strings": string_kind_counts.get("command", 0) > 0,
    }


def build_oneshot_summary(archive_dir: Path, verbose: bool = False) -> Dict[str, Any]:
    """
    Build the JSON payload consumed by the oneshot LLM mode.

    Args:
        archive_dir: Path to the extracted analysis bundle.
        verbose: If True, log progress messages during pruning.

    Returns:
        Dictionary following the schema defined in the product spec.
    """
    archive_dir = Path(archive_dir)
    meta = _read_json(archive_dir / "meta.json")
    sections = _read_json(archive_dir / "sections.json")
    imports_exports = _read_json(archive_dir / "imports_exports.json")
    index_data = _read_json(archive_dir / "index.json")

    functions_path = archive_dir / "functions.jsonl"
    strings_path = archive_dir / "strings.jsonl"
    callgraph_path = archive_dir / "callgraph.jsonl"
    data_path = archive_dir / "data.jsonl"

    if not functions_path.exists():
        raise OneshotPruningError(f"Required artifact missing: {functions_path}")
    if not strings_path.exists():
        raise OneshotPruningError(f"Required artifact missing: {strings_path}")

    # Build minimal function records
    functions: List[Dict[str, Any]] = []
    name_by_ea: Dict[str, str] = {}
    ea_by_name: Dict[str, str] = {k: v for k, v in (index_data.get("by_name") or {}).items()}

    for entry in _iter_jsonl(functions_path):
        record = {
            "ea": entry.get("ea"),
            "name": entry.get("name") or entry.get("ea"),
            "metrics": entry.get("metrics") or {},
            "xrefs_in": entry.get("xrefs_in") or [],
            "xrefs_out": entry.get("xrefs_out") or [],
            "ranges": entry.get("ranges") or [],
        }
        functions.append(record)
        if record["ea"]:
            name_by_ea[record["ea"]] = record["name"]

    if not functions:
        raise OneshotPruningError("functions.jsonl is empty – cannot build summary.")

    if verbose:
        logger.info("Loaded %d functions from snapshot", len(functions))

    # Section analysis
    file_info = {
        "sha256": meta.get("sha256"),
        "name": meta.get("file_name"),
        "size": meta.get("file_size"),
        "format": _normalize_format(meta.get("executable_format") or meta.get("format")),
        "arch": _determine_arch(meta),
        "language_id": meta.get("language"),
        "image_base": _normalize_hex(meta.get("image_base")),
        "endian": meta.get("endian"),
    }

    section_summary, suspicious_sections = _analyze_sections(sections, file_info["format"])
    suspicious_section_names = {sec["name"].lower() for sec in suspicious_sections if sec.get("name")}

    for function in functions:
        ranges = function.get("ranges") or []
        first_range = ranges[0] if ranges else None
        start_addr = _parse_address(first_range[0]) if first_range else None
        section_name = _find_section_name(start_addr, sections)
        function["section_name"] = section_name

    # Imports → capabilities
    imports_by_capability, api_capabilities = _build_import_capabilities(imports_exports)

    if verbose:
        detected_caps = [cap for cap in CAPABILITY_ORDER if imports_by_capability.get(cap)]
        if detected_caps:
            logger.info("Detected capabilities from imports: %s", ", ".join(detected_caps))

    # Load strings and map to functions
    interesting_strings: List[Dict[str, Any]] = []
    string_kind_counts: Counter = Counter()
    function_strings: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    func_has_strings: set = set()

    for entry in _iter_jsonl(strings_path):
        value = entry.get("value")
        if not value:
            continue
        refs, ref_eas = _resolve_function_refs(entry.get("xrefs"), name_by_ea, ea_by_name)
        kind = _classify_string(value)
        if kind:
            # Always count string kinds for suspicion signals, regardless of MAX_STRINGS limit
            string_kind_counts[kind] += 1
            # Only add to interesting_strings list up to MAX_STRINGS limit
            if len(interesting_strings) < MAX_STRINGS:
                used_in_names = _dedup_preserve([ref.get("name") for ref in refs])
                interesting_strings.append(
                    {
                        "value": value,
                        "ea": entry.get("ea"),
                        "used_in": used_in_names,
                        "kind": kind,
                    }
                )
            for ea in ref_eas:
                if ea:
                    function_strings[ea].append((value, kind))
                    func_has_strings.add(ea)

    if verbose:
        total_string_kinds = sum(string_kind_counts.values())
        logger.info("Pruned strings: selected %d/%d interesting strings", len(interesting_strings), total_string_kinds)
        if string_kind_counts:
            kind_breakdown = ", ".join(f"{kind}={count}" for kind, count in string_kind_counts.most_common(5))
            logger.info("String breakdown: %s", kind_breakdown)

    # Callgraph
    callers_map, callees_map = _build_callgraph_maps(callgraph_path, name_by_ea)

    entrypoint_candidates = {
        name.lower()
        for name in [
            "main",
            "wmain",
            "winmain",
            "wwinmain",
            "dllmain",
            "servicemain",
            "driverentry",
            "_start",
            "entry",
            "start",
            "maincrtstartup",
            "wmaincrtstartup",
            "__tmaincrtstartup",
            "dllregisterserver",
            "dllinstall",
        ]
    }
    exported_names = {entry.get("name") for entry in imports_exports.get("exports", []) if entry.get("name")}
    exported_lower = {name.lower() for name in exported_names}
    entrypoint_names = entrypoint_candidates | exported_lower

    # Capabilities per function
    function_capabilities: Dict[str, set] = defaultdict(set)

    for function in functions:
        ea = function["ea"]
        for xref in function.get("xrefs_out", []):
            name = xref.get("name")
            if not name:
                continue
            caps = api_capabilities.get(name.lower())
            if caps:
                function_capabilities[ea].update(caps)
        for value, kind in function_strings.get(ea, []):
            function_capabilities[ea].update(STRING_KIND_TO_CAPS.get(kind, set()))

    if verbose:
        funcs_with_caps = sum(1 for caps in function_capabilities.values() if caps)
        logger.info("Mapped capabilities to %d/%d functions", funcs_with_caps, len(functions))

    # Score + select
    scored_functions = []
    for function in functions:
        score = _score_function(
            function,
            entrypoint_names,
            exported_names,
            suspicious_section_names,
            function_capabilities,
            func_has_strings,
        )
        function["score"] = score
        scored_functions.append(function)

    scored_functions.sort(key=lambda item: item["score"], reverse=True)

    selected: List[Dict[str, Any]] = []
    seen_eas: set = set()

    # Always include explicit entrypoints
    for function in scored_functions:
        name_lower = (function["name"] or "").lower()
        if name_lower in entrypoint_names and function["ea"] not in seen_eas:
            selected.append(function)
            seen_eas.add(function["ea"])
            if len(selected) >= MAX_KEY_FUNCTIONS:
                break

    if len(selected) < MAX_KEY_FUNCTIONS:
        for function in scored_functions:
            if function["ea"] in seen_eas:
                continue
            selected.append(function)
            seen_eas.add(function["ea"])
            if len(selected) >= MAX_KEY_FUNCTIONS:
                break

    if verbose:
        logger.info("Selected %d/%d key functions for analysis", len(selected), len(functions))

    key_functions_output: List[Dict[str, Any]] = []
    for function in selected:
        ea = function["ea"]
        metrics = function.get("metrics") or {}
        caps = sorted(function_capabilities.get(ea, []), key=lambda c: CAPABILITY_ORDER.index(c) if c in CAPABILITY_ORDER else len(CAPABILITY_ORDER))
        callers = callers_map.get(ea)
        callees = callees_map.get(ea)

        if not callers:
            fallback_callers = {}
            for caller_ea in function.get("xrefs_in", []):
                if isinstance(caller_ea, str) and not caller_ea.startswith("EXTERNAL"):
                    fallback_callers[caller_ea] = name_by_ea.get(caller_ea, caller_ea)
            callers = fallback_callers

        if not callees:
            fallback_callees = {}
            for callee in function.get("xrefs_out", []):
                callee_ea = callee.get("ea")
                if callee_ea and not callee_ea.startswith("EXTERNAL"):
                    fallback_callees[callee_ea] = callee.get("name") or name_by_ea.get(callee_ea, callee_ea)
            callees = fallback_callees

        strings_for_func = [
            value for value, _kind in function_strings.get(ea, [])
        ]

        key_functions_output.append(
            {
                "ea": ea,
                "name": function["name"],
                "size_bytes": metrics.get("size_bytes"),
                "cyclomatic_complexity": metrics.get("cyclomatic_complexity"),
                "capabilities": caps,
                "callers": _format_call_refs(callers or {}),
                "callees": _format_call_refs(callees or {}),
                "interesting_strings_used": _dedup_preserve(strings_for_func)[:5],
            }
        )

    # Possible configs (best-effort)
    possible_configs: List[Dict[str, Any]] = []
    if data_path.exists():
        for entry in _iter_jsonl(data_path):
            length = entry.get("length") or 0
            value = entry.get("value")
            ea = entry.get("ea")
            if length < 32 or not _looks_like_config(value):
                continue
            refs, _ = _resolve_function_refs(entry.get("xrefs"), name_by_ea, ea_by_name)
            if not refs:
                continue
            used_in = _dedup_preserve(ref.get("name") for ref in refs)
            if not used_in:
                continue
            possible_configs.append(
                {
                    "ea": ea,
                    "length": length,
                    "used_in": used_in,
                    "preview": (value or "")[:CONFIG_PREVIEW_LIMIT],
                }
            )
            if len(possible_configs) >= 20:
                break

    if verbose:
        logger.info("Found %d possible configuration strings", len(possible_configs))

    capa_summary_path = archive_dir / "capa_summary.json"
    capa_raw = _read_optional_json(capa_summary_path)
    capa_highlights = _summarize_capa_for_oneshot(capa_raw)
    if verbose and capa_highlights:
        logger.info("Included CAPA highlights (%d rules)", capa_highlights["counts"]["rules"] if capa_highlights.get("counts") else 0)

    summary = {
        "file": file_info,
        "sections": section_summary,
        "imports": {cap: imports_by_capability[cap] for cap in CAPABILITY_ORDER},
        "interesting_strings": interesting_strings,
        "key_functions": key_functions_output,
        "possible_configs": possible_configs,
        "suspicion_signals": _build_suspicion_signals(
            imports_by_capability,
            section_summary,
            string_kind_counts,
            file_info.get("size") or 0,
            key_functions_output,
        ),
        "notes": {
            "generation_version": GENERATION_VERSION,
            "limits": {
                "max_strings": MAX_STRINGS,
                "max_key_functions": MAX_KEY_FUNCTIONS,
            },
        },
    }

    if capa_highlights:
        summary["capa"] = capa_highlights

    return summary


__all__ = ["build_oneshot_summary", "OneshotPruningError"]
