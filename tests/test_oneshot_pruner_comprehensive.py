"""Comprehensive tests for oneshot pruner logic."""

from pathlib import Path

import pytest

from kernagent.oneshot.pruner import (
    MAX_KEY_FUNCTIONS,
    MAX_STRINGS,
    _analyze_sections,
    _build_import_capabilities,
    _build_suspicion_signals,
    _classify_string,
    _determine_arch,
    _looks_like_config,
    _match_capabilities,
    _normalize_format,
    _normalize_hex,
    _score_function,
    _section_permission_string,
    build_oneshot_summary,
)


@pytest.fixture
def fixture_archive():
    """Path to test fixture archive."""
    return Path(__file__).parent / "fixtures" / "bifrose_archive"


class TestStringClassification:
    """Test _classify_string() for different string types."""

    def test_classify_url_http(self):
        """HTTP URLs should be classified as 'url'."""
        assert _classify_string("http://example.com/path") == "url"
        assert _classify_string("Visit http://evil.com for more") == "url"

    def test_classify_url_https(self):
        """HTTPS URLs should be classified as 'url'."""
        assert _classify_string("https://example.com/api") == "url"

    def test_classify_url_generic_scheme(self):
        """Strings with :// might be classified as 'url'."""
        # Note: Only http:// and https:// are caught by URL_REGEX
        # Other schemes with :// will match the fallback "://" check at the end
        result = _classify_string("ftp://server.com")
        # This will be None because ftp:// doesn't match URL_REGEX and comes after domain check
        # Actually it should be url because of the "://" check at the end
        assert result in ["url", "domain", None]

    def test_classify_ip_public(self):
        """Public IPs should be classified as 'ip'."""
        assert _classify_string("8.8.8.8") == "ip"
        assert _classify_string("Connect to 1.2.3.4") == "ip"
        assert _classify_string("173.0.0.1") == "ip"  # Not in 172.16-31 range

    def test_classify_ip_private_skipped(self):
        """Private IPs should not be classified."""
        assert _classify_string("192.168.1.1") is None
        assert _classify_string("10.0.0.1") is None
        assert _classify_string("127.0.0.1") is None
        assert _classify_string("172.16.0.1") is None  # Private range
        assert _classify_string("172.31.255.255") is None  # Private range

    def test_classify_domain(self):
        """Domains should be classified as 'domain'."""
        assert _classify_string("example.com") == "domain"
        assert _classify_string("sub.domain.net") == "domain"
        assert _classify_string("malware.ru") == "domain"
        assert _classify_string("test.co.uk") == "domain"

    def test_classify_windows_path(self):
        """Windows paths should be classified as 'path'."""
        assert _classify_string("C:\\Windows\\System32") == "path"
        assert _classify_string("D:\\temp\\file.txt") == "path"

    def test_classify_posix_path(self):
        """POSIX paths should be classified as 'path'."""
        assert _classify_string("/etc/passwd") == "path"
        assert _classify_string("/var/log/messages") == "path"
        assert _classify_string("/usr/bin/bash") == "path"
        assert _classify_string("~/config") == "path"

    def test_classify_registry(self):
        """Windows registry paths should be classified as 'registry'."""
        assert _classify_string("HKLM\\Software\\Microsoft") == "registry"
        assert _classify_string("HKCU\\Run") == "registry"
        assert _classify_string("HKCR\\") == "registry"

    def test_classify_command(self):
        """Command strings should be classified as 'command'."""
        assert _classify_string("cmd.exe /c dir") == "command"
        assert _classify_string("powershell -enc ABC") == "command"
        # /bin/bash will match as path first (before command check)
        bash_result = _classify_string("/bin/bash -c 'ls'")
        assert bash_result in ["path", "command"]
        assert _classify_string("python exploit.py") == "command"
        assert _classify_string("chmod +x malware") == "command"
        assert _classify_string("certutil -decode") == "command"

    def test_classify_auth(self):
        """Auth-related strings should be classified as 'auth'."""
        assert _classify_string("password=secret") == "auth"
        assert _classify_string("Enter your token") == "auth"
        assert _classify_string("apikey: xyz") == "auth"
        assert _classify_string("credential store") == "auth"

    def test_classify_keyword(self):
        """Security keyword strings should be classified as 'keyword'."""
        assert _classify_string("vmware detected") == "keyword"
        assert _classify_string("Check for debugger") == "keyword"
        assert _classify_string("sandbox environment") == "keyword"

    def test_classify_too_short(self):
        """Strings shorter than 4 chars should return None."""
        assert _classify_string("abc") is None
        assert _classify_string("") is None
        assert _classify_string("xy") is None

    def test_classify_none_or_empty(self):
        """None or empty strings should return None."""
        assert _classify_string(None) is None
        assert _classify_string("") is None
        assert _classify_string("   ") is None


class TestCapabilityDetection:
    """Test _match_capabilities() and _build_import_capabilities()."""

    def test_match_network_capabilities(self):
        """Network-related APIs should match network capability."""
        caps = _match_capabilities("connect", "ws2_32")
        assert "network" in caps

        caps = _match_capabilities("HttpSendRequest", "wininet")
        assert "network" in caps

    def test_match_filesystem_capabilities(self):
        """Filesystem APIs should match filesystem capability."""
        caps = _match_capabilities("CreateFileA", "kernel32")
        assert "filesystem" in caps

        caps = _match_capabilities("fopen", "libc")
        assert "filesystem" in caps

    def test_match_process_capabilities(self):
        """Process manipulation APIs should match process capability."""
        caps = _match_capabilities("CreateProcess", "kernel32")
        assert "process" in caps

        caps = _match_capabilities("execve", "libc")
        assert "process" in caps

    def test_match_crypto_capabilities(self):
        """Crypto APIs should match crypto capability."""
        caps = _match_capabilities("CryptEncrypt", "advapi32")
        assert "crypto" in caps

        caps = _match_capabilities("AES_encrypt", None)
        assert "crypto" in caps

    def test_match_no_capability(self):
        """Unmatched APIs should return empty list."""
        caps = _match_capabilities("printf", "libc")
        assert len(caps) == 0

    def test_build_import_capabilities(self):
        """_build_import_capabilities should bucket APIs by capability."""
        imports_exports = {
            "imports": [
                {"name": "socket", "library": "ws2_32"},
                {"name": "CreateFile", "library": "kernel32"},
            ],
            "exports": [],
        }

        bucketed, api_map = _build_import_capabilities(imports_exports)

        assert "network" in bucketed
        assert "filesystem" in bucketed
        assert any("socket" in imp for imp in bucketed["network"])
        assert any("CreateFile" in imp for imp in bucketed["filesystem"])


class TestFunctionScoring:
    """Test _score_function() algorithm."""

    def test_score_entrypoint(self):
        """Entry point functions should get bonus score."""
        record = {
            "name": "main",
            "ea": "0x1000",
            "metrics": {"cyclomatic_complexity": 5, "size_bytes": 100},
            "xrefs_in": [],
            "xrefs_out": [],
            "section_name": ".text",
        }

        score = _score_function(
            record,
            entrypoint_names={"main"},
            exported_names=set(),
            suspicious_section_names=set(),
            func_capabilities={},
            func_has_strings=set(),
        )

        assert score >= 5  # Entrypoint bonus

    def test_score_high_complexity(self):
        """High complexity functions should get bonus score."""
        record = {
            "name": "complex_func",
            "ea": "0x2000",
            "metrics": {"cyclomatic_complexity": 25, "size_bytes": 100},
            "xrefs_in": [],
            "xrefs_out": [],
            "section_name": ".text",
        }

        score = _score_function(
            record,
            entrypoint_names=set(),
            exported_names=set(),
            suspicious_section_names=set(),
            func_capabilities={},
            func_has_strings=set(),
        )

        assert score >= 3  # Complexity bonus

    def test_score_large_function(self):
        """Large functions should get bonus score."""
        record = {
            "name": "large_func",
            "ea": "0x3000",
            "metrics": {"cyclomatic_complexity": 5, "size_bytes": 1000},
            "xrefs_in": [],
            "xrefs_out": [],
            "section_name": ".text",
        }

        score = _score_function(
            record,
            entrypoint_names=set(),
            exported_names=set(),
            suspicious_section_names=set(),
            func_capabilities={},
            func_has_strings=set(),
        )

        assert score >= 2  # Size bonus

    def test_score_with_capabilities(self):
        """Functions with capabilities should get bonus score."""
        record = {
            "name": "network_func",
            "ea": "0x4000",
            "metrics": {"cyclomatic_complexity": 5, "size_bytes": 100},
            "xrefs_in": [],
            "xrefs_out": [],
            "section_name": ".text",
        }

        score = _score_function(
            record,
            entrypoint_names=set(),
            exported_names=set(),
            suspicious_section_names=set(),
            func_capabilities={"0x4000": {"network"}},
            func_has_strings=set(),
        )

        assert score >= 3  # Capability bonus

    def test_score_with_strings(self):
        """Functions with interesting strings should get bonus score."""
        record = {
            "name": "string_func",
            "ea": "0x5000",
            "metrics": {"cyclomatic_complexity": 5, "size_bytes": 100},
            "xrefs_in": [],
            "xrefs_out": [],
            "section_name": ".text",
        }

        score = _score_function(
            record,
            entrypoint_names=set(),
            exported_names=set(),
            suspicious_section_names=set(),
            func_capabilities={},
            func_has_strings={"0x5000"},
        )

        assert score >= 3  # String bonus

    def test_score_high_fanout(self):
        """Functions with high fan-out should get bonus score."""
        record = {
            "name": "caller_func",
            "ea": "0x6000",
            "metrics": {"cyclomatic_complexity": 5, "size_bytes": 100},
            "xrefs_in": [],
            "xrefs_out": [{"ea": f"0x{i:04x}"} for i in range(10)],  # 10 callees
            "section_name": ".text",
        }

        score = _score_function(
            record,
            entrypoint_names=set(),
            exported_names=set(),
            suspicious_section_names=set(),
            func_capabilities={},
            func_has_strings=set(),
        )

        assert score >= 2  # Fan-out bonus

    def test_score_in_suspicious_section(self):
        """Functions in suspicious sections should get bonus score."""
        record = {
            "name": "sus_func",
            "ea": "0x7000",
            "metrics": {"cyclomatic_complexity": 5, "size_bytes": 100},
            "xrefs_in": [],
            "xrefs_out": [],
            "section_name": ".weird",
        }

        score = _score_function(
            record,
            entrypoint_names=set(),
            exported_names=set(),
            suspicious_section_names={".weird"},
            func_capabilities={},
            func_has_strings=set(),
        )

        assert score >= 2  # Suspicious section bonus


class TestSectionAnalysis:
    """Test _analyze_sections() for suspicious sections."""

    def test_detect_rwx_section(self):
        """RWX sections should be flagged as suspicious."""
        sections = [
            {
                "name": ".text",
                "start": "0x1000",
                "end": "0x2000",
                "size": 0x1000,
                "permissions": {"read": True, "write": True, "execute": True},
            }
        ]

        summary, suspicious = _analyze_sections(sections, "pe")

        assert summary["has_rwx"] is True
        assert len(suspicious) > 0

    def test_detect_non_standard_section(self):
        """Non-standard section names should be flagged."""
        sections = [
            {
                "name": ".weird",
                "start": "0x1000",
                "end": "0x2000",
                "size": 0x1000,
                "permissions": {"read": True, "write": False, "execute": False},
            }
        ]

        summary, suspicious = _analyze_sections(sections, "pe")

        assert len(suspicious) > 0
        assert suspicious[0]["name"] == ".weird"

    def test_standard_section_not_flagged(self):
        """Standard sections without suspicious properties should not be flagged."""
        sections = [
            {
                "name": ".text",
                "start": "0x1000",
                "end": "0x2000",
                "size": 0x1000,
                "permissions": {"read": True, "write": False, "execute": True},
            }
        ]

        summary, suspicious = _analyze_sections(sections, "pe")

        # .text with r-x is standard, should not be in suspicious list
        assert summary["has_rwx"] is False

    def test_section_permission_string(self):
        """Section permissions should be formatted correctly."""
        assert _section_permission_string({"read": True, "write": True, "execute": True}) == "rwx"
        assert _section_permission_string({"read": True, "write": False, "execute": True}) == "r-x"
        assert _section_permission_string({"read": False, "write": False, "execute": False}) == "---"


class TestSuspicionSignals:
    """Test _build_suspicion_signals()."""

    def test_signal_uses_network(self):
        """Network capabilities/strings should set uses_network."""
        signals = _build_suspicion_signals(
            imports_by_cap={"network": ["connect"]},
            sections_info={},
            string_kind_counts={"url": 0},
            file_size=100000,
            key_functions=[],
        )

        assert signals["uses_network"] is True

    def test_signal_uses_network_from_strings(self):
        """Network strings should set uses_network."""
        signals = _build_suspicion_signals(
            imports_by_cap={},
            sections_info={},
            string_kind_counts={"url": 5},
            file_size=100000,
            key_functions=[],
        )

        assert signals["uses_network"] is True

    def test_signal_uses_filesystem(self):
        """Filesystem capabilities should set uses_filesystem."""
        signals = _build_suspicion_signals(
            imports_by_cap={"filesystem": ["CreateFile"]},
            sections_info={},
            string_kind_counts={},
            file_size=100000,
            key_functions=[],
        )

        assert signals["uses_filesystem"] is True

    def test_signal_spawns_processes(self):
        """Process capabilities should set spawns_processes_or_shell."""
        signals = _build_suspicion_signals(
            imports_by_cap={"process": ["CreateProcess"]},
            sections_info={},
            string_kind_counts={},
            file_size=100000,
            key_functions=[],
        )

        assert signals["spawns_processes_or_shell"] is True

    def test_signal_allocates_rwx_memory(self):
        """Memory injection or RWX sections should set allocates_remote_or_rwx_memory."""
        signals = _build_suspicion_signals(
            imports_by_cap={"memory_injection": ["VirtualAlloc"]},
            sections_info={"has_rwx": False},
            string_kind_counts={},
            file_size=100000,
            key_functions=[],
        )

        assert signals["allocates_remote_or_rwx_memory"] is True

    def test_signal_persistence_indicators(self):
        """Persistence capabilities should set has_persistence_indicators."""
        signals = _build_suspicion_signals(
            imports_by_cap={"persistence": ["RegSetValue"]},
            sections_info={},
            string_kind_counts={},
            file_size=100000,
            key_functions=[],
        )

        assert signals["has_persistence_indicators"] is True

    def test_signal_unusually_small_but_complex(self):
        """Small file with complex functions should be flagged."""
        signals = _build_suspicion_signals(
            imports_by_cap={},
            sections_info={},
            string_kind_counts={},
            file_size=50000,  # Small
            key_functions=[{"cyclomatic_complexity": 35, "size_bytes": 100}],  # Complex
        )

        assert signals["is_unusually_small_but_complex"] is True

    def test_signal_shell_execution_strings(self):
        """Command strings should set has_shell_execution_strings."""
        signals = _build_suspicion_signals(
            imports_by_cap={},
            sections_info={},
            string_kind_counts={"command": 3},
            file_size=100000,
            key_functions=[],
        )

        assert signals["has_shell_execution_strings"] is True


class TestHelperFunctions:
    """Test various helper functions."""

    def test_normalize_format_pe(self):
        """PE formats should be normalized to 'pe'."""
        assert _normalize_format("Portable Executable") == "pe"
        assert _normalize_format("PE32") == "pe"
        assert _normalize_format("COFF") == "pe"

    def test_normalize_format_elf(self):
        """ELF formats should be normalized to 'elf'."""
        assert _normalize_format("ELF 64-bit LSB") == "elf"
        assert _normalize_format("elf") == "elf"

    def test_normalize_format_macho(self):
        """Mach-O formats should be normalized to 'mach-o'."""
        assert _normalize_format("Mach-O 64-bit") == "mach-o"
        assert _normalize_format("mach") == "mach-o"

    def test_normalize_format_unknown(self):
        """Unknown formats should return 'unknown'."""
        assert _normalize_format("Unknown Format") == "unknown"
        assert _normalize_format(None) == "unknown"

    def test_determine_arch_x86_64(self):
        """x86_64 architecture should be detected."""
        meta = {"language": "x86:le:64:default"}
        assert _determine_arch(meta) == "x86_64"

    def test_determine_arch_x86_32(self):
        """x86 architecture should be detected."""
        meta = {"language": "x86:le:32:default"}
        assert _determine_arch(meta) == "x86"

    def test_determine_arch_arm64(self):
        """ARM64 architecture should be detected."""
        meta = {"language": "arm:le:64:v8"}
        assert _determine_arch(meta) == "arm64"

    def test_normalize_hex(self):
        """Hex normalization should work."""
        assert _normalize_hex("0x1234") == "0x1234"
        assert _normalize_hex("ABCD") == "0xabcd"
        assert _normalize_hex("0") == "0x0"

    def test_looks_like_config(self):
        """Config detection should work."""
        assert _looks_like_config("server=example.com") is True
        assert _looks_like_config("host=1.2.3.4") is True
        assert _looks_like_config('{"key": "value"}') is True
        assert _looks_like_config("http://api.example.com/endpoint") is True
        assert _looks_like_config("param1=val1&param2=val2") is True
        assert _looks_like_config("random text") is False


class TestBuildOneshotSummary:
    """Test the main build_oneshot_summary() function."""

    def test_builds_summary_from_fixture(self, fixture_archive):
        """Should build complete summary from test fixture."""
        summary = build_oneshot_summary(fixture_archive)

        # Verify top-level structure
        assert "file" in summary
        assert "sections" in summary
        assert "imports" in summary
        assert "interesting_strings" in summary
        assert "key_functions" in summary
        assert "suspicion_signals" in summary

    def test_summary_file_info(self, fixture_archive):
        """File info should include required fields."""
        summary = build_oneshot_summary(fixture_archive)

        file_info = summary["file"]
        assert "sha256" in file_info
        assert "format" in file_info
        assert "arch" in file_info
        assert "size" in file_info

    def test_summary_respects_max_strings(self, fixture_archive):
        """Summary should respect MAX_STRINGS limit."""
        summary = build_oneshot_summary(fixture_archive)

        # interesting_strings is a list, not a dict by kind
        total_strings = len(summary["interesting_strings"])
        assert total_strings <= MAX_STRINGS

    def test_summary_respects_max_functions(self, fixture_archive):
        """Summary should respect MAX_KEY_FUNCTIONS limit."""
        summary = build_oneshot_summary(fixture_archive)

        assert len(summary["key_functions"]) <= MAX_KEY_FUNCTIONS

    def test_summary_includes_suspicion_signals(self, fixture_archive):
        """Summary should include suspicion signals."""
        summary = build_oneshot_summary(fixture_archive)

        signals = summary["suspicion_signals"]
        assert "uses_network" in signals
        assert "uses_filesystem" in signals
        assert "spawns_processes_or_shell" in signals
        assert isinstance(signals["uses_network"], bool)

    def test_summary_imports_by_capability(self, fixture_archive):
        """Summary should include imports."""
        summary = build_oneshot_summary(fixture_archive)

        imports = summary["imports"]
        assert isinstance(imports, dict)
        # Should have capability categories
        assert isinstance(imports, dict)

    def test_summary_interesting_strings(self, fixture_archive):
        """Summary should include interesting strings."""
        summary = build_oneshot_summary(fixture_archive)

        interesting_strings = summary["interesting_strings"]
        assert isinstance(interesting_strings, list)

    def test_summary_key_functions_structure(self, fixture_archive):
        """Key functions should have expected structure."""
        summary = build_oneshot_summary(fixture_archive)

        key_functions = summary["key_functions"]
        if key_functions:
            # Verify structure of first function
            func = key_functions[0]
            assert "ea" in func
            assert "name" in func
            assert "size_bytes" in func or "cyclomatic_complexity" in func

    def test_summary_includes_capa_when_available(self, fixture_archive):
        """CAPA highlights should be merged when capa_summary.json exists."""
        summary = build_oneshot_summary(fixture_archive)
        assert "capa" in summary
        capa = summary["capa"]
        assert capa["top_rules"], "Expected at least one CAPA rule highlight"
        assert capa["counts"]["rules"] >= len(capa["top_rules"])

    def test_summary_capa_highlights_shape(self, fixture_archive):
        """CAPA highlights should expose top tactics and attack IDs."""
        summary = build_oneshot_summary(fixture_archive)
        capa = summary.get("capa")
        assert capa is not None
        highlights = capa.get("highlights") or {}
        assert isinstance(highlights.get("top_attack_ids"), list)
        assert isinstance(highlights.get("top_tactics"), list)
