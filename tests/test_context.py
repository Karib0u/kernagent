"""Comprehensive tests for multi-agent context building system."""

import json
from pathlib import Path
from unittest import mock

import pytest

from kernagent.context import (
    CONTEXT_HEADER,
    CONTEXT_VERSION,
    build_basic_context_markdown,
    build_full_context_markdown,
    detect_context_level,
    ensure_context,
    ensure_oneshot_summary,
    run_capabilities_agent,
    run_classification_agent,
    run_context_synth_agent,
    run_obfuscation_agent,
    run_structure_agent,
    write_context_file,
)
from kernagent.config import Settings


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_settings():
    """Create test settings."""
    return Settings(
        api_key="test-key",
        base_url="http://test-url",
        model="test-model",
        debug=False,
    )


@pytest.fixture
def minimal_summary():
    """Minimal valid oneshot summary."""
    return {
        "file": {"name": "test.exe", "format": "PE", "arch": "x86"},
        "sections": {"sections": [], "has_rwx": False, "suspicious": []},
        "imports": {},
        "key_functions": [],
        "interesting_strings": [],
        "possible_configs": [],
    }


@pytest.fixture
def fixture_snapshot():
    """Path to test fixture snapshot."""
    return Path(__file__).parent / "fixtures" / "bifrose.snapshot"


class DummyMessage:
    """Mock LLM message."""

    def __init__(self, content):
        self.role = "assistant"
        self.content = content
        self.tool_calls = []


class DummyChoice:
    """Mock LLM choice."""

    def __init__(self, message):
        self.message = message


class DummyResponse:
    """Mock LLM response."""

    def __init__(self, content):
        self.choices = [DummyChoice(DummyMessage(content))]


# ============================================================================
# File I/O Tests
# ============================================================================


class TestWriteContextFile:
    """Test context file writing with headers."""

    def test_writes_with_correct_header(self, tmp_path):
        """Should write file with proper header format."""
        output = tmp_path / "test_context.md"
        markdown = "# Test Content\nSome analysis here."

        write_context_file(output, markdown, level="basic")

        content = output.read_text()
        assert content.startswith(CONTEXT_HEADER)
        assert f"level: basic" in content
        assert f"version: {CONTEXT_VERSION}" in content
        assert "# Test Content" in content
        assert content.endswith("\n")

    def test_strips_extra_whitespace(self, tmp_path):
        """Should strip leading/trailing whitespace from markdown."""
        output = tmp_path / "test_context.md"
        markdown = "\n\n  # Content  \n\n"

        write_context_file(output, markdown, level="full")

        content = output.read_text()
        # Should have header + stripped content + single newline
        assert not content.endswith("\n\n")
        assert content.count("# Content") == 1


class TestDetectContextLevel:
    """Test context level detection from file headers."""

    def test_detects_basic_level(self, tmp_path):
        """Should detect basic level from header."""
        ctx_file = tmp_path / "context.md"
        ctx_file.write_text(f"{CONTEXT_HEADER}\nlevel: basic\nversion: {CONTEXT_VERSION}\n\nContent")

        assert detect_context_level(ctx_file) == "basic"

    def test_detects_full_level(self, tmp_path):
        """Should detect full level from header."""
        ctx_file = tmp_path / "context.md"
        ctx_file.write_text(f"{CONTEXT_HEADER}\nlevel: full\nversion: {CONTEXT_VERSION}\n\nContent")

        assert detect_context_level(ctx_file) == "full"

    def test_returns_unknown_for_missing_file(self, tmp_path):
        """Should return 'unknown' if file doesn't exist."""
        ctx_file = tmp_path / "nonexistent.md"

        assert detect_context_level(ctx_file) == "unknown"

    def test_returns_unknown_for_invalid_header(self, tmp_path):
        """Should return 'unknown' if header is missing."""
        ctx_file = tmp_path / "context.md"
        ctx_file.write_text("# Just some markdown\nNo header here")

        assert detect_context_level(ctx_file) == "unknown"

    def test_returns_unknown_for_missing_level(self, tmp_path):
        """Should return 'unknown' if level line is missing."""
        ctx_file = tmp_path / "context.md"
        ctx_file.write_text(f"{CONTEXT_HEADER}\nversion: {CONTEXT_VERSION}\n\nContent")

        assert detect_context_level(ctx_file) == "unknown"

    def test_case_insensitive_detection(self, tmp_path):
        """Should detect level case-insensitively."""
        ctx_file = tmp_path / "context.md"
        ctx_file.write_text(f"{CONTEXT_HEADER}\nLEVEL: BASIC\nVersion: v1\n\nContent")

        assert detect_context_level(ctx_file) == "basic"


# ============================================================================
# Oneshot Summary Tests
# ============================================================================


class TestEnsureOneshotSummary:
    """Test oneshot summary loading and creation."""

    def test_loads_existing_summary(self, fixture_snapshot):
        """Should load existing oneshot_summary.json if present."""
        summary = ensure_oneshot_summary(fixture_snapshot, verbose=False)

        assert "file" in summary
        assert "sections" in summary
        assert isinstance(summary, dict)

    @mock.patch("kernagent.context.build_oneshot_summary")
    def test_builds_missing_summary(self, mock_build, tmp_path, minimal_summary):
        """Should build and save summary if missing."""
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        mock_build.return_value = minimal_summary

        summary = ensure_oneshot_summary(snapshot_dir, verbose=True)

        mock_build.assert_called_once_with(snapshot_dir, verbose=True)
        assert summary == minimal_summary

        # Should have saved to disk
        saved_path = snapshot_dir / "oneshot_summary.json"
        assert saved_path.exists()
        saved_data = json.loads(saved_path.read_text())
        assert saved_data == minimal_summary


# ============================================================================
# Individual Agent Tests
# ============================================================================


class TestCapabilitiesAgent:
    """Test capabilities agent execution."""

    def test_returns_valid_json_structure(self, mock_settings, minimal_summary):
        """Should return structured JSON with capabilities."""
        mock_response = {
            "capabilities": [
                {
                    "name": "network",
                    "status": "confirmed",
                    "confidence": "HIGH",
                    "description": "Network communication detected",
                    "evidence": ["import ws2_32!WSAStartup"],
                }
            ],
            "notes": [],
        }

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()
            mock_llm.chat.return_value = DummyResponse(json.dumps(mock_response))
            mock_llm_class.return_value = mock_llm

            result = run_capabilities_agent(mock_llm, minimal_summary, verbose=False)

            assert "capabilities" in result
            assert len(result["capabilities"]) == 1
            assert result["capabilities"][0]["name"] == "network"
            mock_llm.chat.assert_called_once()


class TestStructureAgent:
    """Test structure agent execution."""

    def test_returns_valid_json_structure(self, mock_settings, minimal_summary):
        """Should return structured JSON with entrypoints and paths."""
        mock_response = {
            "entrypoints": [
                {
                    "name": "entry",
                    "ea": "10001537",
                    "reason": "Standard PE entry point",
                    "evidence": ["function entry@10001537"],
                }
            ],
            "pivot_functions": [],
            "execution_paths": [],
            "notes": [],
        }

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()
            mock_llm.chat.return_value = DummyResponse(json.dumps(mock_response))
            mock_llm_class.return_value = mock_llm

            result = run_structure_agent(mock_llm, minimal_summary, verbose=False)

            assert "entrypoints" in result
            assert len(result["entrypoints"]) == 1


class TestObfuscationAgent:
    """Test obfuscation agent execution."""

    def test_returns_valid_json_structure(self, mock_settings, minimal_summary):
        """Should return structured JSON with obfuscation analysis."""
        mock_response = {
            "packing_or_protectors": {
                "status": "no_clear_evidence",
                "description": "No packing detected",
                "evidence": [],
            },
            "crypto_usage": [],
            "anti_analysis": [],
            "notes": [],
        }

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()
            mock_llm.chat.return_value = DummyResponse(json.dumps(mock_response))
            mock_llm_class.return_value = mock_llm

            result = run_obfuscation_agent(mock_llm, minimal_summary, verbose=False)

            assert "packing_or_protectors" in result
            assert result["packing_or_protectors"]["status"] == "no_clear_evidence"


class TestClassificationAgent:
    """Test classification agent execution."""

    def test_combines_all_agent_outputs(self, mock_settings, minimal_summary):
        """Should receive and process all upstream agent outputs."""
        caps = {"capabilities": []}
        struct = {"entrypoints": []}
        obf = {"packing_or_protectors": {}}

        mock_response = {
            "verdict": "BENIGN",
            "risk_level": "LOW",
            "family": "unknown",
            "justification": "No malicious indicators",
            "key_behaviors": [],
            "attack_mapping": [],
            "open_questions": [],
        }

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()
            mock_llm.chat.return_value = DummyResponse(json.dumps(mock_response))
            mock_llm_class.return_value = mock_llm

            result = run_classification_agent(
                mock_llm,
                summary=minimal_summary,
                capabilities=caps,
                structure=struct,
                obfuscation=obf,
                verbose=False,
            )

            assert "verdict" in result
            assert result["verdict"] == "BENIGN"

            # Verify it received combined payload
            call_args = mock_llm.chat.call_args
            messages = call_args[1]["messages"]
            user_msg = json.loads(messages[1]["content"])
            assert "summary" in user_msg
            assert "capabilities" in user_msg
            assert "structure" in user_msg
            assert "obfuscation" in user_msg


class TestContextSynthAgent:
    """Test context synthesis agent execution."""

    def test_produces_markdown_output(self, mock_settings, minimal_summary):
        """Should return markdown document."""
        caps = {"capabilities": []}
        struct = {"entrypoints": []}
        obf = {"packing_or_protectors": {}}
        cls = {"verdict": "BENIGN"}

        mock_markdown = "# Overview\nThis is a test binary.\n\n# Verdict & Risk\nBENIGN"

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()
            mock_llm.chat.return_value = DummyResponse(mock_markdown)
            mock_llm_class.return_value = mock_llm

            result = run_context_synth_agent(
                mock_llm,
                summary=minimal_summary,
                capabilities=caps,
                structure=struct,
                obfuscation=obf,
                classification=cls,
                verbose=False,
            )

            assert "# Overview" in result
            assert "# Verdict & Risk" in result
            assert isinstance(result, str)


# ============================================================================
# High-Level Context Building Tests
# ============================================================================


class TestBuildBasicContext:
    """Test basic (single-agent) context building."""

    def test_produces_markdown_from_summary(self, mock_settings, minimal_summary):
        """Should generate markdown context from oneshot summary."""
        mock_markdown = "# Overview\nBasic analysis complete.\n\n# Capabilities\nNetwork: confirmed"

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()
            mock_llm.chat.return_value = DummyResponse(mock_markdown)
            mock_llm_class.return_value = mock_llm

            result = build_basic_context_markdown(minimal_summary, mock_settings, verbose=False)

            assert "# Overview" in result
            assert isinstance(result, str)
            mock_llm.chat.assert_called_once()


class TestBuildFullContext:
    """Test full (multi-agent) context building."""

    def test_orchestrates_all_agents(self, mock_settings, minimal_summary):
        """Should run all 5 agents in sequence."""
        mock_caps = {"capabilities": []}
        mock_struct = {"entrypoints": []}
        mock_obf = {"packing_or_protectors": {}}
        mock_cls = {"verdict": "UNKNOWN"}
        mock_markdown = "# Full Analysis\nComplete."

        with mock.patch("kernagent.context.LLMClient") as mock_llm_class:
            mock_llm = mock.Mock()

            # Agent calls return JSON, synthesis returns markdown
            mock_llm.chat.side_effect = [
                DummyResponse(json.dumps(mock_caps)),  # capabilities
                DummyResponse(json.dumps(mock_struct)),  # structure
                DummyResponse(json.dumps(mock_obf)),  # obfuscation
                DummyResponse(json.dumps(mock_cls)),  # classification
                DummyResponse(mock_markdown),  # synthesis
            ]
            mock_llm_class.return_value = mock_llm

            result = build_full_context_markdown(minimal_summary, mock_settings, verbose=True)

            assert "# Full Analysis" in result
            # Should have called LLM 5 times (4 agents + 1 synthesis)
            assert mock_llm.chat.call_count == 5


# ============================================================================
# Integration: ensure_context Tests
# ============================================================================


class TestEnsureContext:
    """Test main ensure_context orchestration."""

    def test_returns_existing_full_context(self, tmp_path, mock_settings):
        """Should not rebuild if full context already exists."""
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        ctx_file = snapshot_dir / "BINARY_CONTEXT.md"
        write_context_file(ctx_file, "# Existing full context", level="full")

        result = ensure_context(snapshot_dir, mock_settings, level="basic", verbose=False)

        assert result == ctx_file
        # Should not have modified the file
        assert "# Existing full context" in ctx_file.read_text()

    def test_returns_existing_basic_when_basic_requested(self, tmp_path, mock_settings):
        """Should not rebuild basic if basic exists and basic requested."""
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        ctx_file = snapshot_dir / "BINARY_CONTEXT.md"
        write_context_file(ctx_file, "# Existing basic context", level="basic")

        result = ensure_context(snapshot_dir, mock_settings, level="basic", verbose=False)

        assert result == ctx_file
        assert "# Existing basic context" in ctx_file.read_text()

    @mock.patch("kernagent.context.build_basic_context_markdown")
    @mock.patch("kernagent.context.ensure_oneshot_summary")
    def test_builds_basic_when_missing(self, mock_ensure, mock_build, tmp_path, mock_settings, minimal_summary):
        """Should build basic context if none exists."""
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        mock_ensure.return_value = minimal_summary
        mock_build.return_value = "# New basic context"

        result = ensure_context(snapshot_dir, mock_settings, level="basic", verbose=False)

        assert result == snapshot_dir / "BINARY_CONTEXT.md"
        assert detect_context_level(result) == "basic"
        mock_build.assert_called_once()

    @mock.patch("kernagent.context.build_full_context_markdown")
    @mock.patch("kernagent.context.ensure_oneshot_summary")
    def test_upgrades_basic_to_full_when_requested(self, mock_ensure, mock_build, tmp_path, mock_settings, minimal_summary):
        """Should rebuild from basic to full when full is requested."""
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        ctx_file = snapshot_dir / "BINARY_CONTEXT.md"
        write_context_file(ctx_file, "# Basic context", level="basic")

        mock_ensure.return_value = minimal_summary
        mock_build.return_value = "# Upgraded full context"

        result = ensure_context(snapshot_dir, mock_settings, level="full", verbose=True)

        assert result == ctx_file
        assert detect_context_level(result) == "full"
        assert "# Upgraded full context" in ctx_file.read_text()
        mock_build.assert_called_once()

    def test_raises_on_invalid_level(self, tmp_path, mock_settings):
        """Should raise ValueError for invalid level."""
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        with pytest.raises(ValueError, match="level must be 'basic' or 'full'"):
            ensure_context(snapshot_dir, mock_settings, level="invalid", verbose=False)


# ============================================================================
# Real Fixture Integration Test
# ============================================================================


class TestRealFixture:
    """Test with actual bifrose fixture."""

    def test_loads_real_oneshot_summary(self, fixture_snapshot):
        """Should successfully load real fixture summary."""
        if not fixture_snapshot.exists():
            pytest.skip("Fixture not available")

        summary = ensure_oneshot_summary(fixture_snapshot, verbose=False)

        # Verify it has expected structure
        assert "file" in summary
        assert "bifrose" in summary["file"]["name"].lower()
        assert "sections" in summary
        assert "key_functions" in summary
