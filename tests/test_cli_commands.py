"""Comprehensive tests for CLI commands."""

import json
from pathlib import Path
from unittest import mock

import pytest

from kernagent.cli import (
    build_parser,
    ensure_snapshot,
    run_analyze,
    run_chat,
    run_snapshot,
    _snapshot_dir_for,
    _get_config_path,
    _fetch_models,
)
from kernagent.config import Settings
from kernagent.snapshot import SnapshotError


class DummyMessage:
    """Mock message for LLM responses."""

    def __init__(self, content, tool_calls=None):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls or []


class DummyChoice:
    """Mock choice for LLM responses."""

    def __init__(self, message):
        self.message = message


class DummyResponse:
    """Mock response for LLM chat completions."""

    def __init__(self, content):
        self.choices = [DummyChoice(DummyMessage(content))]


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
def fixture_archive():
    """Path to test fixture snapshot."""
    return Path(__file__).parent / "fixtures" / "bifrose.snapshot"


# ============================================================================
# Argument Parsing Tests
# ============================================================================


class TestArgumentParsing:
    """Test CLI argument parsing for new commands."""

    def test_parser_requires_command(self):
        """Parser should require a subcommand."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_init_command_parsing(self):
        """Test init command argument parsing."""
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"

    def test_analyze_command_parsing(self):
        """Test analyze command argument parsing."""
        parser = build_parser()
        args = parser.parse_args(["analyze", "/path/to/binary"])
        assert args.command == "analyze"
        assert args.binary == Path("/path/to/binary")
        assert not args.json

    def test_analyze_command_with_json_flag(self):
        """Test analyze command with --json flag."""
        parser = build_parser()
        args = parser.parse_args(["analyze", "/path/to/binary", "--json"])
        assert args.command == "analyze"
        assert args.json

    def test_chat_command_parsing(self):
        """Test chat command argument parsing."""
        parser = build_parser()
        args = parser.parse_args(["chat", "/path/to/binary"])
        assert args.command == "chat"
        assert args.binary == Path("/path/to/binary")

    def test_snapshot_command_parsing(self):
        """Test snapshot command argument parsing."""
        parser = build_parser()
        args = parser.parse_args(["snapshot", "/path/to/binary"])
        assert args.command == "snapshot"
        assert args.binary == Path("/path/to/binary")
        assert not args.list
        assert not args.force

    def test_snapshot_command_with_list_flag(self):
        """Test snapshot command with --list flag."""
        parser = build_parser()
        args = parser.parse_args(["snapshot", "--list"])
        assert args.command == "snapshot"
        assert args.list
        assert args.binary is None

    def test_snapshot_command_with_force_flag(self):
        """Test snapshot command with --force flag."""
        parser = build_parser()
        args = parser.parse_args(["snapshot", "/path/to/binary", "--force"])
        assert args.command == "snapshot"
        assert args.force

    def test_global_model_override(self):
        """Test --model global argument."""
        parser = build_parser()
        args = parser.parse_args(["--model", "custom-model", "analyze", "/path/to/binary"])
        assert args.model == "custom-model"

    def test_global_base_url_override(self):
        """Test --base-url global argument."""
        parser = build_parser()
        args = parser.parse_args(["--base-url", "http://custom-url", "analyze", "/path/to/binary"])
        assert args.base_url == "http://custom-url"

    def test_global_api_key_override(self):
        """Test --api-key global argument."""
        parser = build_parser()
        args = parser.parse_args(["--api-key", "custom-key", "analyze", "/path/to/binary"])
        assert args.api_key == "custom-key"

    def test_verbose_flag(self):
        """Test --verbose global flag."""
        parser = build_parser()
        args = parser.parse_args(["-v", "analyze", "/path/to/binary"])
        assert args.verbose


# ============================================================================
# Helper Function Tests
# ============================================================================


class TestHelperFunctions:
    """Test helper functions."""

    def test_snapshot_dir_for(self):
        """Test _snapshot_dir_for returns correct path."""
        binary = Path("/some/path/test.exe")
        result = _snapshot_dir_for(binary)
        assert result == Path("/some/path/test.snapshot")

    def test_get_config_path_default(self, monkeypatch):
        """Test _get_config_path with default path."""
        monkeypatch.delenv("KERNAGENT_CONFIG", raising=False)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setenv("HOME", "/home/testuser")
        result = _get_config_path()
        assert result == Path("/home/testuser/.config/kernagent/config.env")

    def test_get_config_path_from_env(self, monkeypatch):
        """Test _get_config_path respects KERNAGENT_CONFIG env var."""
        monkeypatch.setenv("KERNAGENT_CONFIG", "/custom/config.env")
        result = _get_config_path()
        assert result == Path("/custom/config.env")

    def test_fetch_models_returns_empty_on_error(self):
        """Test _fetch_models returns empty list on network error."""
        result = _fetch_models("http://invalid-url", "test-key")
        assert result == []


# ============================================================================
# Snapshot Tests
# ============================================================================


class TestEnsureSnapshot:
    """Test snapshot discovery and creation logic."""

    def test_returns_existing_snapshot_directory(self, tmp_path):
        """Should return existing snapshot directory if present."""
        binary = tmp_path / "test.exe"
        binary.touch()
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        result = ensure_snapshot(binary, verbose=False)
        assert result == snapshot_dir

    @mock.patch("kernagent.cli.build_snapshot")
    def test_builds_snapshot_if_nothing_exists(self, mock_build, tmp_path):
        """Should build snapshot via PyGhidra if nothing exists."""
        binary = tmp_path / "test.exe"
        binary.touch()
        snapshot_dir = tmp_path / "test.snapshot"

        mock_build.return_value = snapshot_dir

        result = ensure_snapshot(binary, verbose=True)
        assert result == snapshot_dir
        mock_build.assert_called_once_with(binary, None, verbose=True)


# ============================================================================
# Analyze Command Tests
# ============================================================================


class TestAnalyzeCommand:
    """Test analyze command execution."""

    def test_analyze_json_output(self, fixture_archive, mock_settings, capsys):
        """Analyze --json should output pruned JSON without LLM call."""
        # Create a mock binary path that maps to the fixture
        binary_path = fixture_archive.parent / "bifrose"

        with mock.patch("kernagent.cli._snapshot_dir_for", return_value=fixture_archive):
            run_analyze(binary_path, mock_settings, verbose=False, json_output=True)

        captured = capsys.readouterr()
        output = json.loads(captured.out)

        assert "file" in output
        assert "sections" in output

    def test_analyze_streaming_output(self, fixture_archive, mock_settings, capsys):
        """Analyze without --json should stream LLM response."""
        binary_path = fixture_archive.parent / "bifrose"

        with mock.patch("kernagent.cli._snapshot_dir_for", return_value=fixture_archive):
            with mock.patch("kernagent.cli.LLMClient") as mock_llm_class:
                mock_llm = mock.Mock()
                mock_llm.chat_stream.return_value = iter(["Threat ", "assessment ", "complete."])
                mock_llm_class.return_value = mock_llm

                run_analyze(binary_path, mock_settings, verbose=False, json_output=False)

                captured = capsys.readouterr()
                assert "Threat assessment complete." in captured.out
                mock_llm.chat_stream.assert_called_once()


# ============================================================================
# Snapshot Command Tests
# ============================================================================


class TestSnapshotCommand:
    """Test snapshot command execution."""

    def test_snapshot_list_mode(self, tmp_path, capsys, monkeypatch):
        """Snapshot --list should list all .snapshot directories."""
        monkeypatch.chdir(tmp_path)

        # Create some snapshot directories
        (tmp_path / "test1.snapshot").mkdir()
        (tmp_path / "test2.snapshot").mkdir()

        run_snapshot(None, list_mode=True, force=False, verbose=False)

        captured = capsys.readouterr()
        assert "test1.snapshot" in captured.out
        assert "test2.snapshot" in captured.out

    def test_snapshot_list_empty(self, tmp_path, capsys, monkeypatch):
        """Snapshot --list with no snapshots should print message."""
        monkeypatch.chdir(tmp_path)

        run_snapshot(None, list_mode=True, force=False, verbose=False)

        captured = capsys.readouterr()
        assert "No snapshots found" in captured.out

    def test_snapshot_exists_without_force(self, tmp_path, capsys):
        """Snapshot should not rebuild without --force."""
        binary = tmp_path / "test.exe"
        binary.touch()
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()

        run_snapshot(binary, list_mode=False, force=False, verbose=False)

        captured = capsys.readouterr()
        assert "Snapshot exists" in captured.out
        assert "--force" in captured.out

    @mock.patch("kernagent.cli.build_snapshot")
    def test_snapshot_force_rebuild(self, mock_build, tmp_path, capsys):
        """Snapshot --force should rebuild existing snapshot."""
        binary = tmp_path / "test.exe"
        binary.touch()
        snapshot_dir = tmp_path / "test.snapshot"
        snapshot_dir.mkdir()
        (snapshot_dir / "meta.json").write_text("{}")

        mock_build.return_value = snapshot_dir

        run_snapshot(binary, list_mode=False, force=True, verbose=False)

        mock_build.assert_called_once()
        captured = capsys.readouterr()
        assert "Snapshot created" in captured.out


# ============================================================================
# Settings Override Tests
# ============================================================================


class TestSettingsOverride:
    """Test that CLI arguments override settings."""

    def test_model_override_applied(self):
        """Test that --model overrides settings.model."""
        parser = build_parser()
        args = parser.parse_args(["--model", "gpt-4", "analyze", "/test/binary"])

        settings = Settings()
        if args.model:
            settings.model = args.model

        assert settings.model == "gpt-4"

    def test_base_url_override_applied(self):
        """Test that --base-url overrides settings.base_url."""
        parser = build_parser()
        args = parser.parse_args(["--base-url", "http://custom", "analyze", "/test/binary"])

        settings = Settings()
        if args.base_url:
            settings.base_url = args.base_url

        assert settings.base_url == "http://custom"

    def test_api_key_override_applied(self):
        """Test that --api-key overrides settings.api_key."""
        parser = build_parser()
        args = parser.parse_args(["--api-key", "sk-custom", "analyze", "/test/binary"])

        settings = Settings()
        if args.api_key:
            settings.api_key = args.api_key

        assert settings.api_key == "sk-custom"
