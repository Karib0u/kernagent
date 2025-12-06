"""Modern Typer-based CLI for kernagent."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .cli import run_init, run_analyze, run_chat, run_snapshot
from .config import Settings, load_settings
from .log import get_logger, setup_logging
from .oneshot import OneshotPruningError
from .snapshot import SnapshotError

logger = get_logger(__name__)

app = typer.Typer(
    name="kernagent",
    help="Static binary analysis assistant powered by LLMs.",
    no_args_is_help=True,
    add_completion=False,
)

# Global context for settings
_settings: Settings | None = None


def get_settings(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Settings:
    """Load settings with CLI overrides."""
    global _settings
    if _settings is None:
        _settings = load_settings()

    # Apply overrides
    if model:
        _settings.model = model
    if base_url:
        _settings.base_url = base_url
    if api_key:
        _settings.api_key = api_key

    return _settings


@app.command()
def init() -> None:
    """
    Interactive configuration wizard.

    Guides you through setting up your LLM provider, API credentials,
    and model selection.
    """
    run_init()


@app.command()
def analyze(
    binary: Annotated[Path, typer.Argument(help="Path to the binary to analyze")],
    json_output: Annotated[bool, typer.Option("--json", help="Output raw JSON")] = False,
    full: Annotated[bool, typer.Option("--full", help="Build full multi-agent context")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging")] = False,
    model: Annotated[Optional[str], typer.Option(help="Override LLM model")] = None,
    base_url: Annotated[Optional[str], typer.Option(help="Override API base URL")] = None,
    api_key: Annotated[Optional[str], typer.Option(help="Override API key")] = None,
) -> None:
    """
    One-click threat assessment of a binary.

    Generates a comprehensive security analysis by examining the binary's
    behavior, capabilities, and potential threats.
    """
    settings = get_settings(model, base_url, api_key)
    setup_logging(settings.debug)

    binary_path = binary.expanduser().resolve()
    if not binary_path.exists():
        typer.echo(f"Error: Binary not found: {binary_path}", err=True)
        raise typer.Exit(1)

    try:
        run_analyze(binary_path, settings, verbose, json_output, full)
    except (SnapshotError, OneshotPruningError) as exc:
        logger.error("Analysis failed: %s", exc)
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


@app.command()
def chat(
    binary: Annotated[Path, typer.Argument(help="Path to the binary to analyze")],
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging")] = False,
    model: Annotated[Optional[str], typer.Option(help="Override LLM model")] = None,
    base_url: Annotated[Optional[str], typer.Option(help="Override API base URL")] = None,
    api_key: Annotated[Optional[str], typer.Option(help="Override API key")] = None,
) -> None:
    """
    Interactive reverse engineering session.

    Start a chat session with an AI assistant that has full context
    about the binary. Ask questions, explore functions, and get insights.
    """
    settings = get_settings(model, base_url, api_key)
    setup_logging(settings.debug)

    binary_path = binary.expanduser().resolve()
    if not binary_path.exists():
        typer.echo(f"Error: Binary not found: {binary_path}", err=True)
        raise typer.Exit(1)

    try:
        run_chat(binary_path, settings, verbose)
    except (SnapshotError, OneshotPruningError) as exc:
        logger.error("Chat failed: %s", exc)
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


@app.command()
def snapshot(
    binary: Annotated[Optional[Path], typer.Argument(help="Binary to snapshot")] = None,
    list_snapshots: Annotated[bool, typer.Option("--list", help="List all snapshots")] = False,
    force: Annotated[bool, typer.Option("--force", help="Force rebuild existing snapshot")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging")] = False,
    model: Annotated[Optional[str], typer.Option(help="Override LLM model")] = None,
    base_url: Annotated[Optional[str], typer.Option(help="Override API base URL")] = None,
    api_key: Annotated[Optional[str], typer.Option(help="Override API key")] = None,
) -> None:
    """
    Snapshot management commands.

    Create, list, or rebuild Ghidra analysis snapshots for binaries.
    Snapshots contain decompiled code, function info, and other artifacts.
    """
    settings = get_settings(model, base_url, api_key)
    setup_logging(settings.debug)

    binary_path = None
    if binary:
        binary_path = binary.expanduser().resolve()
        if not binary_path.exists():
            typer.echo(f"Error: Binary not found: {binary_path}", err=True)
            raise typer.Exit(1)

    run_snapshot(binary_path, list_snapshots, force, verbose)


def main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main()
