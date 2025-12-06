"""kernagent command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import httpx

from .agent import ReverseEngineeringAgent
from .context import ensure_context, ensure_oneshot_summary
from .config import Settings, load_settings
from .llm_client import LLMClient
from .log import get_logger, setup_logging
from .oneshot import OneshotPruningError
from .prompts import ANALYZE_SYSTEM_PROMPT, TOOLS
from .snapshot import SnapshotError, SnapshotTools, build_snapshot, build_tool_map

logger = get_logger(__name__)

# ============================================================================
# ASCII Banner
# ============================================================================

KERNAGENT_BANNER = r"""
     _                                            _
    | | _____ _ __ _ __   __ _  __ _  ___ _ __ | |_
    | |/ / _ \ '__| '_ \ / _` |/ _` |/ _ \ '_ \| __|
    |   <  __/ |  | | | | (_| | (_| |  __/ | | | |_
    |_|\_\___|_|  |_| |_|\__,_|\__, |\___|_| |_|\__|
                                |___/
            Static Binary Analysis Assistant
"""

# ============================================================================
# Helper Functions
# ============================================================================


def _snapshot_dir_for(binary_path: Path) -> Path:
    """Return expected snapshot directory path for a binary."""
    return binary_path.parent / f"{binary_path.stem}.snapshot"


def _get_config_path() -> Path:
    """Determine config file path, respecting KERNAGENT_CONFIG env var."""
    config_path = os.environ.get("KERNAGENT_CONFIG")
    if config_path:
        return Path(config_path)
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "kernagent" / "config.env"


def _convert_localhost_for_docker(url: str) -> str:
    """Convert localhost URLs to host.docker.internal for Docker containers."""
    import re
    # Match localhost, 127.0.0.1, or 0.0.0.0
    pattern = r"(https?://)(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?"
    return re.sub(pattern, r"\1host.docker.internal\2", url)


def _fetch_models(base_url: str, api_key: str) -> list[str]:
    """Query endpoint for available models."""
    try:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{base_url.rstrip('/')}/models", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            # Handle both {data: [...]} and {models: [...]} formats
            models = data.get("data") or data.get("models") or []
            return [m.get("id", m.get("name", "")) for m in models if isinstance(m, dict)]
    except Exception:
        return []


def _select_from_list(prompt: str, options: list[str], default: str = "") -> str:
    """Display numbered list with pagination and let user select."""
    if not options:
        return input(f"{prompt}: ").strip() or default

    page_size = 15
    page = 0
    total_pages = (len(options) + page_size - 1) // page_size

    while True:
        start = page * page_size
        end = min(start + page_size, len(options))
        page_options = options[start:end]

        print(f"\n{prompt}:")
        for i, opt in enumerate(page_options, start + 1):
            marker = " *" if opt == default else ""
            print(f"  {i:2}) {opt}{marker}")

        # Navigation hints
        nav_hints = []
        if page > 0:
            nav_hints.append("'p' prev")
        if end < len(options):
            nav_hints.append("'n' next")
        if total_pages > 1:
            nav_hints.append(f"page {page + 1}/{total_pages}")

        if nav_hints:
            print(f"  [{', '.join(nav_hints)}]")

        choice = input("\nSelect number or type custom: ").strip()

        if not choice:
            return options[0] if options else default
        if choice.lower() == "n" and end < len(options):
            page += 1
            continue
        if choice.lower() == "p" and page > 0:
            page -= 1
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        return choice  # Custom input


def ensure_snapshot(binary_path: Path, verbose: bool = False) -> Path:
    """Ensure snapshot exists, building if necessary."""
    snapshot_dir = _snapshot_dir_for(binary_path)
    if snapshot_dir.exists():
        return snapshot_dir
    logger.info("Snapshot not found; building via Ghidra/PyGhidra")
    return build_snapshot(binary_path, None, verbose=verbose)


# ============================================================================
# Argument Parser
# ============================================================================


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with 4 commands."""
    parser = argparse.ArgumentParser(
        prog="kernagent",
        description="Static binary analysis assistant."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--model", type=str, help="Override the LLM model.")
    parser.add_argument("--base-url", type=str, help="Override the API base URL.")
    parser.add_argument("--api-key", type=str, help="Override the API key.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # init command
    subparsers.add_parser("init", help="Interactive configuration wizard.")

    # analyze command
    analyze = subparsers.add_parser("analyze", help="One-click threat assessment.")
    analyze.add_argument("binary", type=Path, help="Path to the binary.")
    analyze.add_argument("--json", action="store_true", help="Output raw JSON.")
    analyze.add_argument(
        "--full",
        action="store_true",
        help="Build a full multi-agent context (BINARY_CONTEXT.md) in addition to the summary.",
    )

    # chat command
    chat = subparsers.add_parser("chat", help="Interactive RE session.")
    chat.add_argument("binary", type=Path, help="Path to the binary.")

    # snapshot command
    snapshot = subparsers.add_parser("snapshot", help="Snapshot management.")
    snapshot.add_argument("binary", type=Path, nargs="?", help="Binary to snapshot.")
    snapshot.add_argument("--list", action="store_true", help="List snapshots.")
    snapshot.add_argument("--force", action="store_true", help="Force rebuild.")

    return parser


# ============================================================================
# Command Implementations
# ============================================================================


def run_init() -> None:
    """Interactive configuration wizard with premium UX."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt

    console = Console()

    # Display welcome banner
    console.print(Panel.fit(
        KERNAGENT_BANNER + "\n[dim]Static Binary Analysis Assistant[/dim]",
        border_style="blue",
        padding=(1, 2)
    ))
    console.print("\n[bold cyan]Welcome![/bold cyan] Let's configure your LLM provider.\n")

    providers = {
        "1": ("OpenAI", "https://api.openai.com/v1", "gpt-4o"),
        "2": ("Google (Gemini)", "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-1.5-pro"),
        "3": ("Anthropic", "https://api.anthropic.com/v1/", "claude-3-5-sonnet-20241022"),
        "4": ("Local (Ollama/LM Studio)", "http://host.docker.internal:1234/v1", ""),
        "5": ("Custom endpoint", "", ""),
    }

    # Display providers in a table
    table = Table(title="Available LLM Providers", show_header=True, header_style="bold magenta")
    table.add_column("Choice", style="cyan", width=8)
    table.add_column("Provider", style="green")
    table.add_column("Endpoint", style="dim")

    for key, (name, url, _) in providers.items():
        table.add_row(key, name, url or "[dim]Custom[/dim]")

    console.print(table)

    choice = Prompt.ask("\n[bold]Select provider[/bold]", default="1", choices=list(providers.keys()))

    name, default_url, default_model = providers[choice]
    console.print(f"\n[bold blue]━━━ {name} Configuration ━━━[/bold blue]\n")

    # Get base URL
    if default_url:
        base_url = Prompt.ask("[cyan]Base URL[/cyan]", default=default_url)
    else:
        base_url = ""
        while not base_url:
            base_url = Prompt.ask("[cyan]Base URL[/cyan] (required)")

    # Get API key (with masked input)
    if choice in ("1", "2", "3"):  # Cloud providers require key
        api_key = ""
        while not api_key:
            api_key = Prompt.ask("[cyan]API Key[/cyan] (required)", password=True)
    elif choice == "4":  # Local providers don't need API key
        api_key = "not-needed"
        console.print("[dim]Skipping API key for local provider[/dim]")
    else:  # Custom endpoint - optional
        api_key = Prompt.ask("[cyan]API Key[/cyan] (optional)", default="not-needed", password=True)

    console.print("[green]✓[/green] Provider configured")

    # Convert localhost URLs for Docker compatibility
    docker_base_url = _convert_localhost_for_docker(base_url)
    if docker_base_url != base_url:
        console.print(f"[dim]  Using {docker_base_url} for Docker compatibility[/dim]")

    # Fetch and select model
    console.print("\n[yellow]⚙[/yellow]  Fetching available models...")
    models = _fetch_models(docker_base_url, api_key)

    if models:
        console.print(f"[green]✓[/green] Found {len(models)} models!")

        # Display models in a table if there are many
        if len(models) > 15:
            model = _select_from_list("Select model", models, default_model)
        else:
            model_table = Table(show_header=False, box=None)
            model_table.add_column("Number", style="cyan", width=4)
            model_table.add_column("Model", style="white")

            for i, m in enumerate(models[:15], 1):
                marker = " [green]*[/green]" if m == default_model else ""
                model_table.add_row(str(i), f"{m}{marker}")

            console.print(model_table)

            # Get model choice
            choice_str = Prompt.ask("\n[bold]Select model number or type custom[/bold]", default="1")
            if choice_str.isdigit() and 1 <= int(choice_str) <= len(models):
                model = models[int(choice_str) - 1]
            else:
                model = choice_str
    else:
        if choice in ("1", "2", "3"):
            console.print("[yellow]⚠[/yellow]  Could not fetch models (check API key or endpoint)")
        if default_model:
            model = Prompt.ask("[cyan]Model name[/cyan]", default=default_model)
        else:
            model = ""
            while not model:
                model = Prompt.ask("[cyan]Model name[/cyan] (required)")

    console.print(f"[green]✓[/green] Model selected: [bold]{model}[/bold]")

    # Write config (using Docker-compatible URL)
    config_path = _get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w") as f:
        f.write(f"OPENAI_API_KEY={api_key}\n")
        f.write(f"OPENAI_BASE_URL={docker_base_url}\n")
        f.write(f"OPENAI_MODEL={model}\n")
        f.write("DEBUG=false\n")

    config_path.chmod(0o600)

    # Success message
    console.print("\n" + "─" * 60)
    console.print(Panel.fit(
        f"[green]✓ Configuration Complete![/green]\n\n"
        f"[cyan]Provider:[/cyan] {name}\n"
        f"[cyan]Model:[/cyan]    {model}\n"
        f"[cyan]Config:[/cyan]   {config_path}",
        border_style="green",
        padding=(1, 2)
    ))
    console.print("─" * 60)

    console.print("\n[bold green]You're ready to go![/bold green] Try these commands:\n")
    console.print("  [cyan]kernagent analyze[/cyan] [dim]<binary>[/dim]")
    console.print("  [cyan]kernagent chat[/cyan] [dim]<binary>[/dim]\n")


def run_analyze(
    binary_path: Path,
    settings: Settings,
    verbose: bool,
    json_output: bool,
    full: bool,
) -> None:
    """One-click threat assessment."""
    from rich.console import Console
    from rich.rule import Rule
    from datetime import datetime
    import io
    import contextlib

    console = Console()
    snapshot_dir = _snapshot_dir_for(binary_path)

    # Suppress verbose output unless verbose flag is set
    output_suppressor = contextlib.redirect_stdout(io.StringIO()) if not verbose else contextlib.nullcontext()

    # Step 1: Snapshot
    if not snapshot_dir.exists():
        with console.status("[bold blue]Extracting binary artifacts via Ghidra...", spinner="dots"):
            with output_suppressor:
                snapshot_dir = build_snapshot(binary_path, verbose=verbose)
        console.print("[green]✓[/green] Snapshot extracted")
    else:
        console.print(f"[dim]Using existing snapshot: {snapshot_dir.name}[/dim]")

    # Step 2: Context
    context_level = "full" if full else "basic"
    with console.status(f"[bold blue]Preparing {context_level} analysis context...", spinner="dots"):
        with output_suppressor:
            context_path = ensure_context(snapshot_dir, settings, level=context_level, verbose=verbose)
            context_text = context_path.read_text(encoding="utf-8")
            summary = ensure_oneshot_summary(snapshot_dir, verbose=verbose)
    console.print(f"[green]✓[/green] Context prepared ({len(context_text):,} characters)")

    # Step 3: Analysis
    console.print(f"[bold blue]Analyzing {binary_path.name}...[/bold blue]")

    if json_output:
        print(json.dumps(summary, indent=2))
        return

    llm = LLMClient(settings)
    payload = json.dumps(summary, indent=2)

    # Stream the response and render as markdown
    from rich.markdown import Markdown
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.columns import Columns

    console.print(f"\n[bold cyan]Analysis for {binary_path.name}:[/bold cyan]\n")

    accumulated_text = ""

    # Use Live display for real-time markdown rendering
    with Live(console=console, refresh_per_second=4) as live:
        live.update(Spinner("dots", text="[dim]Generating analysis...[/dim]"))

        for chunk in llm.chat_stream(
            verbose=verbose,
            messages=[
                {"role": "system", "content": ANALYZE_SYSTEM_PROMPT},
                {
                    "role": "system",
                    "content": "Pre-analysis context for this binary (BINARY_CONTEXT.md):\n\n" + context_text,
                },
                {"role": "user", "content": payload},
            ],
            temperature=0,
        ):
            accumulated_text += chunk
            # Update live display with rendered markdown
            live.update(Markdown(accumulated_text))

    # Final markdown render
    console.print(Markdown(accumulated_text))
    console.print()

    # Add finishing touches
    console.print(Rule(style="dim"))
    console.print(f"[dim]Analysis completed at {datetime.now().strftime('%H:%M:%S')}[/dim]")
    console.print(f"[dim]Context saved to: {context_path}[/dim]\n")


def run_chat(binary_path: Path, settings: Settings, verbose: bool) -> None:
    """Interactive RE session with REPL."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    import io
    import contextlib
    from .events import (
        ThinkingEvent,
        ToolCallEvent,
        ToolResultEvent,
        MessageEvent,
        ErrorEvent,
        MaxIterationsEvent,
    )

    console = Console()
    snapshot_dir = _snapshot_dir_for(binary_path)

    # Suppress verbose output unless verbose flag is set
    output_suppressor = contextlib.redirect_stdout(io.StringIO()) if not verbose else contextlib.nullcontext()

    # Step 1: Snapshot
    if not snapshot_dir.exists():
        with console.status("[bold blue]Extracting binary artifacts via Ghidra...", spinner="dots"):
            with output_suppressor:
                snapshot_dir = build_snapshot(binary_path, verbose=verbose)
        console.print("[green]✓[/green] Snapshot extracted")
    else:
        console.print(f"[dim]Using existing snapshot: {snapshot_dir.name}[/dim]")

    # Step 2: Context
    with console.status("[bold blue]Preparing analysis context...", spinner="dots"):
        with output_suppressor:
            context_path = ensure_context(snapshot_dir, settings, level="basic", verbose=verbose)
            context_text = context_path.read_text(encoding="utf-8")
    console.print(f"[green]✓[/green] Context ready ({len(context_text):,} characters)")

    snapshot = SnapshotTools(snapshot_dir)
    tool_map = build_tool_map(snapshot)
    llm = LLMClient(settings)

    def _make_agent() -> ReverseEngineeringAgent:
        base_agent = ReverseEngineeringAgent(llm, TOOLS, tool_map)
        base_agent.messages.insert(
            1,
            {
                "role": "system",
                "content": "Pre-analysis context for this specific binary:\n\n" + context_text,
            },
        )
        return base_agent

    agent = _make_agent()

    # Display welcome banner
    console.print(Panel.fit(
        f"[bold cyan]Chat session for {binary_path.name}[/bold cyan]\n\n"
        f"[dim]Type 'exit', 'quit', or Ctrl+D to exit\n"
        f"Type 'clear' to reset conversation[/dim]",
        border_style="cyan"
    ))
    console.print()

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]>>[/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting...[/dim]")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            console.print("[dim]Goodbye![/dim]")
            break
        if user_input.lower() == "clear":
            agent = _make_agent()
            console.print("[yellow]✓[/yellow] Session cleared\n")
            continue

        try:
            from rich.live import Live
            from rich.spinner import Spinner

            # Use Live context for smooth updates
            with Live(console=console, refresh_per_second=10, transient=True) as live:
                for event in agent.run_stream(user_input, verbose=verbose):
                    if isinstance(event, ThinkingEvent):
                        # Show spinner while thinking
                        live.update(Spinner("dots", text=f"[dim]Thinking... (step {event.iteration}/{event.max_iterations})[/dim]"))

                    elif isinstance(event, ToolCallEvent):
                        # Show tool call immediately (not in live display)
                        live.stop()
                        # Format tool arguments for display
                        args_str = ", ".join(f"{k}={v!r}" for k, v in list(event.arguments.items())[:2])
                        if len(event.arguments) > 2:
                            args_str += ", ..."
                        console.print(f"[dim]  → {event.tool_name}({args_str})[/dim]")
                        live.start()

                    elif isinstance(event, ToolResultEvent):
                        live.stop()
                        if event.success:
                            console.print("[dim]    [green]✓[/green] Done[/dim]")
                        else:
                            console.print(f"[dim]    [red]✗[/red] Error: {event.error}[/dim]")
                        live.start()

                    elif isinstance(event, MaxIterationsEvent):
                        live.stop()
                        console.print("[yellow]⚠[/yellow]  Max iterations reached, generating summary...")
                        live.start()

                    elif isinstance(event, MessageEvent):
                        if event.is_final:
                            # Stop the live display before showing final answer
                            live.stop()
                            # Display the final answer
                            console.print("\n[bold magenta]Assistant:[/bold magenta]")
                            console.print(event.content)
                            console.print()

                    elif isinstance(event, ErrorEvent):
                        live.stop()
                        console.print(f"\n[red]Error:[/red] {event.message}\n")

        except Exception as exc:
            logger.error("Agent error: %s", exc)
            console.print(f"\n[red]Error:[/red] {exc}\n")


def run_snapshot(binary_path: Path | None, list_mode: bool, force: bool, verbose: bool) -> None:
    """Snapshot management."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()

    if list_mode or binary_path is None:
        # List all .snapshot directories (current dir + subdirs)
        # Also check /data for Docker environments where host dir is mounted there
        search_paths = [Path.cwd()]
        data_path = Path("/data")
        if data_path.exists() and data_path.is_dir():
            search_paths.append(data_path)

        snapshots: set[Path] = set()
        for base in search_paths:
            snapshots |= set(base.glob("*.snapshot")) | set(base.glob("**/*.snapshot"))

        if not snapshots:
            console.print("[yellow]No snapshots found.[/yellow]")
            return

        # Display snapshots in a table
        table = Table(title="Available Snapshots", show_header=True, header_style="bold cyan")
        table.add_column("Snapshot", style="green")
        table.add_column("Path", style="dim")

        for s in sorted(snapshots):
            # Show relative path from cwd or /data
            try:
                rel = s.relative_to(Path.cwd())
            except ValueError:
                try:
                    rel = s.relative_to(data_path)
                except ValueError:
                    rel = s
            table.add_row(s.name, str(rel.parent) if rel.parent != Path(".") else ".")

        console.print(table)
        return

    snapshot_dir = _snapshot_dir_for(binary_path)

    if snapshot_dir.exists() and not force:
        console.print(Panel.fit(
            f"[yellow]Snapshot already exists[/yellow]\n\n"
            f"[dim]Path:[/dim] {snapshot_dir}\n\n"
            f"[dim]Use[/dim] [cyan]--force[/cyan] [dim]to rebuild[/dim]",
            border_style="yellow"
        ))
        return

    if snapshot_dir.exists() and force:
        console.print("[yellow]⚠[/yellow]  Removing existing snapshot...")
        shutil.rmtree(snapshot_dir)

    with console.status(f"[bold blue]Building snapshot for {binary_path.name}...", spinner="dots"):
        result = build_snapshot(binary_path, verbose=verbose)

    console.print(Panel.fit(
        f"[green]✓ Snapshot created successfully![/green]\n\n"
        f"[dim]Path:[/dim] {result}",
        border_style="green"
    ))


# ============================================================================
# Main Entry Point
# ============================================================================


def main() -> None:
    """Main CLI entry point."""
    settings = load_settings()
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    setup_logging(settings.debug)

    # Apply CLI overrides
    if getattr(args, "model", None):
        settings.model = args.model
    if getattr(args, "base_url", None):
        settings.base_url = args.base_url
    if getattr(args, "api_key", None):
        settings.api_key = args.api_key

    # Dispatch commands
    if args.command == "init":
        run_init()
        return

    if args.command == "snapshot":
        binary = getattr(args, "binary", None)
        if binary:
            binary = Path(binary).expanduser().resolve()
            if not binary.exists():
                raise FileNotFoundError(binary)
        run_snapshot(binary, args.list, getattr(args, "force", False), args.verbose)
        return

    # analyze and chat require binary
    binary_path = Path(args.binary).expanduser().resolve()
    if not binary_path.exists():
        raise FileNotFoundError(binary_path)

    if args.command == "analyze":
        try:
            json_output = getattr(args, "json", False)
            full = getattr(args, "full", False)
            run_analyze(binary_path, settings, args.verbose, json_output, full)
        except (SnapshotError, OneshotPruningError) as exc:
            logger.error("Analysis failed: %s", exc)
            raise SystemExit(str(exc)) from exc
    elif args.command == "chat":
        try:
            run_chat(binary_path, settings, args.verbose)
        except (SnapshotError, OneshotPruningError) as exc:
            logger.error("Chat failed: %s", exc)
            raise SystemExit(str(exc)) from exc
    else:  # pragma: no cover
        parser.error("Unknown command")


if __name__ == "__main__":  # pragma: no cover
    main()
