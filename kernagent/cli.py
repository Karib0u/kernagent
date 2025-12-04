"""kernagent command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
from pathlib import Path

import httpx

from .agent import ReverseEngineeringAgent
from .config import Settings, load_settings
from .llm_client import LLMClient
from .log import get_logger, setup_logging
from .oneshot import OneshotPruningError, build_oneshot_summary
from .prompts import ANALYZE_SYSTEM_PROMPT, SYSTEM_PROMPT, TOOLS
from .snapshot import SnapshotError, SnapshotTools, build_snapshot, build_tool_map

logger = get_logger(__name__)

# ============================================================================
# ASCII Banner
# ============================================================================

KERNAGENT_BANNER = r"""
 _  __                                      _
| |/ /   ___   _ __   _ __    __ _    __ _ | |_
| ' /   / _ \ | '__| | '_ \  / _` |  / _` ||  _|
| . \  |  __/ | |    | | | || (_| | | (_| || |_
|_|\_\  \___| |_|    |_| |_| \__,_|  \__, | \__|
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
    print(KERNAGENT_BANNER)
    print("Welcome! Let's configure your LLM provider.\n")

    providers = {
        "1": ("OpenAI", "https://api.openai.com/v1", "gpt-4o"),
        "2": ("Google (Gemini)", "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-1.5-pro"),
        "3": ("Anthropic", "https://api.anthropic.com/v1/", "claude-3-5-sonnet-20241022"),
        "4": ("Local (Ollama/LM Studio)", "http://host.docker.internal:1234/v1", ""),
        "5": ("Custom endpoint", "", ""),
    }

    print("Select your LLM provider:\n")
    for key, (name, url, _) in providers.items():
        hint = f"  ({url})" if url else ""
        print(f"  {key}) {name}{hint}")

    choice = input("\nProvider [1]: ").strip() or "1"
    if choice not in providers:
        choice = "1"

    name, default_url, default_model = providers[choice]
    print(f"\n--- {name} Configuration ---\n")

    # Get base URL
    if default_url:
        base_url = input(f"Base URL [{default_url}]: ").strip() or default_url
    else:
        base_url = input("Base URL: ").strip()
        while not base_url:
            print("  Base URL is required.")
            base_url = input("Base URL: ").strip()

    # Get API key (with masked input)
    if choice in ("1", "2", "3"):  # Cloud providers require key
        print("\nAPI Key (input hidden):")
        api_key = getpass.getpass("  > ").strip()
        while not api_key:
            print("  API key is required for this provider.")
            api_key = getpass.getpass("  > ").strip()
    elif choice == "4":  # Local providers don't need API key
        api_key = "not-needed"
    else:  # Custom endpoint - optional
        api_key = getpass.getpass("API Key (optional, press Enter to skip): ").strip() or "not-needed"

    # Convert localhost URLs for Docker compatibility
    docker_base_url = _convert_localhost_for_docker(base_url)
    if docker_base_url != base_url:
        print(f"  (Using {docker_base_url} for Docker compatibility)")

    # Fetch and select model
    print("\nFetching available models...")
    models = _fetch_models(docker_base_url, api_key)

    if models:
        print(f"Found {len(models)} models!")
        model = _select_from_list("Select model", models, default_model)
    else:
        if not models and (choice in ("1", "2", "3")):
            print("Could not fetch models (check API key or endpoint).")
        if default_model:
            model = input(f"Model [{default_model}]: ").strip() or default_model
        else:
            model = input("Model name: ").strip()
            while not model:
                print("  Model name is required.")
                model = input("Model name: ").strip()

    # Write config (using Docker-compatible URL)
    config_path = _get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w") as f:
        f.write(f"OPENAI_API_KEY={api_key}\n")
        f.write(f"OPENAI_BASE_URL={docker_base_url}\n")
        f.write(f"OPENAI_MODEL={model}\n")
        f.write("DEBUG=false\n")

    config_path.chmod(0o600)

    print("\n" + "=" * 50)
    print("Configuration complete!")
    print(f"  Provider: {name}")
    print(f"  Model:    {model}")
    print(f"  Saved to: {config_path}")
    print("=" * 50)
    print("\nYou're ready to go! Try:")
    print("  kernagent analyze <binary>")
    print("  kernagent chat <binary>")
    print()


def run_analyze(binary_path: Path, settings: Settings, verbose: bool, json_output: bool) -> None:
    """One-click threat assessment."""
    snapshot_dir = _snapshot_dir_for(binary_path)

    if not snapshot_dir.exists():
        print("🔨 Building snapshot...", file=sys.stderr)
        snapshot_dir = build_snapshot(binary_path, verbose=verbose)

    summary = build_oneshot_summary(snapshot_dir, verbose=verbose)

    if json_output:
        print(json.dumps(summary, indent=2))
        return

    llm = LLMClient(settings)
    payload = json.dumps(summary, indent=2)

    # Stream the response
    for chunk in llm.chat_stream(
        verbose=verbose,
        messages=[
            {"role": "system", "content": ANALYZE_SYSTEM_PROMPT},
            {"role": "user", "content": payload},
        ],
        temperature=0,
    ):
        print(chunk, end="", flush=True)
    print()  # Final newline


def run_chat(binary_path: Path, settings: Settings, verbose: bool) -> None:
    """Interactive RE session with REPL."""
    snapshot_dir = _snapshot_dir_for(binary_path)

    if not snapshot_dir.exists():
        print("🔨 Building snapshot...", file=sys.stderr)
        snapshot_dir = build_snapshot(binary_path, verbose=verbose)

    snapshot = SnapshotTools(snapshot_dir)
    tool_map = build_tool_map(snapshot)
    llm = LLMClient(settings)
    agent = ReverseEngineeringAgent(llm, TOOLS, tool_map)

    print(f"\nkernagent chat session for {binary_path.name}")
    print("Type 'exit', 'quit', or Ctrl+D to exit. 'clear' to reset.\n")

    while True:
        try:
            user_input = input("kernagent >> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            break
        if user_input.lower() == "clear":
            agent = ReverseEngineeringAgent(llm, TOOLS, tool_map)
            print("Session cleared.\n")
            continue

        try:
            answer = agent.run(user_input, verbose=verbose)
            print(f"\n{answer}\n")
        except Exception as exc:
            logger.error("Agent error: %s", exc)
            print(f"\nError: {exc}\n")


def run_snapshot(binary_path: Path | None, list_mode: bool, force: bool, verbose: bool) -> None:
    """Snapshot management."""
    if list_mode or binary_path is None:
        # List all .snapshot directories in current folder
        snapshots = list(Path.cwd().glob("*.snapshot"))
        if not snapshots:
            print("No snapshots found in current directory.")
            return
        print("Snapshots:")
        for s in sorted(snapshots):
            print(f"  {s.name}")
        return

    snapshot_dir = _snapshot_dir_for(binary_path)

    if snapshot_dir.exists() and not force:
        print(f"Snapshot exists: {snapshot_dir}")
        print("Use --force to rebuild.")
        return

    if snapshot_dir.exists() and force:
        shutil.rmtree(snapshot_dir)

    print(f"🔨 Building snapshot for {binary_path.name}...")
    result = build_snapshot(binary_path, verbose=verbose)
    print(f"✓ Snapshot created: {result}")


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
            run_analyze(binary_path, settings, args.verbose, json_output)
        except (SnapshotError, OneshotPruningError) as exc:
            logger.error("Analysis failed: %s", exc)
            raise SystemExit(str(exc)) from exc
    elif args.command == "chat":
        try:
            run_chat(binary_path, settings, args.verbose)
        except SnapshotError as exc:
            logger.error("Chat failed: %s", exc)
            raise SystemExit(str(exc)) from exc
    else:  # pragma: no cover
        parser.error("Unknown command")


if __name__ == "__main__":  # pragma: no cover
    main()
