"""Runtime configuration for kernagent."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None


@dataclass
class Settings:
    """Container for runtime configuration values."""

    api_key: str = os.getenv("OPENAI_API_KEY", "not-needed")
    base_url: str = os.getenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    model: str = os.getenv("OPENAI_MODEL", "kernagent-default-model")
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"


def load_settings() -> Settings:
    """Load settings from environment (optionally via python-dotenv)."""
    if load_dotenv:
        config_path = os.environ.get(
            "KERNAGENT_CONFIG",
            str(
                Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
                / "kernagent"
                / "config.env"
            ),
        )
        if os.path.exists(config_path):
            load_dotenv(config_path)
    return Settings()
