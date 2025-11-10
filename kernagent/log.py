"""Logging helpers for kernagent."""

from __future__ import annotations

import logging


def setup_logging(debug: bool = False) -> None:
    """Configure root logger with a consistent format."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not debug:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        # Quiet noisy dependencies (vivisect/capa) unless explicitly debugging
        for noisy in (
            "vivisect",
            "vivisect.base",
            "vivisect.analysis",
            "vivisect.tools",
            "viv_utils",
        ):
            logging.getLogger(noisy).setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(name)
