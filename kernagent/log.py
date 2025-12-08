"""Logging helpers for kernagent."""

from __future__ import annotations

import logging

from .config import Settings


def setup_logging(debug: bool = False) -> None:
    """Configure root logger with a consistent format."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not debug:
        # Silence noisy dependencies that shred CLI animations
        logging.getLogger("httpx").setLevel(logging.CRITICAL)
        for noisy in (
            "vivisect",
            "vivisect.base",
            "vivisect.analysis",
            "vivisect.tools",
            "viv_utils",
            "capa",
        ):
            logging.getLogger(noisy).setLevel(logging.CRITICAL)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(name)


def init_logging_from_cli(verbose: bool, settings: Settings) -> None:
    """Initialize logging based on CLI flags and settings."""

    debug = settings.debug or verbose
    setup_logging(debug)
    if verbose:
        logger = get_logger(__name__)
        logger.info("Using model=%s base_url=%s", settings.model, settings.base_url)
