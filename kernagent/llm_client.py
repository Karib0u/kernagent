"""OpenAI-compatible client wrapper."""

from __future__ import annotations

from typing import Iterator

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - handled lazily
    OpenAI = None  # type: ignore[assignment]

from .config import Settings
from .log import get_logger

logger = get_logger(__name__)


class LLMClient:
    """Thin convenience wrapper around the OpenAI SDK."""

    def __init__(self, settings: Settings):
        if OpenAI is None:  # pragma: no cover - depends on local tooling setup
            raise ImportError(
                "The OpenAI SDK is required to use LLMClient. "
                "Install it with `pip install openai`."
            )
        self.settings = settings
        self.client = OpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url,
        )

    def chat(self, verbose: bool = False, **kwargs):
        """Call the chat completions API.

        Args:
            verbose: If True, log API call details.
            **kwargs: Arguments passed to the OpenAI chat completions API.
        """
        kwargs.setdefault("model", self.settings.model)

        if verbose:
            logger.info("Calling LLM API with model: %s", kwargs["model"])

        response = self.client.chat.completions.create(**kwargs)

        if verbose and hasattr(response, "usage") and response.usage:
            logger.info(
                "LLM response received - tokens: prompt=%d, completion=%d, total=%d",
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
                response.usage.total_tokens,
            )

        return response

    def chat_stream(self, verbose: bool = False, **kwargs) -> Iterator[str]:
        """Stream chat completions token by token.

        Args:
            verbose: If True, log API call details.
            **kwargs: Arguments passed to the OpenAI chat completions API.

        Yields:
            Content strings as they arrive from the API.
        """
        kwargs.setdefault("model", self.settings.model)
        kwargs["stream"] = True

        if verbose:
            logger.info("Streaming LLM API with model: %s", kwargs["model"])

        stream = self.client.chat.completions.create(**kwargs)

        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
