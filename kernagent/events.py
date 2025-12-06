"""Event types for streaming agent progress."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ThinkingEvent:
    """Agent is thinking/making LLM request."""
    iteration: int
    max_iterations: int


@dataclass
class ToolCallEvent:
    """Agent is calling a tool."""
    tool_name: str
    arguments: Dict[str, Any]
    tool_call_id: str


@dataclass
class ToolResultEvent:
    """Tool execution completed."""
    tool_name: str
    success: bool
    error: str | None = None


@dataclass
class MessageEvent:
    """Agent has a message/response for the user."""
    content: str
    is_final: bool = False


@dataclass
class ErrorEvent:
    """An error occurred."""
    message: str


@dataclass
class MaxIterationsEvent:
    """Max iterations reached, requesting summary."""
    pass


# Type alias for any event
AgentEvent = ThinkingEvent | ToolCallEvent | ToolResultEvent | MessageEvent | ErrorEvent | MaxIterationsEvent
