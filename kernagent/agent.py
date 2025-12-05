"""Multi-step agent orchestration."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable

from .llm_client import LLMClient
from .log import get_logger
from .prompts import SYSTEM_PROMPT

logger = get_logger(__name__)


class ReverseEngineeringAgent:
    """Run the tool-calling loop over a snapshot."""

    def __init__(
        self,
        llm: LLMClient,
        tools_spec: Iterable[Dict[str, Any]],
        tool_map: Dict[str, Any],
        max_iterations: int = 20,
    ):
        self.llm = llm
        self.tools_spec = list(tools_spec)
        self.tool_map = tool_map
        self.max_iterations = max_iterations
        self.messages: list[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    def _format_args_short(self, args: Dict[str, Any]) -> str:
        """Format arguments for logging in a concise way."""
        if not args:
            return ""

        parts = []
        for key, value in args.items():
            if isinstance(value, str):
                # Truncate long strings
                if len(value) > 50:
                    value_str = f"{value[:47]}..."
                else:
                    value_str = value
                parts.append(f"{key}={value_str!r}")
            elif isinstance(value, (list, dict)):
                # Show type and length for collections
                if isinstance(value, list):
                    parts.append(f"{key}=list[{len(value)}]")
                else:
                    parts.append(f"{key}=dict[{len(value)}]")
            else:
                parts.append(f"{key}={value!r}")

        return ", ".join(parts)

    def run(self, question: str, verbose: bool = False) -> str:
        # Working messages includes history + current question + tool loop
        # Only user question and final answer are persisted to self.messages
        working_messages = self.messages + [{"role": "user", "content": question}]

        for iteration in range(self.max_iterations):
            if verbose:
                logger.info("Agent iteration %s/%s", iteration + 1, self.max_iterations)

            try:
                response = self.llm.chat(
                    verbose=verbose,
                    messages=working_messages,
                    tools=self.tools_spec,
                    tool_choice="auto",
                    temperature=0.1,
                )
            except Exception as exc:
                logger.error("LLM call failed: %s", exc)
                return f"LLM Error: {exc}"

            message = response.choices[0].message

            # Debug: log what we received from the API
            if verbose:
                logger.info(
                    "LLM response: content=%r, tool_calls=%s",
                    message.content[:100] if message.content else None,
                    len(message.tool_calls) if message.tool_calls else 0
                )

            message_dict = {"role": message.role, "content": message.content}
            if message.tool_calls:
                message_dict["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": call.type,
                        "function": {
                            "name": call.function.name,
                            "arguments": call.function.arguments,
                        },
                    }
                    for call in message.tool_calls
                ]
            working_messages.append(message_dict)

            if not message.tool_calls:
                # Persist only user question and final answer to history
                final_answer = message.content or "No response generated"
                self.messages.append({"role": "user", "content": question})
                self.messages.append({"role": "assistant", "content": final_answer})
                return final_answer

            for tool_call in message.tool_calls:
                func_name = tool_call.function.name
                handler = self.tool_map.get(func_name)
                try:
                    args = json.loads(tool_call.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}

                # Log tool call with short args representation when verbose
                if verbose:
                    args_str = self._format_args_short(args)
                    logger.info("Calling tool: %s(%s)", func_name, args_str)

                if not handler:
                    result = {"error": f"Unknown tool: {func_name}"}
                    if verbose:
                        logger.info("Tool %s: ERROR (unknown tool)", func_name)
                else:
                    try:
                        result = handler(**args)
                        if verbose:
                            logger.info("Tool %s: SUCCESS", func_name)
                    except Exception as exc:  # pragma: no cover - depends on tool inputs
                        logger.exception("Tool %s failed", func_name)
                        result = {"error": str(exc)}
                        if verbose:
                            logger.info("Tool %s: ERROR (%s)", func_name, type(exc).__name__)

                working_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(result),
                    }
                )

        logger.warning("Max iterations reached; requesting summary from model")
        try:
            working_messages.append(
                {
                    "role": "user",
                    "content": "Max iterations reached. Provide analysis based on gathered information.",
                }
            )
            final_response = self.llm.chat(
                verbose=verbose,
                messages=working_messages,
                temperature=0.1,
            )
            final_content = final_response.choices[0].message.content or "No summary generated"
            # Persist only user question and final answer to history
            self.messages.append({"role": "user", "content": question})
            self.messages.append({"role": "assistant", "content": final_content})
            return final_content
        except Exception as exc:  # pragma: no cover
            logger.error("Final summary request failed: %s", exc)
            return f"Max iterations reached. Error getting summary: {exc}"
