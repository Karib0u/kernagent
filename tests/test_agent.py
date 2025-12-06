from kernagent.agent import ReverseEngineeringAgent


class DummyToolCallFunction:
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class DummyToolCall:
    def __init__(self, name: str, arguments: str = "{}"):
        self.id = "call_1"
        self.type = "function"
        self.function = DummyToolCallFunction(name, arguments)


class DummyMessage:
    def __init__(self, content, tool_calls=None):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls or []


class DummyResponse:
    def __init__(self, message):
        self.choices = [type("Choice", (), {"message": message})()]


class FakeLLM:
    def __init__(self):
        self.invocations = 0

    def chat(self, **kwargs):
        if self.invocations == 0:
            self.invocations += 1
            tool_call = DummyToolCall("echo_tool", '{"text": "hi"}')
            return DummyResponse(DummyMessage(None, [tool_call]))

        self.invocations += 1
        return DummyResponse(DummyMessage("final-answer"))


def test_agent_runs_tool_loop():
    llm = FakeLLM()

    def echo_tool(**kwargs):
        return {"received": kwargs}

    agent = ReverseEngineeringAgent(
        llm=llm,
        tools_spec=[
            {
                "type": "function",
                "function": {
                    "name": "echo_tool",
                    "parameters": {"type": "object", "properties": {"text": {"type": "string"}}},
                },
            }
        ],
        tool_map={"echo_tool": echo_tool},
    )

    answer = agent.run("test question")
    assert answer == "final-answer"


def test_agent_preserves_conversation_history():
    """Agent should preserve conversation history across turns."""
    llm = FakeLLM()

    agent = ReverseEngineeringAgent(
        llm=llm,
        tools_spec=[],
        tool_map={},
    )

    # First turn
    answer1 = agent.run("first question")
    assert answer1 == "final-answer"

    # History should now have system + user + assistant
    assert len(agent.messages) == 3
    assert agent.messages[0]["role"] == "system"
    assert agent.messages[1]["role"] == "user"
    assert agent.messages[1]["content"] == "first question"
    assert agent.messages[2]["role"] == "assistant"
    assert agent.messages[2]["content"] == "final-answer"

    # Second turn
    llm.invocations = 0  # Reset for second question
    answer2 = agent.run("second question")

    # History should now have 5 messages (system + 2 Q&A pairs)
    assert len(agent.messages) == 5
    assert agent.messages[3]["role"] == "user"
    assert agent.messages[3]["content"] == "second question"
    assert agent.messages[4]["role"] == "assistant"


def test_agent_excludes_tool_calls_from_history():
    """Tool calls should not be persisted to conversation history."""
    llm = FakeLLM()

    def dummy_tool(**kwargs):
        return "tool result"

    agent = ReverseEngineeringAgent(
        llm=llm,
        tools_spec=[
            {
                "type": "function",
                "function": {
                    "name": "dummy_tool",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
        tool_map={"dummy_tool": dummy_tool},
    )

    # Run with tool call (FakeLLM calls tool on first invocation)
    answer = agent.run("question with tool use")
    assert answer == "final-answer"

    # History should only have system + user + final assistant answer
    # Tool calls and tool results should NOT be in persisted history
    assert len(agent.messages) == 3
    assert agent.messages[0]["role"] == "system"
    assert agent.messages[1]["role"] == "user"
    assert agent.messages[2]["role"] == "assistant"
    # No tool messages in history
    assert all(msg["role"] != "tool" for msg in agent.messages)
