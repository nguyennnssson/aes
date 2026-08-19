"""Unit tests for the OpenAI Responses API compatibility wrapper."""

from types import SimpleNamespace

import pytest

from agents.llm_client import LLMBackendError, _OpenAIMessages


class _FakeResponses:
    def __init__(self, output_text="ok"):
        self.output_text = output_text
        self.request = None

    def create(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(output_text=self.output_text)


def test_openai_wrapper_uses_responses_api_and_preserves_roles():
    responses = _FakeResponses("  accepted  ")
    client = SimpleNamespace(responses=responses)
    wrapper = _OpenAIMessages(client, "gpt-5.6-sol")

    result = wrapper.create(
        system="trusted policy",
        messages=[{"role": "user", "content": "analyze"}],
        max_tokens=10,
        timeout=12,
    )

    assert result.content[0].text == "accepted"
    assert responses.request == {
        "model": "gpt-5.6-sol",
        "input": [{"role": "user", "content": "analyze"}],
        "max_output_tokens": 256,
        "timeout": 12,
        "instructions": "trusted policy",
    }


def test_openai_wrapper_honors_per_call_model_and_rejects_empty_output():
    responses = _FakeResponses("")
    wrapper = _OpenAIMessages(SimpleNamespace(responses=responses), "default")

    with pytest.raises(LLMBackendError, match="empty output"):
        wrapper.create(model="patch-model", messages=[], max_tokens=1024)

    assert responses.request["model"] == "patch-model"
    assert responses.request["max_output_tokens"] == 1024
