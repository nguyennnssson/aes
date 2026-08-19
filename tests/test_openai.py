"""
AES — OpenAI connectivity smoke test.

Manual script (NOT a unit test — it opens a live client and needs a key).
Run after setting OPENAI_API_KEY:  python tests/test_openai.py

Verifies the reasoning model (HERMES_MODEL, default gpt-5.6-sol) responds end-to-end.
"""

import os
from openai import OpenAI

client = OpenAI()  # reads OPENAI_API_KEY
MODEL = os.getenv("HERMES_MODEL", "gpt-5.6-sol")
print(f"Using: OpenAI {MODEL}\n")


def ask(prompt: str) -> str:
    resp = client.responses.create(
        model=MODEL,
        input=prompt,
        max_output_tokens=256,
    )
    return resp.output_text


response = ask(
    "You are the AES security system. An ESP32 camera just reported "
    "a CPU spike of 85% and a packet rate 10x above normal. "
    "In one sentence, what should happen next?"
)

print("AI response:")
print(response)
