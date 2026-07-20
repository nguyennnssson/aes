"""
AES — OpenAI connectivity smoke test.

Manual script (NOT a unit test — it opens a live client and needs a key).
Run after setting OPENAI_API_KEY:  python tests/test_openai.py

Verifies the reasoning model (HERMES_MODEL, default gpt-5) responds end-to-end.
"""

import os
from openai import OpenAI

client = OpenAI()  # reads OPENAI_API_KEY
MODEL = os.getenv("HERMES_MODEL", "gpt-5")
print(f"Using: OpenAI {MODEL}\n")


def ask(prompt: str) -> str:
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=256,
    )
    return resp.choices[0].message.content


response = ask(
    "You are the AES security system. An ESP32 camera just reported "
    "a CPU spike of 85% and a packet rate 10x above normal. "
    "In one sentence, what should happen next?"
)

print("AI response:")
print(response)
