"""Send one short live prompt through every configured model backend.

Usage (from the repository root, with .env loaded or variables exported):
    python scripts/check_backends.py

Prints, for each backend in the reasoning and code chains, whether it answered
and how long it took. Exit code 0 only if every configured backend answered.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass

from agents.llm_client import is_backend_error, make_hermes_client  # noqa: E402

PROMPT = [{"role": "user", "content": "Reply with exactly one word: pong"}]


def main() -> int:
    seen, failures = set(), 0
    for role in ("reasoning", "code"):
        chain = make_hermes_client(role=role)
        print(f"\n{role} chain: {chain.model}")
        for backend in chain.backends:
            key = (backend.name, backend.model)
            if key in seen:
                continue
            seen.add(key)
            start = time.perf_counter()
            try:
                reply = backend.messages.create(messages=PROMPT, max_tokens=16, timeout=60)
                text = reply.content[0].text.strip()
                print(f"  OK    {backend.name}:{backend.model}  {time.perf_counter() - start:.1f}s  -> {text[:40]!r}")
            except Exception as exc:
                if not is_backend_error(exc):
                    raise
                failures += 1
                print(f"  FAIL  {backend.name}:{backend.model}  {exc}")
    if not seen:
        print("\nNo backend is configured; Hermes would use the offline Llama 3 fallback.")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
