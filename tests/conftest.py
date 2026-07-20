"""Pytest configuration for the AES unit suite.

test_openai.py is a manual API smoke SCRIPT (it opens a live OpenAI client at
import and needs an API key), not a unit test — exclude it from collection so
`pytest tests/` stays hermetic and offline.
"""

collect_ignore = ["test_openai.py"]
