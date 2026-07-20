"""
Unit tests for _apply_hermes_diff — the hunk-by-hunk diff re-applier that tolerates
Hermes' wrong @@ counts, truncated context, and markdown fences (REVIEW P1-10).
Run: pytest tests/test_diff_apply.py
"""
import pytest

from agents.response_agent import _apply_hermes_diff, _find_line_block

SOURCE = """\
#include <string.h>

void on_packet(char *buf) {
    char dest[64];
    strcpy(dest, buf);
    process(dest);
}
"""


def test_simple_single_hunk():
    diff = (
        "--- a/main/main.c\n"
        "+++ b/main/main.c\n"
        "@@ -4,3 +4,4 @@\n"
        "     char dest[64];\n"
        "-    strcpy(dest, buf);\n"
        "+    strlcpy(dest, buf, sizeof(dest));\n"
        "     process(dest);\n"
    )
    patched, proper = _apply_hermes_diff(SOURCE, diff, "main.c")
    assert "strlcpy(dest, buf, sizeof(dest));" in patched
    assert "strcpy(dest, buf);" not in patched
    assert proper.startswith("---")  # a real unified diff was regenerated


def test_wrong_at_counts_are_ignored():
    # @@ line numbers are deliberately nonsense — the applier must not trust them.
    diff = (
        "@@ -999,99 +12345,0 @@\n"
        "-    strcpy(dest, buf);\n"
        "+    strlcpy(dest, buf, sizeof(dest));\n"
    )
    patched, _ = _apply_hermes_diff(SOURCE, diff, "main.c")
    assert "strlcpy" in patched


def test_markdown_fenced_diff():
    diff = (
        "```diff\n"
        "@@ -5 +5 @@\n"
        "-    strcpy(dest, buf);\n"
        "+    strlcpy(dest, buf, sizeof(dest));\n"
        "```\n"
    )
    patched, _ = _apply_hermes_diff(SOURCE, diff, "main.c")
    assert "strlcpy" in patched


def test_trailing_whitespace_drift_tolerated():
    # The removed line carries trailing whitespace the source doesn't have.
    diff = (
        "@@ -5 +5 @@\n"
        "-    strcpy(dest, buf);   \n"
        "+    strlcpy(dest, buf, sizeof(dest));\n"
    )
    patched, _ = _apply_hermes_diff(SOURCE, diff, "main.c")
    assert "strlcpy" in patched


def test_multi_hunk():
    diff = (
        "@@ -1 +1,2 @@\n"
        " #include <string.h>\n"
        "+#include <stdio.h>\n"
        "@@ -5 +5 @@\n"
        "-    strcpy(dest, buf);\n"
        "+    strlcpy(dest, buf, sizeof(dest));\n"
    )
    patched, _ = _apply_hermes_diff(SOURCE, diff, "main.c")
    assert "#include <stdio.h>" in patched
    assert "strlcpy" in patched


def test_nonmatching_hunk_raises():
    diff = (
        "@@ -1 +1 @@\n"
        "-    this_line_is_not_in_the_source();\n"
        "+    replacement();\n"
    )
    with pytest.raises(ValueError):
        _apply_hermes_diff(SOURCE, diff, "main.c")


def test_no_hunks_raises():
    with pytest.raises(ValueError):
        _apply_hermes_diff(SOURCE, "just some prose, no hunks", "main.c")


def test_find_line_block_matches_whole_lines_only():
    hay = ["max = 1;", "x = 1;"]
    # 'x = 1;' must not match inside 'max = 1;'
    assert _find_line_block(hay, ["x = 1;"]) == 1
    assert _find_line_block(hay, ["= 1;"]) == -1
