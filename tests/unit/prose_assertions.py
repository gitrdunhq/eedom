"""Shared assertions for generated review prose."""

from __future__ import annotations

import re

FORBIDDEN_PROSE = (
    "Specific:",
    "Measurable:",
    "Actionable:",
    "Relevant:",
    "Targeted:",
    "finding(s)",
    "warning(s)",
    "you forgot",
    "bad code",
    "obviously",
)

EMPTY_PLACEHOLDERS = (
    r"\(\s*\)",
    r"`\s*`",
    r"\bNone\b",
    r"\bnull\b",
    r"\bundefined\b",
    r"\bTBD\b",
    r"\bN/A\b",
)


def assert_professional_review_prose(text: str) -> None:
    for forbidden in FORBIDDEN_PROSE:
        assert forbidden not in text


def assert_no_empty_placeholders(text: str) -> None:
    for pattern in EMPTY_PLACEHOLDERS:
        assert re.search(pattern, text) is None, pattern


def assert_scannable(text: str, max_width: int = 110) -> None:
    assert "\n\n\n" not in text
    long_lines = [
        (line_no, line)
        for line_no, line in enumerate(text.splitlines(), start=1)
        if len(line) > max_width
    ]
    assert long_lines == []


def assert_field_has_content(text: str, label: str) -> None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != f"{label}:":
            continue
        following = lines[index + 1 : index + 4]
        assert any(candidate.strip() for candidate in following)
        return
    raise AssertionError(f"missing field: {label}")


def assert_review_prose_contract(text: str) -> None:
    assert_professional_review_prose(text)
    assert_no_empty_placeholders(text)
    assert_scannable(text)
