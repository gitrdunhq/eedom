"""Tests for PR review posting — SARIF to inline GitHub review comments.
# tested-by: tests/unit/test_pr_review.py
"""

from __future__ import annotations

from eedom.core.pr_review import sarif_to_review


def _sarif(results: list[dict], tool: str = "test-tool") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool}},
                "results": results,
            }
        ],
    }


def _finding(
    file: str = "src/app.py",
    line: int = 10,
    level: str = "error",
    rule: str = "test-rule",
    msg: str = "test finding",
) -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line},
                }
            }
        ],
    }


class TestSarifToReview:
    def test_empty_sarif_produces_comment_no_findings(self):
        review = sarif_to_review(_sarif([]), diff_files=set())
        assert review.event == "COMMENT"
        assert "No findings" in review.body
        assert review.comments == []

    def test_error_finding_in_diff_becomes_inline_comment(self):
        sarif = _sarif([_finding(file="src/app.py", line=42, level="error")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "REQUEST_CHANGES"
        assert len(review.comments) == 1
        assert review.comments[0].path == "src/app.py"
        assert review.comments[0].line == 42
        assert "test-rule" in review.comments[0].body

    def test_finding_outside_diff_goes_to_summary(self):
        sarif = _sarif([_finding(file="src/other.py", level="warning")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "COMMENT"
        assert len(review.comments) == 0
        assert len(review.outside_diff) == 1
        assert "src/other.py" in review.body

    def test_mixed_findings_request_changes_on_errors(self):
        sarif = _sarif(
            [
                _finding(file="src/app.py", level="error"),
                _finding(file="src/app.py", line=20, level="warning", rule="warn-rule"),
                _finding(file="src/other.py", level="note", rule="note-rule"),
            ]
        )
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "REQUEST_CHANGES"
        assert len(review.comments) == 2
        assert len(review.outside_diff) == 1
        assert "3" in review.body

    def test_warnings_only_uses_comment_event(self):
        sarif = _sarif([_finding(file="src/app.py", level="warning")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "COMMENT"
        assert "warning" in review.body.lower()

    def test_summary_counts_are_correct(self):
        sarif = _sarif(
            [
                _finding(level="error", rule="r1"),
                _finding(level="error", rule="r2", line=20),
                _finding(level="warning", rule="r3", line=30),
                _finding(level="note", rule="r4", file="other.py"),
            ]
        )
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert "2 error" in review.body
        assert "1 warning" in review.body
        assert "4" in review.body

    def test_no_locations_skips_inline(self):
        sarif = _sarif(
            [
                {
                    "ruleId": "no-loc",
                    "level": "warning",
                    "message": {"text": "no location"},
                    "locations": [],
                }
            ]
        )
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert len(review.comments) == 0
        assert review.event == "COMMENT"
