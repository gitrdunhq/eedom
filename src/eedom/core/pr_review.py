"""PR review posting — maps SARIF findings to inline GitHub PR review comments.
# tested-by: tests/unit/test_pr_review.py

Takes SARIF output + PR diff metadata from the GitHub API and posts a proper
PR review with inline comments on the right lines. Findings outside the diff
go in a collapsed section in the summary body.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ReviewComment:
    path: str
    line: int
    body: str
    side: str = "RIGHT"


@dataclass
class PRReview:
    body: str
    event: str
    comments: list[ReviewComment] = field(default_factory=list)
    outside_diff: list[dict] = field(default_factory=list)


def sarif_to_review(sarif: dict, diff_files: set[str]) -> PRReview:
    """Convert SARIF findings into a PRReview with inline comments.

    Findings on files in the PR diff become inline comments.
    Findings on files outside the diff go in the summary body.
    """
    comments: list[ReviewComment] = []
    outside: list[dict] = []
    error_count = 0
    warning_count = 0
    total = 0

    for run in sarif.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        for result in run.get("results", []):
            total += 1
            level = result.get("level", "note")
            if level == "error":
                error_count += 1
            elif level == "warning":
                warning_count += 1

            msg = result.get("message", {}).get("text", "")
            rule_id = result.get("ruleId", tool_name)
            locations = result.get("locations", [])

            file_path = ""
            line_num = 1
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                line_num = phys.get("region", {}).get("startLine", 1)

            icon = {"error": "🔴", "warning": "🟡", "note": "🔵"}.get(level, "⚪")
            comment_body = f"{icon} **{rule_id}** ({level})\n\n{msg}"

            if file_path and file_path in diff_files:
                comments.append(
                    ReviewComment(
                        path=file_path,
                        line=line_num,
                        body=comment_body,
                    )
                )
            elif file_path:
                outside.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "rule": rule_id,
                        "level": level,
                        "message": msg,
                    }
                )

    if error_count > 0:
        event = "REQUEST_CHANGES"
        verdict = f"🚫 **{error_count} blocking finding(s)** found"
    elif warning_count > 0:
        event = "COMMENT"
        verdict = f"⚠️ **{warning_count} warning(s)** found, no blockers"
    else:
        event = "COMMENT"
        verdict = "✅ No findings"

    body_lines = [
        f"## Eagle Eyed Dom — {verdict}",
        "",
        f"**{total}** findings: {error_count} error, "
        f"{warning_count} warning, {total - error_count - warning_count} note",
        f"**{len(comments)}** inline, **{len(outside)}** outside diff",
    ]

    if outside:
        body_lines.append("")
        body_lines.append("<details>")
        body_lines.append(f"<summary>{len(outside)} finding(s) outside the PR diff</summary>")
        body_lines.append("")
        body_lines.append("| File | Line | Rule | Level | Message |")
        body_lines.append("|------|------|------|-------|---------|")
        for f in outside:
            msg_short = f["message"][:80].replace("|", "\\|")
            body_lines.append(
                f"| `{f['file']}` | {f['line']} | {f['rule']} | {f['level']} | {msg_short} |"
            )
        body_lines.append("")
        body_lines.append("</details>")

    return PRReview(
        body="\n".join(body_lines),
        event=event,
        comments=comments,
        outside_diff=outside,
    )


def detect_gh_repo() -> str | None:
    """Auto-detect GitHub owner/repo from git remote."""
    import re

    result = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        return None
    url = result.stdout.strip()
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", url)
    return m.group(1) if m else None


def get_pr_diff_files(repo: str, pr_number: int) -> set[str]:
    """Fetch the list of files changed in a PR via gh CLI."""
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{repo}/pulls/{pr_number}/files",
            "--jq",
            ".[].filename",
            "--paginate",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        logger.warning("pr_review.diff_files_failed", stderr=result.stderr[:200])
        return set()
    return {f.strip() for f in result.stdout.strip().split("\n") if f.strip()}


def post_review(repo: str, pr_number: int, review: PRReview) -> bool:
    """Post a PR review with inline comments via gh CLI."""
    payload: dict = {
        "event": review.event,
        "body": review.body,
    }

    if review.comments:
        payload["comments"] = [
            {
                "path": c.path,
                "line": c.line,
                "side": c.side,
                "body": c.body,
            }
            for c in review.comments
        ]

    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{repo}/pulls/{pr_number}/reviews",
            "--method",
            "POST",
            "--input",
            "-",
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        logger.warning(
            "pr_review.post_failed",
            status=result.returncode,
            stderr=result.stderr[:200],
        )
        return False

    logger.info(
        "pr_review.posted",
        pr=pr_number,
        event=review.event,
        inline_comments=len(review.comments),
        outside_diff=len(review.outside_diff),
    )
    return True
