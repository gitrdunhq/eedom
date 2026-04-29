"""PR review posting — maps SARIF findings to inline GitHub PR review comments.
# tested-by: tests/unit/test_pr_review.py

Takes SARIF output + PR diff metadata from the GitHub API and posts a proper
PR review with inline comments on the right lines. Findings outside the diff
go in a collapsed section in the summary body.
"""

from __future__ import annotations

import json
import re
import subprocess
import textwrap
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def parse_hunk_ranges(patch: str) -> list[tuple[int, int]]:
    """Extract (start, end) line ranges from a unified diff patch string."""
    ranges: list[tuple[int, int]] = []
    for m in _HUNK_RE.finditer(patch):
        start = int(m.group(1))
        length = int(m.group(2)) if m.group(2) is not None else 1
        end = start + length - 1 if length > 0 else start
        ranges.append((start, end))
    return ranges


def line_in_hunks(line: int, hunks: list[tuple[int, int]]) -> bool:
    """Return True if line falls within any of the hunk ranges."""
    return any(start <= line <= end for start, end in hunks)


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


def _location_from_result(result: dict) -> tuple[str, int]:
    locations = result.get("locations", [])
    if not locations:
        return "", 1
    phys = locations[0].get("physicalLocation", {})
    file_path = phys.get("artifactLocation", {}).get("uri", "")
    line_num = phys.get("region", {}).get("startLine", 1)
    return file_path, line_num


def _target_text(file_path: str, line_num: int) -> str:
    return f"`{file_path}:{line_num}`" if file_path else "`repository`"


def _wrap_lines(text: str, width: int = 96) -> list[str]:
    return textwrap.wrap(
        str(text),
        width=width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]


def _labeled_lines(label: str, text: str) -> list[str]:
    return [f"{label}:"] + [f"  {line}" for line in _wrap_lines(text)]


def _bullet_lines(label: str, text: str) -> list[str]:
    return [f"- {label}:"] + [f"  {line}" for line in _wrap_lines(text)]


def _finding_noun(count: int) -> str:
    return "finding" if count == 1 else "findings"


def _count_phrase(count: int, noun: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {noun}{suffix}"


def _review_label(level: str) -> str:
    if level == "error":
        return "Required"
    if level == "warning":
        return "Consider"
    return "FYI"


def _why_text(rule_id: str, level: str, msg: str) -> str:
    rule_lower = rule_id.lower()
    msg_lower = msg.lower()
    if "secret" in rule_lower or "secret" in msg_lower or "key" in rule_lower:
        return "Exposed credentials can be reused outside this PR until removed and rotated."
    if "sql" in rule_lower or "sql" in msg_lower:
        return "Concatenated input can let request data change the SQL query structure."
    if "dependency" in rule_lower or "cve" in rule_lower:
        return "A vulnerable dependency can ship exploitable code with the application."
    if level == "error":
        return "Dom marks this required because eedom reported an error-level finding in this PR."
    if level == "warning":
        return "This is non-blocking guidance; addressing it now can reduce follow-up review churn."
    return "This is informational context for future cleanup."


def _fix_text(rule_id: str, msg: str, result: dict) -> str:
    fixes = result.get("fixes", [])
    if fixes:
        fix_text = fixes[0].get("description", {}).get("text", "")
        if fix_text:
            return fix_text

    rule_lower = rule_id.lower()
    msg_lower = msg.lower()
    if "secret" in rule_lower or "secret" in msg_lower or "key" in rule_lower:
        return (
            "Remove the secret from the diff, rotate the exposed credential, "
            "and load it from secrets management."
        )
    if "sql" in rule_lower or "sql" in msg_lower:
        return "Parameterize the query or use a safe query builder; do not concatenate input."
    if "dependency" in rule_lower or "cve" in rule_lower:
        return "Upgrade, replace, or pin the affected dependency to a safe release."
    return (
        "Simplify the flagged code/config where possible, or make the intent explicit, "
        "then change it so the rule no longer matches."
    )


def _build_smart_comment(rule_id: str, level: str, msg: str, result: dict) -> str:
    """Build an inline comment with concrete fix, pass condition, and verification."""
    icon = {"error": "🔴", "warning": "🟡", "note": "🔵"}.get(level, "⚪")
    file_path, line_num = _location_from_result(result)
    target = _target_text(file_path, line_num)
    fix_text = _fix_text(rule_id, msg, result)
    label = _review_label(level)
    parts = [f"{icon} **{label}:** `{rule_id}` (`{level}`)"]
    parts.append("")
    parts.extend(_labeled_lines("What failed", msg))
    why_label = "Why it blocks" if label == "Required" else "Why it matters"
    parts.extend(_labeled_lines(why_label, _why_text(rule_id, level, msg)))
    parts.extend(_labeled_lines("Fix", fix_text))
    parts.extend(_labeled_lines("Done when", f"`{rule_id}` is absent on the next eedom run."))
    parts.extend(_labeled_lines("Where", target))
    parts.extend(_labeled_lines("Verify", "`uv run eedom review --repo-path . --all`"))

    return "\n".join(parts)


def _build_body_smart_plan(blockers: list[dict]) -> list[str]:
    if not blockers:
        return []

    lines = [
        "",
        "### Blocking Fix Plan",
        "",
        f"> Why blocked: {len(blockers)} error-level {_finding_noun(len(blockers))} "
        "must be fixed before merge.",
        "",
    ]
    for blocker in blockers[:5]:
        target = _target_text(blocker["file"], blocker["line"])
        lines.append(f"**Required:** `{blocker['rule']}` — {target}")
        lines.extend(_bullet_lines("What failed", blocker["message"]))
        lines.extend(
            _bullet_lines(
                "Why it blocks",
                _why_text(blocker["rule"], blocker["level"], blocker["message"]),
            )
        )
        lines.extend(
            _bullet_lines(
                "Fix",
                _fix_text(blocker["rule"], blocker["message"], blocker["raw"]),
            )
        )
        lines.extend(
            _bullet_lines(
                "Done when",
                f"This `{blocker['level']}` finding is absent from the next run.",
            )
        )
        lines.extend(
            _bullet_lines(
                "Verify",
                "Fix this location and verify with `uv run eedom review --repo-path . --all`.",
            )
        )
        lines.append("")
    if len(blockers) > 5:
        lines.append(f"*...{len(blockers) - 5} more blocker(s) omitted from this summary.*")
    return lines


def sarif_to_review(
    sarif: dict,
    diff_files: set[str],
    diff_hunks: dict[str, list[tuple[int, int]]] | None = None,
) -> PRReview:
    """Convert SARIF findings into a PRReview with inline comments.

    Findings on files in the PR diff become inline comments, but only when
    the finding's line falls within an actual diff hunk (when diff_hunks is
    provided). Findings outside hunks or outside the diff go in the summary.
    """
    comments: list[ReviewComment] = []
    outside: list[dict] = []
    blockers: list[dict] = []
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
            file_path, line_num = _location_from_result(result)

            comment_body = _build_smart_comment(rule_id, level, msg, result)

            if level == "error":
                blockers.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "rule": rule_id,
                        "level": level,
                        "message": msg,
                        "raw": result,
                    }
                )

            in_diff = file_path and file_path in diff_files
            in_hunk = True
            if in_diff and diff_hunks and file_path in diff_hunks:
                in_hunk = line_in_hunks(line_num, diff_hunks[file_path])

            if in_diff and in_hunk:
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
        verdict = f"🚫 **{error_count} blocking {_finding_noun(error_count)}** found"
    elif warning_count > 0:
        event = "COMMENT"
        verdict = f"⚠️ **{_count_phrase(warning_count, 'warning')}** found, no blockers"
    else:
        event = "COMMENT"
        verdict = "✅ No findings"

    body_lines = [
        f"## Eagle Eyed Dom — {verdict}",
        "",
        f"**{total}** {_finding_noun(total)}: {_count_phrase(error_count, 'error')}, "
        f"{_count_phrase(warning_count, 'warning')}, "
        f"{_count_phrase(total - error_count - warning_count, 'note')}",
        f"**{len(comments)}** inline, **{len(outside)}** outside diff",
    ]

    body_lines.extend(_build_body_smart_plan(blockers))

    if outside:
        body_lines.append("")
        body_lines.append("<details>")
        body_lines.append(
            f"<summary>{len(outside)} {_finding_noun(len(outside))} outside the PR diff</summary>"
        )
        body_lines.append("")
        body_lines.append("| File | Line | Rule | Level | Message |")
        body_lines.append("|------|------|------|-------|---------|")
        for f in outside:
            msg_short = f["message"][:80].replace("\n", " ").replace("\r", "").replace("|", "\\|")
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
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        logger.warning("pr_review.detect_repo_git_not_found")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("pr_review.detect_repo_timeout")
        return None
    if result.returncode != 0:
        return None
    url = result.stdout.strip()
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", url)
    return m.group(1) if m else None


def get_pr_diff_files(repo: str, pr_number: int) -> set[str]:
    """Fetch the list of files changed in a PR via gh CLI."""
    try:
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
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("pr_review.get_diff_files_failed", error=str(e))
        return set()
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"Failed to fetch PR diff files for {repo}#{pr_number}: {stderr[:200]}")
    return {f.strip() for f in result.stdout.strip().split("\n") if f.strip()}


def get_pr_diff_hunks(repo: str, pr_number: int) -> dict[str, list[tuple[int, int]]]:
    """Fetch per-file hunk ranges from a PR via gh CLI.

    Returns {filename: [(start, end), ...]} for each file with a patch.
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repo}/pulls/{pr_number}/files",
                "--paginate",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("pr_review.get_diff_hunks_failed", error=str(e))
        return {}
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"Failed to fetch PR diff hunks for {repo}#{pr_number}: {stderr[:200]}")

    hunks: dict[str, list[tuple[int, int]]] = {}
    try:
        entries = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        logger.warning("pr_review.invalid_json_response", stdout=result.stdout[:200])
        return {}
    for file_entry in entries:
        filename = file_entry.get("filename", "")
        patch = file_entry.get("patch", "")
        if filename and patch:
            ranges = parse_hunk_ranges(patch)
            if ranges:
                hunks[filename] = ranges
    return hunks


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

    try:
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
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("pr_review.post_failed_exception", error=str(e))
        return False

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
