"""PMD CPD subprocess runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_CPD_LANGUAGES: dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "ecmascript",
    ".jsx": "ecmascript",
    ".py": "python",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".kt": "kotlin",
    ".swift": "swift",
    ".rs": "rust",
    ".css": "css",
    ".html": "html",
    ".xml": "xml",
}


def run_cpd(
    changed_files: list[str],
    repo_path: str,
    min_tokens: int = 75,
    timeout: int = 60,
) -> dict:
    if not changed_files:
        return {"duplicates": [], "files_scanned": 0}

    by_lang: dict[str, list[str]] = {}
    for f in changed_files:
        lang = _CPD_LANGUAGES.get(Path(f).suffix)
        if lang:
            by_lang.setdefault(lang, []).append(f)

    if not by_lang:
        return {"duplicates": [], "files_scanned": 0}

    all_dupes: list[dict] = []
    total_scanned = 0

    for lang, files in by_lang.items():
        cmd = [
            "pmd",
            "cpd",
            "--minimum-tokens",
            str(min_tokens),
            "--language",
            lang,
            "--format",
            "json",
            "--dir",
            repo_path,
            "--non-recursive",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for dup in data.get("duplications", []):
                    locs = []
                    for loc in dup.get("files", []):
                        locs.append(
                            {
                                "file": loc.get("id", ""),
                                "start_line": loc.get("beginLine", 0),
                                "end_line": loc.get("endLine", 0),
                            }
                        )
                    if len(locs) >= 2:
                        all_dupes.append(
                            {
                                "tokens": dup.get("tokens", 0),
                                "lines": dup.get("lines", 0),
                                "language": lang,
                                "locations": locs,
                                "fragment": dup.get("codefragment", "")[:200],
                            }
                        )
            total_scanned += len(files)
        except FileNotFoundError:
            from eedom.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.NOT_INSTALLED, "pmd")
            logger.warning("cpd.not_installed", error=msg)
            return {"duplicates": [], "files_scanned": 0, "error": msg}
        except subprocess.TimeoutExpired:
            from eedom.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.TIMEOUT, "pmd", timeout=timeout)
            logger.warning("cpd.timeout", error=msg)
            return {"duplicates": [], "files_scanned": 0, "error": msg}
        except Exception:
            from eedom.core.errors import ErrorCode, error_msg

            msg = error_msg(ErrorCode.BINARY_CRASHED, "pmd", exit_code=-1)
            logger.exception("cpd.failed")
            return {"duplicates": [], "files_scanned": 0, "error": msg}

    all_dupes.sort(key=lambda d: d["tokens"], reverse=True)
    return {
        "duplicates": all_dupes,
        "files_scanned": total_scanned,
        "duplicate_count": len(all_dupes),
    }
