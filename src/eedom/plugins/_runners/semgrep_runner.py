"""Opengrep subprocess runner (semgrep-compatible, local rules only)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_PINNED_RULES_PATH = Path(__file__).resolve().parent.parent.parent.parent.parent / "semgrep-rules"

_EXT_TO_RULESETS: dict[str, list[str]] = {}

_NAME_TO_RULESETS: dict[str, list[str]] = {}

_ALWAYS_RULESETS: list[str] = []


def detect_rulesets(changed_files: list[str]) -> list[str]:
    rulesets = list(_ALWAYS_RULESETS)
    for f in changed_files:
        ext = Path(f).suffix
        if ext in _EXT_TO_RULESETS:
            for rs in _EXT_TO_RULESETS[ext]:
                if rs not in rulesets:
                    rulesets.append(rs)
        name = Path(f).name
        if name in _NAME_TO_RULESETS:
            for rs in _NAME_TO_RULESETS[name]:
                if rs not in rulesets:
                    rulesets.append(rs)
    return rulesets


def _resolve_ruleset(rs: str) -> str:
    if not _PINNED_RULES_PATH.exists():
        return rs
    if rs.startswith("r/"):
        local = _PINNED_RULES_PATH / rs[2:].replace(".", "/")
        if local.exists():
            return str(local)
    return rs


def run_semgrep(
    changed_files: list[str],
    repo_path: str,
    timeout: int = 120,
) -> dict:
    if not changed_files:
        return {"results": [], "errors": []}

    rulesets = detect_rulesets(changed_files)
    org_rules = Path(repo_path) / "policies" / "semgrep"

    config_args: list[str] = []
    for rs in rulesets:
        config_args.extend(["--config", _resolve_ruleset(rs)])
    if org_rules.is_dir():
        config_args.extend(["--config", str(org_rules)])

    cmd = ["opengrep", *config_args, "--json", *changed_files]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_path,
            check=False,
        )
        if result.stdout:
            return json.loads(result.stdout)
        return {
            "results": [],
            "errors": [{"message": "no output", "level": "warn"}],
            "status": "degraded",
        }
    except FileNotFoundError:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.NOT_INSTALLED, "opengrep")
        logger.warning("semgrep.not_installed", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except subprocess.TimeoutExpired:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.TIMEOUT, "opengrep", timeout=timeout)
        logger.warning("semgrep.timeout", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except json.JSONDecodeError:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.PARSE_ERROR, "opengrep")
        logger.warning("semgrep.parse_error", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except Exception:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.BINARY_CRASHED, "opengrep", exit_code=-1)
        logger.exception("semgrep.failed")
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
