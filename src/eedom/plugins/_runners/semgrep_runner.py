"""Semgrep subprocess runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_PINNED_RULES_PATH = Path(__file__).resolve().parent.parent.parent.parent.parent / "semgrep-rules"

_EXT_TO_RULESETS: dict[str, list[str]] = {
    ".py": ["p/python"],
    ".ts": ["r/typescript.lang"],
    ".tsx": ["r/typescript.lang"],
    ".js": ["r/javascript.lang"],
    ".jsx": ["r/javascript.lang"],
    ".tf": ["p/terraform"],
    ".yaml": ["p/kubernetes", "p/docker"],
    ".yml": ["p/kubernetes", "p/docker"],
    ".go": ["p/golang"],
    ".rb": ["p/ruby"],
    ".java": ["p/java"],
    ".sh": ["r/bash.lang"],
}

_NAME_TO_RULESETS: dict[str, list[str]] = {
    "Dockerfile": ["p/docker"],
    "Jenkinsfile": ["p/ci"],
    "docker-compose.yml": ["p/docker"],
    "docker-compose.yaml": ["p/docker"],
}

_ALWAYS_RULESETS = ["p/default", "p/ci"]


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

    cmd = ["semgrep", *config_args, "--json", *changed_files]
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

        msg = error_msg(ErrorCode.NOT_INSTALLED, "semgrep")
        logger.warning("semgrep.not_installed", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except subprocess.TimeoutExpired:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.TIMEOUT, "semgrep", timeout=timeout)
        logger.warning("semgrep.timeout", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except json.JSONDecodeError:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.PARSE_ERROR, "semgrep")
        logger.warning("semgrep.parse_error", error=msg)
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
    except Exception:
        from eedom.core.errors import ErrorCode, error_msg

        msg = error_msg(ErrorCode.BINARY_CRASHED, "semgrep", exit_code=-1)
        logger.exception("semgrep.failed")
        return {"results": [], "errors": [{"message": msg}], "status": "error"}
