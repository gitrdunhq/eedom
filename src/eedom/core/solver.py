# tested-by: tests/unit/test_solver.py
"""Issue solver — generates detector tests via LLM with model fallback.

API-style module for automated issue resolution. Reads GitHub issue context,
builds scoped prompts, sends to OpenRouter-compatible endpoints with rate-limit
aware sequential processing and model fallback ladder.

All boundary contracts use Pydantic models. LLM output is untrusted input
and is validated + sanitized before use.

Public interface:
  - SolverConfig     — model ladder, rate limits, endpoint
  - SolverTask       — structured task from a GitHub issue
  - SolverResult     — result from model (code + metadata)
  - solve()          — process a single task
  - solve_batch()    — process multiple tasks sequentially with rate limiting
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

import httpx
import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger()

_MAX_CODE_LENGTH = 50_000
_MAX_FILE_SIZE = 50_000
_MAX_PROMPT_LENGTH = 200_000
_DANGEROUS_PATTERNS = re.compile(
    r"os\.system\(|subprocess\.call\(.*shell=True" r"|__import__\(|exec\(|eval\("
)


class ModelTier(StrEnum):
    DENSE = "dense"
    MOE = "moe"
    MOE_LARGE = "moe_large"


class ModelSpec(BaseModel):
    id: str = Field(min_length=1)
    tier: ModelTier
    context_window: int = Field(default=32_000, gt=0)
    max_output: int = Field(default=8_000, gt=0)


DEFAULT_MODEL_LADDER: list[ModelSpec] = [
    ModelSpec(
        id="google/gemma-3-27b-it:free",
        tier=ModelTier.DENSE,
        context_window=96_000,
    ),
    ModelSpec(
        id="qwen/qwen3-235b-a22b:free",
        tier=ModelTier.MOE,
        context_window=40_000,
    ),
    ModelSpec(
        id="mistralai/devstral-small:free",
        tier=ModelTier.MOE_LARGE,
        context_window=128_000,
    ),
]


class SolverConfig(BaseModel):
    endpoint: str = Field(default="https://openrouter.ai/api", pattern=r"^https://")
    api_key: str = ""
    model_ladder: list[ModelSpec] = Field(default_factory=lambda: list(DEFAULT_MODEL_LADDER))
    output_dir: str = ".temp/solver-results"
    request_delay: float = Field(default=2.0, ge=0.0)
    max_retries: int = Field(default=3, ge=1, le=10)
    timeout: int = Field(default=120, ge=5, le=600)


class TaskStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"


class SolverTask(BaseModel):
    issue_number: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=500)
    body: str = Field(max_length=200_000)
    group: str = ""
    source_files: dict[str, str] = Field(default_factory=dict)
    test_files: dict[str, str] = Field(default_factory=dict)

    @field_validator("source_files", "test_files")
    @classmethod
    def truncate_large_files(cls, v: dict[str, str]) -> dict[str, str]:
        return {k: content[:_MAX_FILE_SIZE] for k, content in v.items()}


class SolverResult(BaseModel):
    issue_number: int = Field(gt=0)
    status: TaskStatus
    model_used: str = ""
    code: str = Field(default="", max_length=_MAX_CODE_LENGTH)
    error: str = ""
    attempts: int = Field(default=0, ge=0)
    duration_s: float = Field(default=0.0, ge=0.0)
    flagged_patterns: list[str] = Field(default_factory=list)


class OpenRouterRequest(BaseModel):
    model: str = Field(min_length=1)
    max_tokens: int = Field(gt=0)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    messages: list[dict[str, str]]


class OpenRouterChoice(BaseModel):
    message: dict[str, str]
    finish_reason: str | None = None


class OpenRouterResponse(BaseModel):
    id: str = ""
    choices: list[OpenRouterChoice] = Field(min_length=1)
    model: str = ""
    usage: dict[str, int] | None = None


_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

SYSTEM_PROMPT = """\
You are a senior test engineer writing deterministic detection tests for known \
bugs in a Python codebase called eedom (Eagle Eyed Dom — a CI code review tool).

Your output is ONLY raw Python code. No markdown, no code fences, no explanation.
Start with imports. End with the last test function.

Conventions you MUST follow:
- pytest as the test framework
- structlog for logging (never print)
- Typed annotations on all functions
- One test class per detection rule, named Test{BugDescription}
- Each test must FAIL on the current buggy code (RED phase)
- Use unittest.mock for isolation, never hit real APIs or filesystem
- Descriptive test names: test_{what}_{condition}_{expected}
- Add a module docstring: "Detector test for issue #{number}"
"""


def build_prompt(task: SolverTask) -> str:
    sections = [f"# Issue #{task.issue_number}: {task.title}\n\n{task.body}"]

    if task.source_files:
        sections.append("# Source Files Under Test")
        for path, content in task.source_files.items():
            sections.append(f"\n## {path}\n```python\n{content}\n```")

    if task.test_files:
        sections.append("# Existing Tests (match these conventions)")
        for path, content in task.test_files.items():
            truncated = "\n".join(content.split("\n")[:80])
            sections.append(f"\n## {path}\n```python\n{truncated}\n```")

    sections.append(
        "# Task\n\n"
        f"Write a pytest test module that detects the bug in issue "
        f"#{task.issue_number}.\n\n"
        "Requirements:\n"
        "1. The test MUST fail on the current codebase (RED phase)\n"
        "2. The test verifies the specific behavior described in the bug\n"
        "3. Use mock/patch to isolate from external dependencies\n"
        "4. Match the test conventions shown in existing tests above\n"
        "5. Include: # tested-by: tests/unit/test_detector_{issue}.py\n\n"
        "Output ONLY the Python code. No markdown, no explanation."
    )

    prompt = "\n\n".join(sections)
    if len(prompt) > _MAX_PROMPT_LENGTH:
        prompt = prompt[:_MAX_PROMPT_LENGTH]
        logger.warning(
            "solver.prompt_truncated",
            issue=task.issue_number,
            length=_MAX_PROMPT_LENGTH,
        )
    return prompt


def _extract_rate_limit(headers: httpx.Headers) -> float | None:
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is None or reset is None:
        return None
    try:
        if int(remaining) < 2:
            wait = max(0, int(reset) - int(time.time()))
            return float(wait + 1)
    except ValueError:
        return None
    return None


def _sanitize_code(raw: str) -> tuple[str, list[str]]:
    code = _clean_code(raw)
    if len(code) > _MAX_CODE_LENGTH:
        code = code[:_MAX_CODE_LENGTH]

    flags: list[str] = []
    for match in _DANGEROUS_PATTERNS.finditer(code):
        flags.append(f"dangerous pattern at char {match.start()}: {match.group()}")

    return code, flags


def _post(
    client: httpx.Client,
    url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    timeout: int,
) -> tuple[str, dict]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/gitrdunhq/eedom",
        "X-Title": "eedom-solver",
    }
    request = OpenRouterRequest(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    resp = client.post(
        url,
        json=request.model_dump(),
        headers=headers,
        timeout=timeout,
    )
    return resp.text, {
        "status": resp.status_code,
        "headers": dict(resp.headers),
    }


def _parse_response(raw: str) -> OpenRouterResponse:
    import orjson

    data = orjson.loads(raw)
    return OpenRouterResponse.model_validate(data)


def solve(task: SolverTask, config: SolverConfig) -> SolverResult:
    """Solve a single task, trying each model in the ladder."""
    start = time.monotonic()
    prompt = build_prompt(task)
    url = f"{config.endpoint}/v1/chat/completions"
    attempts = 0

    with httpx.Client() as client:
        for model_spec in config.model_ladder:
            for retry in range(config.max_retries):
                attempts += 1
                try:
                    raw, meta = _post(
                        client=client,
                        url=url,
                        api_key=config.api_key,
                        model=model_spec.id,
                        system=SYSTEM_PROMPT,
                        user=prompt,
                        max_tokens=model_spec.max_output,
                        timeout=config.timeout,
                    )
                except (httpx.TimeoutException, httpx.HTTPError) as exc:
                    logger.warning(
                        "solver.request_error",
                        issue=task.issue_number,
                        model=model_spec.id,
                        error=str(exc),
                        attempt=attempts,
                    )
                    time.sleep(2.0**retry)
                    continue

                status_code = meta["status"]

                if status_code == 429:
                    wait = _extract_rate_limit(httpx.Headers(meta["headers"])) or (2.0**retry * 5)
                    logger.warning(
                        "solver.rate_limited",
                        issue=task.issue_number,
                        model=model_spec.id,
                        wait_s=wait,
                    )
                    time.sleep(wait)
                    continue

                if status_code in _RETRYABLE_STATUS:
                    logger.warning(
                        "solver.retryable",
                        issue=task.issue_number,
                        model=model_spec.id,
                        status=status_code,
                        attempt=attempts,
                    )
                    time.sleep(2.0**retry)
                    continue

                if status_code != 200:
                    logger.warning(
                        "solver.api_error",
                        issue=task.issue_number,
                        model=model_spec.id,
                        status=status_code,
                        body=raw[:200],
                    )
                    break

                try:
                    response = _parse_response(raw)
                    raw_code = response.choices[0].message.get("content", "")
                except Exception as exc:
                    logger.warning(
                        "solver.parse_error",
                        issue=task.issue_number,
                        model=model_spec.id,
                        error=str(exc),
                    )
                    break

                code, flags = _sanitize_code(raw_code)
                if not _looks_like_python(code):
                    logger.warning(
                        "solver.invalid_output",
                        issue=task.issue_number,
                        model=model_spec.id,
                        preview=code[:100],
                    )
                    break

                if flags:
                    logger.warning(
                        "solver.dangerous_patterns",
                        issue=task.issue_number,
                        model=model_spec.id,
                        flags=flags,
                    )

                duration = time.monotonic() - start
                logger.info(
                    "solver.success",
                    issue=task.issue_number,
                    model=model_spec.id,
                    code_lines=code.count("\n") + 1,
                    duration_s=round(duration, 1),
                    flagged=len(flags),
                )
                return SolverResult(
                    issue_number=task.issue_number,
                    status=TaskStatus.SUCCESS,
                    model_used=model_spec.id,
                    code=code,
                    attempts=attempts,
                    duration_s=round(duration, 1),
                    flagged_patterns=flags,
                )

    duration = time.monotonic() - start
    return SolverResult(
        issue_number=task.issue_number,
        status=TaskStatus.FAILED,
        error="All models exhausted",
        attempts=attempts,
        duration_s=round(duration, 1),
    )


def solve_batch(
    tasks: list[SolverTask],
    config: SolverConfig,
    on_result: Callable[[SolverResult], None] | None = None,
) -> list[SolverResult]:
    """Process tasks sequentially with rate-limit pacing.

    Calls on_result(result) after each task if provided (webhook hook).
    """
    results: list[SolverResult] = []
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for i, task in enumerate(tasks):
        logger.info(
            "solver.batch_progress",
            current=i + 1,
            total=len(tasks),
            issue=task.issue_number,
        )

        result = solve(task, config)
        results.append(result)

        if result.status == TaskStatus.SUCCESS:
            out_path = out_dir / f"test_detector_{task.issue_number}.py"
            out_path.write_text(result.code)
            logger.info("solver.wrote_file", path=str(out_path))

        if on_result is not None:
            on_result(result)

        if i < len(tasks) - 1:
            time.sleep(config.request_delay)

    succeeded = sum(1 for r in results if r.status == TaskStatus.SUCCESS)
    failed = sum(1 for r in results if r.status == TaskStatus.FAILED)
    logger.info(
        "solver.batch_complete",
        succeeded=succeeded,
        failed=failed,
        total=len(tasks),
    )

    return results


def _clean_code(raw: str) -> str:
    lines = raw.strip().split("\n")
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _looks_like_python(code: str) -> bool:
    if not code:
        return False
    indicators = ["import ", "def test_", "class Test", "from ", "assert "]
    return any(indicator in code for indicator in indicators)
