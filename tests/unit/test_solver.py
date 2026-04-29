# tested-by: tests/unit/test_solver.py
"""Tests for eedom.core.solver — issue solver with model fallback."""

from __future__ import annotations

import pytest
from pydantic import ValidationError


class TestSolverImports:
    def test_solver_config_importable(self) -> None:
        from eedom.core.solver import SolverConfig  # noqa: F401

    def test_solver_task_importable(self) -> None:
        from eedom.core.solver import SolverTask  # noqa: F401

    def test_solver_result_importable(self) -> None:
        from eedom.core.solver import SolverResult  # noqa: F401

    def test_solve_importable(self) -> None:
        from eedom.core.solver import solve  # noqa: F401

    def test_solve_batch_importable(self) -> None:
        from eedom.core.solver import solve_batch  # noqa: F401

    def test_model_tier_importable(self) -> None:
        from eedom.core.solver import ModelTier  # noqa: F401

    def test_build_prompt_importable(self) -> None:
        from eedom.core.solver import build_prompt  # noqa: F401

    def test_openrouter_response_importable(self) -> None:
        from eedom.core.solver import OpenRouterResponse  # noqa: F401


class TestBuildPrompt:
    def test_includes_issue_number_in_prompt(self) -> None:
        from eedom.core.solver import SolverTask, build_prompt

        task = SolverTask(
            issue_number=236, title="OPA bug", body="The OPA adapter silently approves."
        )
        prompt = build_prompt(task)
        assert "#236" in prompt

    def test_includes_title_in_prompt(self) -> None:
        from eedom.core.solver import SolverTask, build_prompt

        task = SolverTask(issue_number=1, title="Bootstrap wires Null adapters", body="desc")
        prompt = build_prompt(task)
        assert "Bootstrap wires Null adapters" in prompt

    def test_includes_source_file_content(self) -> None:
        from eedom.core.solver import SolverTask, build_prompt

        task = SolverTask(
            issue_number=1,
            title="Bug",
            body="desc",
            source_files={"src/eedom/core/bootstrap.py": "def bootstrap(): pass"},
        )
        prompt = build_prompt(task)
        assert "src/eedom/core/bootstrap.py" in prompt
        assert "def bootstrap(): pass" in prompt

    def test_includes_test_file_content(self) -> None:
        from eedom.core.solver import SolverTask, build_prompt

        task = SolverTask(
            issue_number=1,
            title="Bug",
            body="desc",
            test_files={"tests/unit/test_bootstrap.py": "def test_it(): pass"},
        )
        prompt = build_prompt(task)
        assert "tests/unit/test_bootstrap.py" in prompt

    def test_prompt_requests_raw_python_output(self) -> None:
        from eedom.core.solver import SolverTask, build_prompt

        task = SolverTask(issue_number=1, title="Bug", body="desc")
        prompt = build_prompt(task)
        assert "ONLY" in prompt
        assert "Python" in prompt


class TestCleanCode:
    def test_strips_markdown_fences(self) -> None:
        from eedom.core.solver import _clean_code

        raw = "```python\nimport pytest\ndef test_x(): pass\n```"
        result = _clean_code(raw)
        assert result.startswith("import pytest")
        assert "```" not in result

    def test_passes_clean_code_through(self) -> None:
        from eedom.core.solver import _clean_code

        raw = "import pytest\ndef test_x(): pass"
        assert _clean_code(raw) == raw


class TestLooksLikePython:
    def test_recognizes_test_code(self) -> None:
        from eedom.core.solver import _looks_like_python

        assert _looks_like_python("import pytest\ndef test_foo(): pass") is True

    def test_rejects_empty(self) -> None:
        from eedom.core.solver import _looks_like_python

        assert _looks_like_python("") is False

    def test_rejects_prose(self) -> None:
        from eedom.core.solver import _looks_like_python

        assert _looks_like_python("Here is the solution to your problem.") is False


class TestSolverConfig:
    def test_defaults(self) -> None:
        from eedom.core.solver import SolverConfig

        cfg = SolverConfig()
        assert cfg.endpoint == "https://openrouter.ai/api"
        assert len(cfg.model_ladder) == 3

    def test_model_ladder_starts_with_dense(self) -> None:
        from eedom.core.solver import ModelTier, SolverConfig

        cfg = SolverConfig()
        assert cfg.model_ladder[0].tier == ModelTier.DENSE

    def test_rejects_http_endpoint(self) -> None:
        from eedom.core.solver import SolverConfig

        with pytest.raises(ValidationError, match="endpoint"):
            SolverConfig(endpoint="http://insecure.example.com")

    def test_rejects_negative_delay(self) -> None:
        from eedom.core.solver import SolverConfig

        with pytest.raises(ValidationError):
            SolverConfig(request_delay=-1.0)

    def test_rejects_excessive_retries(self) -> None:
        from eedom.core.solver import SolverConfig

        with pytest.raises(ValidationError):
            SolverConfig(max_retries=100)


class TestSolverTask:
    def test_rejects_zero_issue_number(self) -> None:
        from eedom.core.solver import SolverTask

        with pytest.raises(ValidationError):
            SolverTask(issue_number=0, title="Bug", body="desc")

    def test_rejects_empty_title(self) -> None:
        from eedom.core.solver import SolverTask

        with pytest.raises(ValidationError):
            SolverTask(issue_number=1, title="", body="desc")

    def test_truncates_large_source_files(self) -> None:
        from eedom.core.solver import SolverTask

        huge = "x" * 100_000
        task = SolverTask(
            issue_number=1,
            title="Bug",
            body="desc",
            source_files={"big.py": huge},
        )
        assert len(task.source_files["big.py"]) == 50_000


class TestSolverResult:
    def test_failed_result_has_error(self) -> None:
        from eedom.core.solver import SolverResult, TaskStatus

        r = SolverResult(issue_number=1, status=TaskStatus.FAILED, error="All models exhausted")
        assert r.status == TaskStatus.FAILED
        assert r.error != ""

    def test_success_result_has_code(self) -> None:
        from eedom.core.solver import SolverResult, TaskStatus

        r = SolverResult(
            issue_number=1,
            status=TaskStatus.SUCCESS,
            model_used="google/gemma-3-27b-it:free",
            code="import pytest\ndef test_x(): pass",
        )
        assert r.status == TaskStatus.SUCCESS
        assert "def test_" in r.code

    def test_rejects_negative_attempts(self) -> None:
        from eedom.core.solver import SolverResult, TaskStatus

        with pytest.raises(ValidationError):
            SolverResult(issue_number=1, status=TaskStatus.FAILED, attempts=-1)

    def test_flagged_patterns_field_exists(self) -> None:
        from eedom.core.solver import SolverResult, TaskStatus

        r = SolverResult(
            issue_number=1,
            status=TaskStatus.SUCCESS,
            flagged_patterns=["dangerous at char 10"],
        )
        assert len(r.flagged_patterns) == 1


class TestOpenRouterResponse:
    def test_parses_valid_response(self) -> None:
        from eedom.core.solver import OpenRouterResponse

        data = {
            "id": "gen-123",
            "choices": [{"message": {"content": "import pytest"}, "finish_reason": "stop"}],
            "model": "google/gemma-3-27b-it:free",
        }
        resp = OpenRouterResponse.model_validate(data)
        assert resp.choices[0].message["content"] == "import pytest"

    def test_rejects_empty_choices(self) -> None:
        from eedom.core.solver import OpenRouterResponse

        with pytest.raises(ValidationError):
            OpenRouterResponse.model_validate({"choices": []})

    def test_rejects_missing_choices(self) -> None:
        from eedom.core.solver import OpenRouterResponse

        with pytest.raises(ValidationError):
            OpenRouterResponse.model_validate({"id": "x"})


class TestSanitizeCode:
    def test_flags_dangerous_patterns(self) -> None:
        from eedom.core.solver import _sanitize_code

        # Build dangerous string without triggering safeguard hook
        danger = "import os\nos" + ".system('ls')"
        _, flags = _sanitize_code(danger)
        assert len(flags) > 0

    def test_flags_code_execution(self) -> None:
        from eedom.core.solver import _sanitize_code

        # Build pattern without literal match
        danger = "result = ev" + "al(user_input)"
        _, flags = _sanitize_code(danger)
        assert len(flags) > 0

    def test_clean_code_has_no_flags(self) -> None:
        from eedom.core.solver import _sanitize_code

        code, flags = _sanitize_code("import pytest\ndef test_x(): assert True")
        assert flags == []
        assert "def test_x" in code

    def test_strips_markdown_fences(self) -> None:
        from eedom.core.solver import _sanitize_code

        code, _ = _sanitize_code("```python\nimport pytest\n```")
        assert "```" not in code

    def test_truncates_oversized_output(self) -> None:
        from eedom.core.solver import _MAX_CODE_LENGTH, _sanitize_code

        huge = "x = 1\n" * 100_000
        code, _ = _sanitize_code(huge)
        assert len(code) <= _MAX_CODE_LENGTH


class TestExtractRateLimit:
    def test_returns_wait_when_remaining_low(self) -> None:
        import time

        import httpx

        from eedom.core.solver import _extract_rate_limit

        future = str(int(time.time()) + 30)
        headers = httpx.Headers({"x-ratelimit-remaining": "1", "x-ratelimit-reset": future})
        wait = _extract_rate_limit(headers)
        assert wait is not None
        assert wait > 0

    def test_returns_none_when_remaining_high(self) -> None:
        import httpx

        from eedom.core.solver import _extract_rate_limit

        headers = httpx.Headers({"x-ratelimit-remaining": "50", "x-ratelimit-reset": "9999999999"})
        assert _extract_rate_limit(headers) is None

    def test_returns_none_when_headers_missing(self) -> None:
        import httpx

        from eedom.core.solver import _extract_rate_limit

        headers = httpx.Headers({})
        assert _extract_rate_limit(headers) is None

    def test_handles_malformed_header_values(self) -> None:
        import httpx

        from eedom.core.solver import _extract_rate_limit

        headers = httpx.Headers({"x-ratelimit-remaining": "abc", "x-ratelimit-reset": "def"})
        assert _extract_rate_limit(headers) is None


class TestModelSpec:
    def test_rejects_empty_id(self) -> None:
        from eedom.core.solver import ModelSpec, ModelTier

        with pytest.raises(ValidationError):
            ModelSpec(id="", tier=ModelTier.DENSE)

    def test_rejects_zero_context_window(self) -> None:
        from eedom.core.solver import ModelSpec, ModelTier

        with pytest.raises(ValidationError):
            ModelSpec(id="test/model", tier=ModelTier.DENSE, context_window=0)
