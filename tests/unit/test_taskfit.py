"""Tests for eedom.core.taskfit -- LLM task-fit advisory."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import httpx
import respx

from eedom.core.config import AdmissionSettings
from eedom.core.taskfit import TaskFitAdvisor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *,
    llm_enabled: bool = False,
    llm_endpoint: str | None = None,
    llm_model: str | None = None,
    llm_api_key: str | None = None,
    llm_timeout: int = 30,
) -> AdmissionSettings:
    """Build an AdmissionSettings with controlled LLM fields."""
    env = {
        "ADMISSION_DB_DSN": "postgresql://test:test@localhost/test",
        "ADMISSION_LLM_ENABLED": str(llm_enabled).lower(),
        "ADMISSION_LLM_TIMEOUT": str(llm_timeout),
    }
    if llm_endpoint:
        env["ADMISSION_LLM_ENDPOINT"] = llm_endpoint
    if llm_model:
        env["ADMISSION_LLM_MODEL"] = llm_model
    if llm_api_key:
        env["ADMISSION_LLM_API_KEY"] = llm_api_key

    with patch.dict(os.environ, env, clear=True):
        return AdmissionSettings()


SAMPLE_METADATA = {"summary": "A fast HTTP client library"}


class TestTaskFitAdvisorDisabled:
    """Tests for when LLM is disabled."""

    def test_disabled_returns_empty_string(self) -> None:
        """When llm_enabled is False, assess returns empty string immediately."""
        config = _make_config(llm_enabled=False)
        advisor = TaskFitAdvisor(config)

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=["requests"],
        )

        assert result == ""

    def test_missing_endpoint_returns_empty_string(self) -> None:
        """When endpoint is missing, returns empty string even if enabled."""
        config = _make_config(llm_enabled=True, llm_model="gpt-4o")
        advisor = TaskFitAdvisor(config)

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""


class TestTaskFitAdvisorEnabled:
    """Tests for when LLM is enabled and configured."""

    @respx.mock
    def test_successful_api_call_returns_advisory(self) -> None:
        """A successful LLM API call returns the advisory text."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_api_key="sk-test",
        )
        advisor = TaskFitAdvisor(config)

        advisory_text = (
            "NECESSITY:    PASS — No stdlib alternative for async HTTP.\n"
            "MINIMALITY:   PASS — Focused HTTP client.\n"
            "MAINTENANCE:  PASS — Active development.\n"
            "SECURITY:     PASS — Signed releases.\n"
            "EXPOSURE:     CONCERN — Processes untrusted HTTP input.\n"
            "BLAST_RADIUS: PASS — 5 transitive deps.\n"
            "ALTERNATIVES: CONCERN — requests and aiohttp exist.\n"
            "BEHAVIORAL:   PASS — No install scripts.\n\n"
            "RECOMMENDATION: APPROVE — Solid choice for async HTTP."
        )
        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": advisory_text}}]},
            )
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="async HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=["requests", "aiohttp"],
        )

        assert result == advisory_text
        assert "RECOMMENDATION: APPROVE" in result

    @respx.mock
    def test_timeout_returns_empty_string(self) -> None:
        """An LLM timeout returns empty string without raising."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
            llm_timeout=1,
        )
        advisor = TaskFitAdvisor(config)

        respx.post("https://llm.example.com/v1/chat/completions").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    @respx.mock
    def test_api_error_returns_empty_string(self) -> None:
        """A non-200 response from the LLM returns empty string."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    @respx.mock
    def test_invalid_response_rejected_returns_empty(self) -> None:
        """LLM response that fails validation is rejected after retries."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        invalid_text = "This package looks fine to me. I approve it."
        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": invalid_text}}]},
            )
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    @respx.mock
    def test_malformed_response_returns_empty_string(self) -> None:
        """A malformed JSON response from the LLM returns empty string."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": []})
        )

        result = advisor.assess(
            package_name="httpx",
            version="0.27.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=[],
        )

        assert result == ""

    # F-013 structured message tests

    @respx.mock
    def test_request_uses_system_and_user_roles(self) -> None:
        """F-013: LLM request must have a system message and a user message."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "looks good"}}]},
            )
        )

        advisor.assess(
            package_name="requests",
            version="2.31.0",
            use_case="HTTP calls",
            metadata=SAMPLE_METADATA,
            alternatives=["httpx"],
        )

        body = json.loads(route.calls.last.request.content)
        messages = body["messages"]
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"

    @respx.mock
    def test_user_message_is_json_encoded_data(self) -> None:
        """F-013: User message content must be JSON — not raw interpolated strings."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "advisory"}}]},
            )
        )

        advisor.assess(
            package_name="numpy",
            version="1.26.0",
            use_case="matrix math",
            metadata={"summary": "Numerical computing"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_content = body["messages"][1]["content"]
        # Content must be parseable as JSON
        parsed = json.loads(user_content)
        assert "package" in parsed
        assert "use_case" in parsed
        assert "summary" in parsed

    @respx.mock
    def test_pypi_summary_truncated_to_200_chars_in_request(self) -> None:
        """F-013: PyPI summary embedded in the prompt must not exceed 200 chars."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
            )
        )

        long_summary = "Z" * 500
        advisor.assess(
            package_name="pkg",
            version="1.0",
            use_case="test",
            metadata={"summary": long_summary},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_data = json.loads(body["messages"][1]["content"])
        assert len(user_data["summary"]) <= 200

    @respx.mock
    def test_html_stripped_from_summary(self) -> None:
        """F-013: HTML tags in PyPI summary must be stripped before sending."""
        config = _make_config(
            llm_enabled=True,
            llm_endpoint="https://llm.example.com/v1",
            llm_model="gpt-4o",
        )
        advisor = TaskFitAdvisor(config)

        route = respx.post("https://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
            )
        )

        advisor.assess(
            package_name="pkg",
            version="1.0",
            use_case="test",
            metadata={"summary": "<b>Fast</b> library"},
            alternatives=[],
        )

        body = json.loads(route.calls.last.request.content)
        user_data = json.loads(body["messages"][1]["content"])
        assert "<b>" not in user_data["summary"]
        assert "Fast" in user_data["summary"]
