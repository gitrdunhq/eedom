"""Tests for webhook HTTP server.
# tested-by: tests/unit/test_webhook.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytest.importorskip("starlette", reason="starlette not installed (eedom[copilot])")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(body: bytes, secret: str) -> str:
    """Compute the HMAC-SHA256 signature GitHub sends."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _pr_body(action: str = "opened") -> bytes:
    """Minimal pull_request webhook payload."""
    payload = {
        "action": action,
        "pull_request": {
            "number": 42,
            "html_url": "https://github.com/org/repo/pull/42",
            "head": {"sha": "abc123def456"},
        },
        "repository": {
            "full_name": "org/repo",
            "clone_url": "https://github.com/org/repo.git",
        },
    }
    return json.dumps(payload).encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def secret() -> str:
    return "webhook-test-secret-xyz789"


@pytest.fixture
def settings(secret: str):
    from eedom.webhook.config import WebhookSettings

    return WebhookSettings(
        secret=secret,
        github_token="ghp_test_token_abc123",
        port=12800,
    )


@pytest.fixture
def app(settings):
    from eedom.core.bootstrap import bootstrap_test
    from eedom.webhook.server import build_app

    return build_app(settings, context=bootstrap_test())


@pytest.fixture
async def client(app) -> httpx.AsyncClient:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Shared patch context for tests that trigger a full PR processing path
# ---------------------------------------------------------------------------


def _quiet_processing_mocks():
    """Returns a context manager tuple that silences review + GH API calls."""
    mock_review_result = MagicMock(
        results=[], verdict="clear", security_score=100.0, quality_score=100.0
    )
    return (
        patch("eedom.webhook.server.review_repository", return_value=mock_review_result),
        patch("eedom.webhook.server._post_pr_comment", new_callable=AsyncMock),
    )


# ---------------------------------------------------------------------------
# 1. Signature validation — valid HMAC passes
# ---------------------------------------------------------------------------


class TestSignatureValidation:
    async def test_valid_hmac_signature_accepted(self, client, secret):
        body = _pr_body()
        sig = _sign(body, secret)

        mock_result = MagicMock(stdout="ok", stderr="", returncode=0)
        with (
            patch("eedom.webhook.server.subprocess.run", return_value=mock_result),
            patch("eedom.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 200

    # 2. Signature validation — invalid HMAC returns 401
    async def test_invalid_hmac_signature_returns_401(self, client):
        body = _pr_body()
        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": "sha256=deadbeefdeadbeefdeadbeef",
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 401

    # 3. Signature validation — missing header returns 401
    async def test_missing_signature_header_returns_401(self, client):
        body = _pr_body()
        resp = await client.post(
            "/webhook",
            content=body,
            headers={
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4 & 5. Event parsing
# ---------------------------------------------------------------------------


class TestEventParsing:
    # 4. pull_request.opened triggers review_repository and comment
    async def test_pull_request_opened_triggers_review(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        mock_review_result = MagicMock(
            results=[], verdict="clear", security_score=100.0, quality_score=100.0
        )
        with (
            patch(
                "eedom.webhook.server.review_repository", return_value=mock_review_result
            ) as mock_review,
            patch("eedom.webhook.server._post_pr_comment", new_callable=AsyncMock) as mock_comment,
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_review.assert_called_once()
        mock_comment.assert_awaited_once()

    async def test_pull_request_synchronize_triggers_review(self, client, secret):
        body = _pr_body("synchronize")
        sig = _sign(body, secret)

        mock_review_result = MagicMock(
            results=[], verdict="clear", security_score=100.0, quality_score=100.0
        )
        with (
            patch(
                "eedom.webhook.server.review_repository", return_value=mock_review_result
            ) as mock_review,
            patch("eedom.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_review.assert_called_once()

    # 5. Non-pull_request event returns 200 and does NOT trigger review
    async def test_non_pull_request_event_ignored(self, client, secret):
        body = json.dumps({"ref": "refs/heads/main", "commits": []}).encode()
        sig = _sign(body, secret)

        with patch("eedom.webhook.server.subprocess.run") as mock_run:
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "push",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_run.assert_not_called()

    async def test_pull_request_closed_action_ignored(self, client, secret):
        body = _pr_body("closed")
        sig = _sign(body, secret)

        with patch("eedom.webhook.server.subprocess.run") as mock_run:
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# 6. Fail-open — subprocess failure still returns 200
# ---------------------------------------------------------------------------


class TestFailOpen:
    async def test_subprocess_timeout_still_returns_200(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        with (
            patch(
                "eedom.webhook.server.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="eedom", timeout=300),
            ),
            patch("eedom.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200

    async def test_subprocess_oserror_still_returns_200(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        with (
            patch(
                "eedom.webhook.server.subprocess.run",
                side_effect=OSError("eedom binary not found"),
            ),
            patch("eedom.webhook.server._post_pr_comment", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200

    async def test_github_api_failure_still_returns_200(self, client, secret):
        body = _pr_body("opened")
        sig = _sign(body, secret)

        mock_result = MagicMock(stdout="review output", stderr="", returncode=0)
        with (
            patch("eedom.webhook.server.subprocess.run", return_value=mock_result),
            patch(
                "eedom.webhook.server._post_pr_comment",
                new_callable=AsyncMock,
                side_effect=httpx.HTTPStatusError(
                    "403 Forbidden",
                    request=MagicMock(),
                    response=MagicMock(status_code=403),
                ),
            ),
        ):
            resp = await client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 7. Config loads from env vars
# ---------------------------------------------------------------------------


class TestConfig:
    def test_config_loads_from_env_vars(self, monkeypatch):
        monkeypatch.setenv("EEDOM_WEBHOOK_SECRET", "env-secret-value")
        monkeypatch.setenv("EEDOM_WEBHOOK_GITHUB_TOKEN", "ghp_env_token_xyz")
        monkeypatch.setenv("EEDOM_WEBHOOK_PORT", "12900")

        from eedom.webhook.config import WebhookSettings

        settings = WebhookSettings()  # type: ignore[call-arg]

        assert settings.secret == "env-secret-value"
        assert settings.github_token.get_secret_value() == "ghp_env_token_xyz"
        assert settings.port == 12900

    def test_config_port_defaults_to_12800(self, monkeypatch):
        monkeypatch.setenv("EEDOM_WEBHOOK_SECRET", "s")
        monkeypatch.setenv("EEDOM_WEBHOOK_GITHUB_TOKEN", "t")

        from eedom.webhook.config import WebhookSettings

        settings = WebhookSettings()  # type: ignore[call-arg]
        assert settings.port == 12800
