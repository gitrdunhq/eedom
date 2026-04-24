"""Webhook server configuration.
# tested-by: tests/unit/test_webhook.py

Loaded from EEDOM_WEBHOOK_* environment variables:
    EEDOM_WEBHOOK_SECRET        — shared secret for HMAC-SHA256 signature validation
    EEDOM_WEBHOOK_GITHUB_TOKEN  — GitHub PAT for posting PR comments
    EEDOM_WEBHOOK_PORT          — port to listen on (default 12800)
"""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class WebhookSettings(BaseSettings):
    """Configuration for the eedom webhook HTTP server."""

    model_config = SettingsConfigDict(
        env_prefix="EEDOM_WEBHOOK_",
        case_sensitive=False,
    )

    secret: str
    github_token: SecretStr
    port: int = 12800
