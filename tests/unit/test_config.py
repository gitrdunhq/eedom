"""Tests for eedom.core.config — configuration module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError


class TestAdmissionSettings:
    """Test suite for AdmissionSettings configuration loading."""

    @staticmethod
    def _minimal_env() -> dict[str, str]:
        """Return the minimum required env vars for a valid config."""
        return {
            "ADMISSION_DB_DSN": "postgresql://user:pass@localhost:5432/testdb",
        }

    @staticmethod
    def _full_env() -> dict[str, str]:
        """Return a complete env var set with all fields specified."""
        return {
            "ADMISSION_OPERATING_MODE": "advise",
            "ADMISSION_DB_DSN": "postgresql://user:pass@localhost:5432/testdb",
            "ADMISSION_EVIDENCE_PATH": "/tmp/evidence",
            "ADMISSION_SCANNER_TIMEOUT": "90",
            "ADMISSION_COMBINED_SCANNER_TIMEOUT": "200",
            "ADMISSION_OPA_TIMEOUT": "15",
            "ADMISSION_LLM_TIMEOUT": "45",
            "ADMISSION_PIPELINE_TIMEOUT": "400",
            "ADMISSION_OPA_POLICY_PATH": "/opt/policies",
            "ADMISSION_ENABLED_SCANNERS": "syft,trivy",
            "ADMISSION_LLM_ENABLED": "true",
            "ADMISSION_LLM_ENDPOINT": "https://llm.example.com/v1",
            "ADMISSION_LLM_MODEL": "gpt-4o",
            "ADMISSION_LLM_API_KEY": "sk-test-key",
            "ADMISSION_ALTERNATIVES_PATH": "/opt/alternatives.json",
        }

    def test_valid_config_loads_from_env(self) -> None:
        """Full env var set produces a correctly populated settings object."""
        from eedom.core.config import AdmissionSettings

        env = self._full_env()
        with patch.dict(os.environ, env, clear=True):
            settings = AdmissionSettings()

        assert settings.operating_mode.value == "advise"
        assert settings.db_dsn == "postgresql://user:pass@localhost:5432/testdb"
        assert settings.evidence_path == "/tmp/evidence"
        assert settings.scanner_timeout == 90
        assert settings.combined_scanner_timeout == 200
        assert settings.opa_timeout == 15
        assert settings.llm_timeout == 45
        assert settings.pipeline_timeout == 400
        assert settings.opa_policy_path == "/opt/policies"
        assert settings.enabled_scanners == ["syft", "trivy"]
        assert settings.llm_enabled is True
        assert settings.llm_endpoint == "https://llm.example.com/v1"
        assert settings.llm_model == "gpt-4o"
        assert settings.llm_api_key.get_secret_value() == "sk-test-key"
        assert settings.alternatives_path == "/opt/alternatives.json"

    def test_missing_db_dsn_raises_validation_error(self) -> None:
        """Config without DB_DSN must fail with a clear validation error."""
        from eedom.core.config import AdmissionSettings

        with patch.dict(os.environ, {}, clear=True), pytest.raises(ValidationError) as exc_info:
            AdmissionSettings()

        errors = exc_info.value.errors()
        field_names = [e["loc"][-1] for e in errors]
        assert "db_dsn" in field_names

    def test_invalid_operating_mode_raises_validation_error(self) -> None:
        """Operating mode must be restricted to 'monitor' and 'advise'."""
        from eedom.core.config import AdmissionSettings

        env = self._minimal_env()
        env["ADMISSION_OPERATING_MODE"] = "enforce"
        with patch.dict(os.environ, env, clear=True), pytest.raises(ValidationError) as exc_info:
            AdmissionSettings()

        errors = exc_info.value.errors()
        # The error should reference operating_mode
        field_names = [e["loc"][-1] for e in errors]
        assert "operating_mode" in field_names

    def test_default_values_are_correct(self) -> None:
        """When only required fields are provided, defaults match the architecture doc."""
        from eedom.core.config import AdmissionSettings

        env = self._minimal_env()
        with patch.dict(os.environ, env, clear=True):
            settings = AdmissionSettings()

        # Operating mode defaults to monitor
        assert settings.operating_mode.value == "monitor"

        # Timeout defaults per Section 14.3
        assert settings.scanner_timeout == 60
        assert settings.combined_scanner_timeout == 180
        assert settings.opa_timeout == 10
        assert settings.llm_timeout == 30
        assert settings.pipeline_timeout == 300

        # Path defaults
        assert settings.evidence_path == "./evidence"
        assert settings.opa_policy_path == "./policies"
        assert settings.alternatives_path == "./alternatives.json"

        # Scanner defaults
        assert settings.enabled_scanners == ["syft", "osv-scanner", "trivy", "scancode"]

        # LLM defaults
        assert settings.llm_enabled is False
        assert settings.llm_endpoint is None
        assert settings.llm_model is None
        assert settings.llm_api_key is None

    def test_minimal_config_loads_with_defaults(self) -> None:
        """Minimal config (just DB_DSN) loads successfully."""
        from eedom.core.config import AdmissionSettings

        env = self._minimal_env()
        with patch.dict(os.environ, env, clear=True):
            settings = AdmissionSettings()

        assert settings.db_dsn == "postgresql://user:pass@localhost:5432/testdb"

    def test_enabled_scanners_parsed_from_comma_separated(self) -> None:
        """Comma-separated scanner list is parsed into a Python list."""
        from eedom.core.config import AdmissionSettings

        env = self._minimal_env()
        env["ADMISSION_ENABLED_SCANNERS"] = "syft,trivy,osv-scanner"
        with patch.dict(os.environ, env, clear=True):
            settings = AdmissionSettings()

        assert settings.enabled_scanners == ["syft", "trivy", "osv-scanner"]

    def test_llm_api_key_is_secret_str(self) -> None:
        """F-021: llm_api_key must be a SecretStr, not a plain str."""
        from pydantic import SecretStr

        from eedom.core.config import AdmissionSettings

        env = self._minimal_env()
        env["ADMISSION_LLM_API_KEY"] = "sk-my-key"
        with patch.dict(os.environ, env, clear=True):
            settings = AdmissionSettings()

        assert isinstance(settings.llm_api_key, SecretStr)
        # repr/str must not expose the value
        assert "sk-my-key" not in repr(settings.llm_api_key)
        assert settings.llm_api_key.get_secret_value() == "sk-my-key"
