"""Tests for SecretStr detector.
# tested-by: tests/unit/detectors/security/test_secret_str.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from eedom.detectors.security.secret_str import SecretStrDetector


class TestSecretStrDetector:
    """Tests for SecretStrDetector (EED-004)."""

    @pytest.fixture
    def detector(self):
        return SecretStrDetector()

    def test_detects_api_key_as_str(self, detector):
        """Detects api_key: str as a violation."""
        code = "api_key: str = 'secret123'"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-004"
        assert "api_key" in findings[0].message
        assert "SecretStr" in findings[0].message

    def test_ignores_api_key_as_secretstr(self, detector):
        """No finding when using SecretStr."""
        code = "api_key: SecretStr = 'secret123'"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_password_as_str(self, detector):
        """Detects password: str as a violation."""
        code = "password: str = 'hunter2'"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "password" in findings[0].message

    def test_detects_secret_token_as_str(self, detector):
        """Detects secret_token: str as a violation."""
        code = "secret_token: str = 'abc123'"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-004"

    def test_ignores_non_secret_names(self, detector):
        """No finding for non-secret field names."""
        code = """
name: str = "Alice"
age: int = 30
username: str = "alice123"
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_credential_as_str(self, detector):
        """Detects credential: str as a violation."""
        code = "credential: str = 'secret'"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "credential" in findings[0].message
