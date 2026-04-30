"""Tests for Cache Eviction detector.
# tested-by: tests/unit/detectors/reliability/test_cache_eviction.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from eedom.detectors.reliability.cache_eviction import CacheEvictionDetector


class TestCacheEvictionDetector:
    """Tests for CacheEvictionDetector (EED-006)."""

    @pytest.fixture
    def detector(self):
        return CacheEvictionDetector()

    def test_detects_bare_cache_decorator(self, detector):
        """Detects @cache without maxsize."""
        code = """
from functools import cache

@cache
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-006"
        assert "without maxsize" in findings[0].message

    def test_detects_lru_cache_without_maxsize(self, detector):
        """Detects @lru_cache() without maxsize argument."""
        code = """
from functools import lru_cache

@lru_cache()
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_lru_cache_with_maxsize(self, detector):
        """No finding when maxsize is specified."""
        code = """
from functools import lru_cache

@lru_cache(maxsize=128)
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_multiple_unbounded_caches(self, detector):
        """Detects multiple unbounded cache decorators."""
        code = """
from functools import cache, lru_cache

@cache
def get_users():
    return fetch_users()

@lru_cache()
def get_items():
    return fetch_items()
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 2
