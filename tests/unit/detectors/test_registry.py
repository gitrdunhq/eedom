"""Tests for detector registry.
# tested-by: tests/unit/detectors/test_registry.py

RED phase tests for Task 1.4: Detector Registry.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

# These imports will fail during RED phase
from eedom.detectors.registry import DetectorRegistry
from eedom.detectors.framework import BugDetector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.core.models import FindingSeverity


# =============================================================================
# Test Detector Classes
# =============================================================================


class TestSecurityDetector(BugDetector):
    """Test security detector for registry tests."""

    @property
    def detector_id(self) -> str:
        return "EED-TEST-001"

    @property
    def name(self) -> str:
        return "Test Security Detector"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        return []


class TestReliabilityDetector(BugDetector):
    """Test reliability detector for registry tests."""

    @property
    def detector_id(self) -> str:
        return "EED-TEST-002"

    @property
    def name(self) -> str:
        return "Test Reliability Detector"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        return []


# =============================================================================
# Registry Registration Tests
# =============================================================================


class TestDetectorRegistryRegistration:
    """Tests for detector registration."""

    def test_register_decorator_works(self):
        """@register decorator registers detector class."""

        @DetectorRegistry.register
        class DecoratedDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "EED-DEC-001"

            @property
            def name(self) -> str:
                return "Decorated Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        # Check it's registered
        assert "EED-DEC-001" in DetectorRegistry._detectors

    def test_explicit_register_method(self):
        """register() method registers detector class."""

        class ExplicitDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "EED-EXP-001"

            @property
            def name(self) -> str:
                return "Explicit Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        DetectorRegistry.register(ExplicitDetector)
        assert "EED-EXP-001" in DetectorRegistry._detectors

    def test_register_returns_class_for_decorator_use(self):
        """register returns the class for use as decorator."""

        @DetectorRegistry.register
        class TestDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "EED-RET-001"

            @property
            def name(self) -> str:
                return "Return Test Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        # Should still be able to instantiate the class
        instance = TestDetector()
        assert instance.detector_id == "EED-RET-001"


# =============================================================================
# Registry Discovery Tests
# =============================================================================


class TestDetectorRegistryDiscovery:
    """Tests for detector auto-discovery."""

    def test_discover_finds_all_detectors(self):
        """discover() finds all registered detector subclasses."""
        # First, manually register some detectors
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)
        DetectorRegistry.register(TestReliabilityDetector)

        # Call discover
        DetectorRegistry.discover()

        # Should have both detectors
        all_detectors = DetectorRegistry.get_all_detectors()
        detector_ids = {d.detector_id for d in all_detectors}
        assert "EED-TEST-001" in detector_ids
        assert "EED-TEST-002" in detector_ids

    def test_get_all_detectors_returns_instances(self):
        """get_all_detectors() returns detector instances."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)

        detectors = DetectorRegistry.get_all_detectors()
        assert len(detectors) == 1
        assert isinstance(detectors[0], TestSecurityDetector)

    def test_get_all_detectors_non_empty_after_registration(self):
        """get_all_detectors() returns non-empty list after registration."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)
        DetectorRegistry.discover()

        detectors = DetectorRegistry.get_all_detectors()
        assert len(detectors) > 0


# =============================================================================
# Registry Lookup Tests
# =============================================================================


class TestDetectorRegistryLookup:
    """Tests for detector lookup."""

    def test_get_detector_by_id(self):
        """get_detector() returns detector by ID."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)
        DetectorRegistry.discover()

        detector = DetectorRegistry.get_detector("EED-TEST-001")
        assert detector is not None
        assert detector.detector_id == "EED-TEST-001"

    def test_get_detector_returns_none_for_unknown_id(self):
        """get_detector() returns None for unknown detector ID."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        detector = DetectorRegistry.get_detector("EED-UNKNOWN")
        assert detector is None

    def test_get_by_category_filters_correctly(self):
        """get_by_category() returns only matching detectors."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)
        DetectorRegistry.register(TestReliabilityDetector)
        DetectorRegistry.discover()

        security_detectors = DetectorRegistry.get_by_category(DetectorCategory.security)
        assert len(security_detectors) == 1
        assert security_detectors[0].detector_id == "EED-TEST-001"

        reliability_detectors = DetectorRegistry.get_by_category(
            DetectorCategory.reliability
        )
        assert len(reliability_detectors) == 1
        assert reliability_detectors[0].detector_id == "EED-TEST-002"

    def test_get_by_severity_filters_correctly(self):
        """get_by_severity() returns only matching detectors."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)
        DetectorRegistry.register(TestReliabilityDetector)
        DetectorRegistry.discover()

        high_detectors = DetectorRegistry.get_by_severity(FindingSeverity.high)
        assert len(high_detectors) == 1
        assert high_detectors[0].detector_id == "EED-TEST-001"

        medium_detectors = DetectorRegistry.get_by_severity(FindingSeverity.medium)
        assert len(medium_detectors) == 1
        assert medium_detectors[0].detector_id == "EED-TEST-002"


# =============================================================================
# Registry Caching Tests
# =============================================================================


class TestDetectorRegistryCaching:
    """Tests for detector instance caching."""

    def test_caches_detector_instances(self):
        """Registry caches detector instances (stateless)."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        DetectorRegistry.register(TestSecurityDetector)
        DetectorRegistry.discover()

        # Get detector twice
        detector1 = DetectorRegistry.get_detector("EED-TEST-001")
        detector2 = DetectorRegistry.get_detector("EED-TEST-001")

        # Should be same instance (cached)
        assert detector1 is detector2


# =============================================================================
# Thread-Safety Tests (VAL-M1)
# =============================================================================


class TestDetectorRegistryThreadSafety:
    """Tests for registry thread-safety (VAL-M1).

    The registry must be thread-safe for parallel orchestrator execution.
    """

    def test_concurrent_registration_is_safe(self):
        """Concurrent registration operations are thread-safe."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        errors = []
        detectors_created = []

        def create_and_register(i):
            try:

                class DynamicDetector(BugDetector):
                    @property
                    def detector_id(self) -> str:
                        return f"EED-THREAD-{i:03d}"

                    @property
                    def name(self) -> str:
                        return f"Thread Detector {i}"

                    @property
                    def category(self) -> DetectorCategory:
                        return DetectorCategory.security

                    @property
                    def severity(self) -> FindingSeverity:
                        return FindingSeverity.high

                    def detect(self, file_path: Path) -> list[DetectorFinding]:
                        return []

                DetectorRegistry.register(DynamicDetector)
                detectors_created.append(i)
            except Exception as e:
                errors.append(e)

        # Spawn multiple threads registering detectors
        threads = []
        for i in range(10):
            t = threading.Thread(target=create_and_register, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0, f"Thread errors: {errors}"

        # All detectors should be registered
        DetectorRegistry.discover()
        all_detectors = DetectorRegistry.get_all_detectors()
        assert len(all_detectors) >= 10

    def test_concurrent_lookup_is_safe(self):
        """Concurrent lookup operations are thread-safe."""
        DetectorRegistry._detectors.clear()
        DetectorRegistry._instances.clear()

        # Pre-register some detectors
        for i in range(5):

            class PreRegisteredDetector(BugDetector):
                @property
                def detector_id(self) -> str:
                    return f"EED-PRE-{i:03d}"

                @property
                def name(self) -> str:
                    return f"Pre-registered {i}"

                @property
                def category(self) -> DetectorCategory:
                    return DetectorCategory.security

                @property
                def severity(self) -> FindingSeverity:
                    return FindingSeverity.high

                def detect(self, file_path: Path) -> list[DetectorFinding]:
                    return []

            DetectorRegistry.register(PreRegisteredDetector)

        DetectorRegistry.discover()

        errors = []
        results = []

        def lookup_detectors():
            try:
                for i in range(5):
                    d = DetectorRegistry.get_detector(f"EED-PRE-{i:03d}")
                    results.append(d is not None)
            except Exception as e:
                errors.append(e)

        # Spawn multiple threads doing lookups
        threads = []
        for _ in range(5):
            t = threading.Thread(target=lookup_detectors)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0, f"Lookup errors: {errors}"

        # All lookups should succeed
        assert all(results)


# =============================================================================
# Clear Registry Helper
# =============================================================================


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear registry before each test."""
    DetectorRegistry._detectors.clear()
    DetectorRegistry._instances.clear()
    yield
    DetectorRegistry._detectors.clear()
    DetectorRegistry._instances.clear()
