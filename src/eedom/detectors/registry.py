"""Detector registry for auto-discovery and management.
# tested-by: tests/unit/detectors/test_registry.py

Provides auto-discovery, registration, and lookup of bug detectors
with thread-safe operations for parallel orchestrator execution (VAL-M1).
"""

from __future__ import annotations

import importlib
import pkgutil
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:

    from eedom.core.models import FindingSeverity
    from eedom.detectors.categories import DetectorCategory


class _DetectorRegistryMeta(type):
    """Metaclass to ensure thread-safe singleton behavior."""

    _lock: threading.Lock = threading.Lock()

    def __new__(mcs, name, bases, namespace):
        # Add lock if not present
        if "_lock" not in namespace:
            namespace["_lock"] = threading.Lock()
        return super().__new__(mcs, name, bases, namespace)


class DetectorRegistry(metaclass=_DetectorRegistryMeta):
    """Registry for auto-discovery and management of bug detectors.

    This registry provides:
    - Manual registration via @register decorator
    - Auto-discovery via discover()
    - Thread-safe operations for parallel execution
    - Instance caching (detectors are stateless)

    Thread Safety:
        All methods use a shared lock to ensure thread-safety when
        accessed from multiple threads (e.g., ScanOrchestrator's
        ThreadPoolExecutor).

    Example:
        @DetectorRegistry.register
        class MyDetector(BugDetector):
            ...

        # Discovery (usually called once at startup)
        DetectorRegistry.discover()

        # Get all detectors
        all_detectors = DetectorRegistry.get_all_detectors()

        # Filter by category
        security_detectors = DetectorRegistry.get_by_category(
            DetectorCategory.security
        )
    """

    _detectors: dict[str, type] = {}
    _instances: dict[str, BugDetector] = {}
    _lock: threading.Lock = threading.Lock()
    _discovered: bool = False

    @classmethod
    def register(cls, detector_class: type) -> type:
        """Register a detector class (can be used as decorator).

        Args:
            detector_class: BugDetector subclass to register

        Returns:
            The detector class (for use as decorator)
        """
        with cls._lock:
            # Get detector_id from the class (without instantiating)
            # We need to create a temporary instance to get the ID
            try:
                # Try to get detector_id from class property
                detector_id = detector_class.detector_id.fget(None)  # type: ignore
            except (AttributeError, TypeError):
                # Fallback: create temp instance to get ID
                try:
                    temp = detector_class()
                    detector_id = temp.detector_id
                except Exception:
                    # If can't instantiate, use class name
                    detector_id = detector_class.__name__

            cls._detectors[detector_id] = detector_class

            # Clear instance cache for this detector (in case of re-registration)
            if detector_id in cls._instances:
                del cls._instances[detector_id]

        return detector_class

    @classmethod
    def discover(cls, package_name: str = "eedom.detectors", _is_root: bool = True) -> None:
        """Auto-discover all detectors in registered packages.

        This imports all submodules to trigger class definitions and
        @register decorators, then caches detector instances.

        Args:
            package_name: Package to discover detectors in
            _is_root: Internal flag to track root call vs recursive calls
        """
        with cls._lock:
            if _is_root and cls._discovered:
                return

        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return

        # Import all submodules to trigger registration
        for _, name, is_pkg in pkgutil.iter_modules(
            package.__path__, package_name + "."  # type: ignore
        ):
            try:
                importlib.import_module(name)
            except ImportError:
                continue

            # If it's a package, recursively discover (not root)
            if is_pkg:
                cls.discover(name, _is_root=False)

        with cls._lock:
            if _is_root:
                cls._discovered = True

    @classmethod
    def get_detector(cls, detector_id: str) -> BugDetector | None:
        """Get detector instance by ID.

        Args:
            detector_id: Detector identifier (e.g., 'EED-001')

        Returns:
            Detector instance or None if not found
        """
        with cls._lock:
            # Check cache first
            if detector_id in cls._instances:
                return cls._instances[detector_id]

            # Create instance
            detector_class = cls._detectors.get(detector_id)
            if detector_class is None:
                return None

            try:
                instance = detector_class()
                cls._instances[detector_id] = instance
                return instance
            except Exception:
                return None

    @classmethod
    def get_all_detectors(cls) -> list[BugDetector]:
        """Get all registered detector instances.

        Returns:
            List of all detector instances
        """
        with cls._lock:
            instances = []
            for detector_id in cls._detectors:
                # Check cache
                if detector_id in cls._instances:
                    instances.append(cls._instances[detector_id])
                else:
                    # Create and cache
                    detector_class = cls._detectors[detector_id]
                    try:
                        instance = detector_class()
                        cls._instances[detector_id] = instance
                        instances.append(instance)
                    except Exception:
                        continue
            return instances

    @classmethod
    def get_by_category(cls, category: DetectorCategory) -> list[BugDetector]:
        """Get detectors filtered by category.

        Args:
            category: DetectorCategory to filter by

        Returns:
            List of detectors in the specified category
        """
        all_detectors = cls.get_all_detectors()
        return [d for d in all_detectors if d.category == category]

    @classmethod
    def get_by_severity(cls, severity: FindingSeverity) -> list[BugDetector]:
        """Get detectors filtered by severity.

        Args:
            severity: FindingSeverity to filter by

        Returns:
            List of detectors with the specified severity
        """
        all_detectors = cls.get_all_detectors()
        return [d for d in all_detectors if d.severity == severity]

    @classmethod
    def clear(cls) -> None:
        """Clear all registered detectors (mainly for testing).

        This clears both the class registry and instance cache.
        """
        with cls._lock:
            cls._detectors.clear()
            cls._instances.clear()
            cls._discovered = False


# Import BugDetector for type hints
from eedom.detectors.framework import BugDetector  # noqa: E402
