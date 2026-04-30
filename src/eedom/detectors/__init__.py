"""Bug detector framework for eedom.
# tested-by: tests/unit/detectors/test_framework.py

Provides the BugDetector base class and supporting infrastructure for
AST-based static analysis of code to detect bugs across security,
reliability, configuration, and process domains.
"""
from __future__ import annotations

from eedom.detectors.framework import BugDetector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding

__all__ = [
    "BugDetector",
    "DetectorCategory",
    "DetectorFinding",
]
