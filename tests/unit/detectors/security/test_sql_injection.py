"""Tests for SQL Injection detector.
# tested-by: tests/unit/detectors/security/test_sql_injection.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from eedom.detectors.security.sql_injection import SQLInjectionDetector


class TestSQLInjectionDetector:
    """Tests for SQLInjectionDetector (EED-005)."""

    @pytest.fixture
    def detector(self):
        return SQLInjectionDetector()

    def test_detects_fstring_in_execute(self, detector):
        """Detects f-string in SQL execute."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
user_id = "123"
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-005"
        assert "f-string" in findings[0].message

    def test_detects_percent_formatting_in_execute(self, detector):
        """Detects % formatting in SQL execute."""
        code = """
import psycopg2

conn = psycopg2.connect(dsn)
cursor = conn.cursor()
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "% formatting" in findings[0].message

    def test_detects_dot_format_in_execute(self, detector):
        """Detects .format() in SQL execute."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
table_name = "users"
cursor.execute("SELECT * FROM {}".format(table_name))
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_parameterized_query(self, detector):
        """No finding for parameterized queries."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_string_literal(self, detector):
        """No finding for string literal queries."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE active = 1")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_executemany_violation(self, detector):
        """Detects formatting in executemany."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
table = "logs"
cursor.executemany(f"INSERT INTO {table} VALUES (?, ?)", data)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
