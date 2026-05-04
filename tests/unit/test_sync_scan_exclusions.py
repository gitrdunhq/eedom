"""Tests for scripts/sync_scan_exclusions.py.
# tested-by: tests/unit/test_sync_scan_exclusions.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the script as a module
sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))
import sync_scan_exclusions as sut


class TestFindLockfileDirs:
    def test_returns_dir_containing_requirements_txt(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
        result = sut.find_lockfile_dirs(tmp_path)
        assert tmp_path in result

    def test_returns_dir_containing_pyproject_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
        result = sut.find_lockfile_dirs(tmp_path)
        assert tmp_path in result

    def test_ignores_dirs_with_no_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("pass\n")
        result = sut.find_lockfile_dirs(tmp_path)
        assert result == []

    def test_recurses_into_subdirectories(self, tmp_path: Path) -> None:
        sub = tmp_path / "nested" / "project"
        sub.mkdir(parents=True)
        (sub / "requirements.txt").write_text("requests==2.25.1\n")
        result = sut.find_lockfile_dirs(tmp_path)
        assert sub in result

    def test_deduplicates_dirs_with_multiple_lockfiles(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
        result = sut.find_lockfile_dirs(tmp_path)
        assert result.count(tmp_path) == 1

    def test_returns_sorted_list(self, tmp_path: Path) -> None:
        (tmp_path / "b").mkdir()
        (tmp_path / "a").mkdir()
        (tmp_path / "b" / "requirements.txt").write_text("")
        (tmp_path / "a" / "requirements.txt").write_text("")
        result = sut.find_lockfile_dirs(tmp_path)
        assert result == sorted(result)


class TestWriteOsvConfigs:
    def test_creates_osv_config_in_lockfile_dir(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
        sut.write_osv_configs([tmp_path])
        assert (tmp_path / "osv-scanner.toml").exists()

    def test_config_contains_package_override_ignore(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
        sut.write_osv_configs([tmp_path])
        content = (tmp_path / "osv-scanner.toml").read_text()
        assert "[[PackageOverrides]]" in content
        assert "ignore = true" in content

    def test_config_contains_auto_generated_header(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
        sut.write_osv_configs([tmp_path])
        content = (tmp_path / "osv-scanner.toml").read_text()
        assert "AUTO-GENERATED" in content

    def test_config_contains_reason(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.2.0\n")
        sut.write_osv_configs([tmp_path])
        content = (tmp_path / "osv-scanner.toml").read_text()
        assert "reason" in content

    def test_writes_to_all_lockfile_dirs(self, tmp_path: Path) -> None:
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / "requirements.txt").write_text("")
        (b / "requirements.txt").write_text("")
        sut.write_osv_configs([tmp_path])
        assert (a / "osv-scanner.toml").exists()
        assert (b / "osv-scanner.toml").exists()

    def test_returns_list_of_written_paths(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("")
        result = sut.write_osv_configs([tmp_path])
        assert tmp_path / "osv-scanner.toml" in result

    def test_no_lockfile_dir_writes_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("pass\n")
        result = sut.write_osv_configs([tmp_path])
        assert result == []


class TestValidateDependabot:
    def test_returns_empty_when_path_covered(self, tmp_path: Path) -> None:
        dependabot = tmp_path / "dependabot.yml"
        dependabot.write_text('exclude-paths:\n  - "tests/e2e/fixtures/**"\n')
        fixture_root = Path("tests/e2e/fixtures")
        # Patch DEPENDABOT_PATH for this test
        original = sut.DEPENDABOT_PATH
        sut.DEPENDABOT_PATH = dependabot
        try:
            result = sut.validate_dependabot([Path(__file__).parents[2] / str(fixture_root)])
        finally:
            sut.DEPENDABOT_PATH = original
        assert result == []

    def test_returns_missing_when_path_not_covered(self, tmp_path: Path) -> None:
        dependabot = tmp_path / "dependabot.yml"
        dependabot.write_text("updates: []\n")
        fixture_root = tmp_path / "tests" / "fixtures"
        fixture_root.mkdir(parents=True)
        original_root = sut.REPO_ROOT
        original_dep = sut.DEPENDABOT_PATH
        sut.REPO_ROOT = tmp_path
        sut.DEPENDABOT_PATH = dependabot
        try:
            result = sut.validate_dependabot([fixture_root])
        finally:
            sut.REPO_ROOT = original_root
            sut.DEPENDABOT_PATH = original_dep
        assert len(result) > 0
        assert any("fixtures" in m for m in result)
