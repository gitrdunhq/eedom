"""Tests for Dockerfile and Docker Compose latest-tag detection in SupplyChainPlugin.
# tested-by: tests/unit/test_supply_chain_latest.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.plugins.supply_chain import SupplyChainPlugin

# ── helpers ──────────────────────────────────────────────────────────────────


def _dockerfile_findings(content: str, tmp_path: Path) -> list[dict]:
    p = tmp_path / "Dockerfile"
    p.write_text(content)
    plugin = SupplyChainPlugin()
    return plugin._check_dockerfile_latest(str(p))


def _compose_findings(content: str, tmp_path: Path) -> list[dict]:
    p = tmp_path / "docker-compose.yml"
    p.write_text(content)
    plugin = SupplyChainPlugin()
    return plugin._check_compose_latest(str(p))


# ── Dockerfile tests ──────────────────────────────────────────────────────────


class TestDockerfileLatestDetection:
    def test_explicit_latest_tag_is_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM python:latest\nRUN echo hi\n", tmp_path)
        assert len(findings) == 1
        assert "python:latest" in findings[0]["description"]
        assert findings[0]["severity"] == "medium"

    def test_pinned_tag_no_finding(self, tmp_path):
        findings = _dockerfile_findings("FROM python:3.12-slim\nRUN echo hi\n", tmp_path)
        assert findings == []

    def test_implicit_latest_no_tag_is_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM python\nRUN echo hi\n", tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_from_scratch_not_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM scratch\nCOPY . /app\n", tmp_path)
        assert findings == []

    def test_multi_stage_implicit_latest_image_is_flagged(self, tmp_path):
        # "FROM python AS builder" — the image has no tag (implicit latest); stage name is not a tag
        findings = _dockerfile_findings("FROM python AS builder\nFROM python:3.12-slim\n", tmp_path)
        assert len(findings) == 1
        assert findings[0]["line"] == 1

    def test_multi_stage_explicit_latest_is_flagged(self, tmp_path):
        findings = _dockerfile_findings("FROM node:latest AS build\nFROM nginx:1.25\n", tmp_path)
        assert len(findings) == 1
        assert "node:latest" in findings[0]["description"]

    def test_multiple_violations_all_reported(self, tmp_path):
        content = "FROM python:latest\nFROM node\nFROM nginx:1.25\n"
        findings = _dockerfile_findings(content, tmp_path)
        assert len(findings) == 2

    def test_finding_includes_file_and_line(self, tmp_path):
        findings = _dockerfile_findings("FROM alpine:latest\n", tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert "file" in f
        assert f["line"] == 1

    def test_sha_pinned_image_not_flagged(self, tmp_path):
        # digest-pinned images are properly fixed
        findings = _dockerfile_findings("FROM python@sha256:abc123def456\nRUN echo hi\n", tmp_path)
        assert findings == []

    def test_arg_based_from_not_flagged(self, tmp_path):
        # FROM $BASE_IMAGE — cannot statically determine, skip
        findings = _dockerfile_findings("ARG BASE_IMAGE\nFROM $BASE_IMAGE\n", tmp_path)
        assert findings == []


# ── Docker Compose tests ──────────────────────────────────────────────────────


class TestComposeLatestDetection:
    def test_explicit_latest_tag_flagged(self, tmp_path):
        content = "services:\n  cache:\n    image: redis:latest\n"
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 1
        assert "redis:latest" in findings[0]["description"]
        assert findings[0]["severity"] == "medium"

    def test_pinned_tag_no_finding(self, tmp_path):
        content = "services:\n  cache:\n    image: redis:7.2\n"
        findings = _compose_findings(content, tmp_path)
        assert findings == []

    def test_no_tag_implicit_latest_flagged(self, tmp_path):
        content = "services:\n  app:\n    image: myapp\n"
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_multiple_services_mixed(self, tmp_path):
        content = (
            "services:\n"
            "  db:\n"
            "    image: postgres:16\n"
            "  cache:\n"
            "    image: redis:latest\n"
            "  app:\n"
            "    image: myapp\n"
        )
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 2

    def test_finding_includes_file(self, tmp_path):
        content = "services:\n  x:\n    image: busybox:latest\n"
        findings = _compose_findings(content, tmp_path)
        assert len(findings) == 1
        assert "file" in findings[0]

    def test_service_without_image_key_ignored(self, tmp_path):
        content = "services:\n  app:\n    build: .\n"
        findings = _compose_findings(content, tmp_path)
        assert findings == []

    def test_digest_pinned_image_not_flagged(self, tmp_path):
        content = "services:\n  app:\n    image: redis@sha256:abc123\n"
        findings = _compose_findings(content, tmp_path)
        assert findings == []


# ── run() wiring tests ────────────────────────────────────────────────────────


class TestRunWiring:
    def test_run_picks_up_dockerfile_findings(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["Dockerfile"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1

    def test_run_picks_up_compose_findings(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image: redis:latest\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["docker-compose.yml"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1

    def test_run_no_docker_files_no_docker_findings(self, tmp_path):
        (tmp_path / "package.json").write_text('{"dependencies": {}}')
        plugin = SupplyChainPlugin()
        result = plugin.run(["package.json"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert docker_findings == []

    def test_dockerfile_variant_names_detected(self, tmp_path):
        (tmp_path / "Dockerfile.dev").write_text("FROM node:latest\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["Dockerfile.dev"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1

    def test_compose_yaml_extension_detected(self, tmp_path):
        (tmp_path / "docker-compose.yaml").write_text("services:\n  app:\n    image: nginx\n")
        plugin = SupplyChainPlugin()
        result = plugin.run(["docker-compose.yaml"], tmp_path)
        docker_findings = [f for f in result.findings if f.get("type") == "docker_latest"]
        assert len(docker_findings) >= 1


# ── Lockfile SHA path tests ───────────────────────────────────────────────────


class TestLockfileShaPath:
    """Verify _check_lockfiles uses per-directory paths, not repo root."""

    def test_lockfile_sha_uses_lockfile_directory(self, tmp_path):
        """When package-lock.json is at apps/web/, SHA should hash apps/web/package-lock.json not repo/package-lock.json."""
        import hashlib

        web_dir = tmp_path / "apps" / "web"
        web_dir.mkdir(parents=True)
        lockfile_content = b'{"lockfileVersion": 3}'
        lockfile = web_dir / "package-lock.json"
        lockfile.write_bytes(lockfile_content)

        files = [str(lockfile)]
        plugin = SupplyChainPlugin()
        result = plugin.run(files, tmp_path)

        assert not result.error
        lockfile_findings = [f for f in result.findings if f.get("type") == "lockfile"]
        assert (
            lockfile_findings
        ), "Expected a lockfile finding for package-lock.json without manifest"
        expected_sha = hashlib.sha256(lockfile_content).hexdigest()
        assert (
            lockfile_findings[0]["sha256"] == expected_sha
        ), f"SHA should come from apps/web/package-lock.json, got {lockfile_findings[0]['sha256']!r}"

    def test_lockfile_sha_uses_package_dir_not_repo_root(self, tmp_path):
        """_check_lockfiles: SHA is from the actual lock file in its subdirectory."""
        import hashlib

        pkg_dir = tmp_path / "apps" / "web"
        pkg_dir.mkdir(parents=True)
        lock_content = '{"lockfileVersion": 2, "name": "web"}'
        (pkg_dir / "package-lock.json").write_text(lock_content)

        files = [str(pkg_dir / "package-lock.json")]
        plugin = SupplyChainPlugin()
        findings = plugin._check_lockfiles(files, tmp_path)

        lockfile_findings = [
            f for f in findings if f.get("type") == "lockfile" and f.get("severity") == "high"
        ]
        assert (
            len(lockfile_findings) == 1
        ), f"Expected 1 high lockfile finding, got {lockfile_findings}"
        expected_sha = hashlib.sha256(lock_content.encode()).hexdigest()
        assert lockfile_findings[0]["sha256"] == expected_sha, (
            f"SHA computed from wrong path. "
            f"Expected {expected_sha}, got {lockfile_findings[0]['sha256']!r}"
        )

    def test_manifest_lockfile_check_uses_package_dir(self, tmp_path):
        """_check_lockfiles: manifest-changed check looks for lockfile in package dir."""
        import hashlib

        pkg_dir = tmp_path / "apps" / "api"
        pkg_dir.mkdir(parents=True)
        lock_content = "# uv.lock\nversion = 1\n"
        (pkg_dir / "uv.lock").write_text(lock_content)
        (pkg_dir / "pyproject.toml").write_text("[project]\nname = 'api'\n")

        files = [str(pkg_dir / "pyproject.toml")]
        plugin = SupplyChainPlugin()
        findings = plugin._check_lockfiles(files, tmp_path)

        uv_findings = [
            f for f in findings if f.get("type") == "lockfile" and f.get("lockfile") == "uv.lock"
        ]
        assert (
            len(uv_findings) == 1
        ), f"Expected 1 uv.lock medium finding (manifest changed, lock not updated), got {uv_findings}"
        expected_sha = hashlib.sha256(lock_content.encode()).hexdigest()
        assert uv_findings[0]["sha256"] == expected_sha, (
            f"SHA computed from wrong path. "
            f"Expected {expected_sha}, got {uv_findings[0]['sha256']!r}"
        )
