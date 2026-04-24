"""Tests for eedom.core.sbom_diff.

# tested-by: tests/unit/test_sbom_diff.py

Covers example-based and property-based tests for parse_sbom_packages(),
diff_sboms(), and PackageInfo.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from eedom.core.sbom_diff import PackageInfo, diff_sboms, parse_sbom_packages

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sbom(*components: dict) -> dict:
    """Build a minimal CycloneDX-shaped SBOM dict."""
    return {"components": list(components)}


def _component(name: str, version: str, purl: str = "") -> dict:
    return {"name": name, "version": version, "purl": purl, "type": "library"}


# ---------------------------------------------------------------------------
# Example-based: parse_sbom_packages
# ---------------------------------------------------------------------------


class TestParseSbomPackages:
    def test_parse_sbom_extracts_packages(self) -> None:
        """CycloneDX JSON with 3 components yields 3 PackageInfo entries."""
        sbom = _make_sbom(
            _component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
            _component("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),
            _component("numpy", "1.26.0", "pkg:pypi/numpy@1.26.0"),
        )

        result = parse_sbom_packages(sbom)

        assert len(result) == 3
        assert "pypi:requests" in result
        assert "pypi:flask" in result
        assert "pypi:numpy" in result

    def test_parse_sbom_empty_components(self) -> None:
        """Empty components list returns empty dict."""
        sbom = _make_sbom()
        result = parse_sbom_packages(sbom)
        assert result == {}

    def test_parse_sbom_missing_components_key(self) -> None:
        """SBOM without 'components' key returns empty dict (no crash)."""
        result = parse_sbom_packages({})
        assert result == {}

    def test_parse_sbom_extracts_ecosystem_from_purl(self) -> None:
        """pkg:pypi/requests@2.31.0 purl → ecosystem='pypi'."""
        sbom = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        result = parse_sbom_packages(sbom)
        assert result["pypi:requests"].ecosystem == "pypi"

    def test_parse_sbom_npm_ecosystem(self) -> None:
        """pkg:npm/lodash@4.17.21 purl → ecosystem='npm'."""
        sbom = _make_sbom(_component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"))
        result = parse_sbom_packages(sbom)
        assert "npm:lodash" in result
        assert result["npm:lodash"].ecosystem == "npm"

    def test_parse_sbom_fallback_ecosystem_from_type(self) -> None:
        """Component with no purl falls back to component's 'type' field."""
        component = {"name": "some-lib", "version": "1.0.0", "type": "library"}
        sbom = {"components": [component]}
        result = parse_sbom_packages(sbom)
        assert "library:some-lib" in result
        assert result["library:some-lib"].ecosystem == "library"

    def test_parse_sbom_skips_components_without_name(self) -> None:
        """Components missing 'name' are silently skipped."""
        sbom = {"components": [{"version": "1.0.0", "purl": "pkg:pypi/unknown@1.0.0"}]}
        result = parse_sbom_packages(sbom)
        assert result == {}

    def test_parse_sbom_package_info_fields(self) -> None:
        """PackageInfo fields are populated correctly from SBOM component."""
        sbom = _make_sbom(_component("boto3", "1.34.0", "pkg:pypi/boto3@1.34.0"))
        result = parse_sbom_packages(sbom)
        pkg = result["pypi:boto3"]
        assert isinstance(pkg, PackageInfo)
        assert pkg.name == "boto3"
        assert pkg.version == "1.34.0"
        assert pkg.ecosystem == "pypi"
        assert pkg.purl == "pkg:pypi/boto3@1.34.0"

    def test_parse_sbom_golang_ecosystem(self) -> None:
        """pkg:golang/... purl → ecosystem='golang'."""
        sbom = _make_sbom(
            _component("gopkg.in/yaml.v3", "3.0.1", "pkg:golang/gopkg.in/yaml.v3@3.0.1")
        )
        result = parse_sbom_packages(sbom)
        assert "golang:gopkg.in/yaml.v3" in result
        assert result["golang:gopkg.in/yaml.v3"].ecosystem == "golang"


# ---------------------------------------------------------------------------
# Example-based: diff_sboms
# ---------------------------------------------------------------------------


class TestDiffSboms:
    def test_diff_added_package(self) -> None:
        """Package in after but not before → action='added'."""
        before = _make_sbom()
        after = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "added"
        assert changes[0]["package"] == "requests"
        assert changes[0]["new_version"] == "2.31.0"
        assert changes[0]["old_version"] is None

    def test_diff_removed_package(self) -> None:
        """Package in before but not after → action='removed'."""
        before = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        after = _make_sbom()

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "removed"
        assert changes[0]["package"] == "requests"
        assert changes[0]["old_version"] == "2.31.0"
        assert changes[0]["new_version"] is None

    def test_diff_upgraded_package(self) -> None:
        """Same package, higher version in after → action='upgraded'."""
        before = _make_sbom(_component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"))
        after = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "upgraded"
        assert changes[0]["old_version"] == "2.25.0"
        assert changes[0]["new_version"] == "2.31.0"

    def test_diff_downgraded_package(self) -> None:
        """Same package, lower version in after → action='downgraded'."""
        before = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        after = _make_sbom(_component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "downgraded"
        assert changes[0]["old_version"] == "2.31.0"
        assert changes[0]["new_version"] == "2.25.0"

    def test_diff_unchanged_packages_not_in_output(self) -> None:
        """Package at same version on both sides does not appear in changes."""
        before = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        after = _make_sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

        changes = diff_sboms(before, after)

        assert changes == []

    def test_diff_multi_ecosystem(self) -> None:
        """npm + pypi packages mixed — diffs each ecosystem correctly."""
        before = _make_sbom(
            _component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
            _component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"),
        )
        after = _make_sbom(
            _component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),  # upgraded
            _component("requests", "2.25.0", "pkg:pypi/requests@2.25.0"),  # unchanged
            _component("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),  # added
        )

        changes = diff_sboms(before, after)

        actions = {c["package"]: c["action"] for c in changes}
        assert actions["lodash"] == "upgraded"
        assert actions["flask"] == "added"
        assert "requests" not in actions

    def test_diff_empty_sboms(self) -> None:
        """Both empty SBOMs produce no changes."""
        changes = diff_sboms(_make_sbom(), _make_sbom())
        assert changes == []

    def test_version_comparison_semantic(self) -> None:
        """1.9.0 → 1.10.0 must be 'upgraded', not 'downgraded' (semver-aware)."""
        before = _make_sbom(_component("mylib", "1.9.0", "pkg:pypi/mylib@1.9.0"))
        after = _make_sbom(_component("mylib", "1.10.0", "pkg:pypi/mylib@1.10.0"))

        changes = diff_sboms(before, after)

        assert len(changes) == 1
        assert changes[0]["action"] == "upgraded"

    def test_diff_change_includes_ecosystem(self) -> None:
        """Each change dict includes 'ecosystem' matching the SBOM purl."""
        before = _make_sbom()
        after = _make_sbom(_component("express", "4.18.0", "pkg:npm/express@4.18.0"))

        changes = diff_sboms(before, after)

        assert changes[0]["ecosystem"] == "npm"

    def test_diff_change_includes_purl(self) -> None:
        """Each change dict includes 'purl' from the package."""
        before = _make_sbom()
        after = _make_sbom(_component("flask", "3.0.0", "pkg:pypi/flask@3.0.0"))

        changes = diff_sboms(before, after)

        assert changes[0]["purl"] == "pkg:pypi/flask@3.0.0"

    def test_diff_multiple_adds_and_removes(self) -> None:
        """Mixed adds and removes are all captured correctly."""
        before = _make_sbom(
            _component("pkg-a", "1.0.0", "pkg:pypi/pkg-a@1.0.0"),
            _component("pkg-b", "2.0.0", "pkg:pypi/pkg-b@2.0.0"),
        )
        after = _make_sbom(
            _component("pkg-b", "2.0.0", "pkg:pypi/pkg-b@2.0.0"),
            _component("pkg-c", "3.0.0", "pkg:pypi/pkg-c@3.0.0"),
        )

        changes = diff_sboms(before, after)
        actions = {c["package"]: c["action"] for c in changes}

        assert actions["pkg-a"] == "removed"
        assert actions["pkg-c"] == "added"
        assert "pkg-b" not in actions


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------

_purl_prefix_strategy = st.sampled_from(
    ["pkg:pypi/", "pkg:npm/", "pkg:maven/", "pkg:golang/", "pkg:cargo/"]
)

_valid_name_strategy = st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True)
_valid_version_strategy = st.from_regex(r"[0-9]+\.[0-9]+\.[0-9]+", fullmatch=True)


def _make_component_strategy():
    return st.builds(
        lambda name, version, prefix: {
            "name": name,
            "version": version,
            "purl": f"{prefix}{name}@{version}",
            "type": "library",
        },
        name=_valid_name_strategy,
        version=_valid_version_strategy,
        prefix=_purl_prefix_strategy,
    )


def _make_sbom_strategy(min_size: int = 0, max_size: int = 10):
    return st.builds(
        lambda components: {"components": components},
        components=st.lists(
            _make_component_strategy(),
            min_size=min_size,
            max_size=max_size,
            unique_by=lambda c: c["name"],
        ),
    )


@given(before=_make_sbom_strategy(), after=_make_sbom_strategy())
@settings(max_examples=200)
def test_diff_is_inverse(before: dict, after: dict) -> None:
    """If A→B produces N additions, then B→A produces N removals.

    The set of packages added going from A→B must equal the set of packages
    removed going from B→A.
    """
    a_to_b = diff_sboms(before, after)
    b_to_a = diff_sboms(after, before)

    added_fwd = {c["package"] for c in a_to_b if c["action"] == "added"}
    removed_rev = {c["package"] for c in b_to_a if c["action"] == "removed"}
    assert added_fwd == removed_rev

    removed_fwd = {c["package"] for c in a_to_b if c["action"] == "removed"}
    added_rev = {c["package"] for c in b_to_a if c["action"] == "added"}
    assert removed_fwd == added_rev


@given(before=_make_sbom_strategy(), after=_make_sbom_strategy())
@settings(max_examples=200)
def test_added_plus_removed_plus_changed_covers_all(before: dict, after: dict) -> None:
    """Total changed packages ≤ union of both package sets.

    No phantom packages can appear in changes that weren't in either SBOM.
    """
    before_pkgs = parse_sbom_packages(before)
    after_pkgs = parse_sbom_packages(after)
    all_package_names = {pkg.name for pkg in before_pkgs.values()} | {
        pkg.name for pkg in after_pkgs.values()
    }

    changes = diff_sboms(before, after)
    changed_names = {c["package"] for c in changes}

    assert changed_names <= all_package_names


@given(data=st.dictionaries(keys=st.text(max_size=20), values=st.text(max_size=20)))
@settings(max_examples=200)
def test_parse_never_crashes(data: dict) -> None:
    """parse_sbom_packages with random dict input must never raise."""
    # Should not raise — any malformed input is silently handled
    result = parse_sbom_packages(data)
    assert isinstance(result, dict)


@given(prefix=_purl_prefix_strategy, name=_valid_name_strategy, version=_valid_version_strategy)
@settings(max_examples=200)
def test_ecosystem_detection_is_deterministic(prefix: str, name: str, version: str) -> None:
    """Same purl always returns the same ecosystem (pure function)."""
    component = {"name": name, "version": version, "purl": f"{prefix}{name}@{version}"}
    sbom = {"components": [component]}

    result1 = parse_sbom_packages(sbom)
    result2 = parse_sbom_packages(sbom)

    # Both calls must produce identical ecosystem values
    keys1 = list(result1.keys())
    keys2 = list(result2.keys())
    assert keys1 == keys2
    for k in keys1:
        assert result1[k].ecosystem == result2[k].ecosystem
