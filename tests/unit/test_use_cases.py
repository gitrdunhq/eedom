# tested-by: tests/unit/test_use_cases.py
"""Contract tests for eedom.core.use_cases — ReviewUseCase interface.

RED phase for issue #182 — all tests import from eedom.core.use_cases which
does not exist yet.  Every test is expected to fail with ImportError until the
production code is added.

Defines the contract for:
  - ReviewOptions dataclass  (scanners, categories, disabled, enabled)
  - ReviewResult  dataclass  (results, verdict, security_score, quality_score)
  - review_repository(context, files, repo_path, options) -> ReviewResult
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

# ---------------------------------------------------------------------------
# Importability
# ---------------------------------------------------------------------------


class TestImportability:
    def test_review_repository_is_importable(self) -> None:
        from eedom.core.use_cases import review_repository  # noqa: F401

    def test_review_options_is_importable(self) -> None:
        from eedom.core.use_cases import ReviewOptions  # noqa: F401

    def test_review_result_is_importable(self) -> None:
        from eedom.core.use_cases import ReviewResult  # noqa: F401


# ---------------------------------------------------------------------------
# ReviewOptions dataclass shape
# ---------------------------------------------------------------------------


class TestReviewOptionsDataclass:
    def test_review_options_is_a_dataclass(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        assert dataclasses.is_dataclass(ReviewOptions)

    def test_review_options_has_scanners_field(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        fields = {f.name for f in dataclasses.fields(ReviewOptions)}
        assert "scanners" in fields, "ReviewOptions must have a 'scanners' field"

    def test_review_options_has_categories_field(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        fields = {f.name for f in dataclasses.fields(ReviewOptions)}
        assert "categories" in fields, "ReviewOptions must have a 'categories' field"

    def test_review_options_has_disabled_field(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        fields = {f.name for f in dataclasses.fields(ReviewOptions)}
        assert "disabled" in fields, "ReviewOptions must have a 'disabled' field"

    def test_review_options_has_enabled_field(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        fields = {f.name for f in dataclasses.fields(ReviewOptions)}
        assert "enabled" in fields, "ReviewOptions must have an 'enabled' field"

    def test_review_options_scanners_defaults_to_none(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        opts = ReviewOptions()
        assert opts.scanners is None

    def test_review_options_categories_defaults_to_none(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        opts = ReviewOptions()
        assert opts.categories is None

    def test_review_options_disabled_defaults_to_empty_set(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        opts = ReviewOptions()
        assert isinstance(opts.disabled, set)
        assert len(opts.disabled) == 0

    def test_review_options_enabled_defaults_to_empty_set(self) -> None:
        from eedom.core.use_cases import ReviewOptions

        opts = ReviewOptions()
        assert isinstance(opts.enabled, set)
        assert len(opts.enabled) == 0


# ---------------------------------------------------------------------------
# ReviewResult dataclass shape
# ---------------------------------------------------------------------------


class TestReviewResultDataclass:
    def test_review_result_is_a_dataclass(self) -> None:
        from eedom.core.use_cases import ReviewResult

        assert dataclasses.is_dataclass(ReviewResult)

    def test_review_result_has_results_field(self) -> None:
        from eedom.core.use_cases import ReviewResult

        fields = {f.name for f in dataclasses.fields(ReviewResult)}
        assert "results" in fields, "ReviewResult must have a 'results' field"

    def test_review_result_has_verdict_field(self) -> None:
        from eedom.core.use_cases import ReviewResult

        fields = {f.name for f in dataclasses.fields(ReviewResult)}
        assert "verdict" in fields, "ReviewResult must have a 'verdict' field"

    def test_review_result_has_security_score_field(self) -> None:
        from eedom.core.use_cases import ReviewResult

        fields = {f.name for f in dataclasses.fields(ReviewResult)}
        assert "security_score" in fields, "ReviewResult must have a 'security_score' field"

    def test_review_result_has_quality_score_field(self) -> None:
        from eedom.core.use_cases import ReviewResult

        fields = {f.name for f in dataclasses.fields(ReviewResult)}
        assert "quality_score" in fields, "ReviewResult must have a 'quality_score' field"


# ---------------------------------------------------------------------------
# review_repository() behaviour
# ---------------------------------------------------------------------------


class TestReviewRepository:
    def test_review_repository_returns_review_result(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, ReviewResult, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions()
        result = review_repository(ctx, files=[], repo_path=Path("."), options=opts)
        assert isinstance(result, ReviewResult)

    def test_review_repository_empty_files_returns_clear_verdict(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions()
        result = review_repository(ctx, files=[], repo_path=Path("."), options=opts)
        assert result.verdict == "clear"

    def test_review_repository_empty_files_has_empty_results_list(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions()
        result = review_repository(ctx, files=[], repo_path=Path("."), options=opts)
        assert isinstance(result.results, list)
        assert len(result.results) == 0

    def test_review_repository_empty_files_scores_are_floats(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions()
        result = review_repository(ctx, files=[], repo_path=Path("."), options=opts)
        assert isinstance(result.security_score, float)
        assert isinstance(result.quality_score, float)

    def test_review_repository_accepts_scanner_filter_via_options(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions(scanners=["semgrep", "trivy"])
        result = review_repository(ctx, files=[], repo_path=Path("."), options=opts)
        # With fakes the result list is always empty — the point is no TypeError is raised.
        assert result is not None

    def test_review_repository_accepts_disabled_set_via_options(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions(disabled={"gitleaks"}, enabled={"semgrep"})
        result = review_repository(ctx, files=[], repo_path=Path("."), options=opts)
        assert result is not None

    def test_review_repository_accepts_repo_path_as_path_object(self) -> None:
        from eedom.core.bootstrap import bootstrap_test
        from eedom.core.use_cases import ReviewOptions, review_repository

        ctx = bootstrap_test()
        opts = ReviewOptions()
        # Must accept a real pathlib.Path, not just a string.
        result = review_repository(ctx, files=[], repo_path=Path("/tmp/fake-repo"), options=opts)
        assert result is not None
