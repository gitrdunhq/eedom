"""Review pipeline — orchestrates scanners, policy eval, and decision assembly.

# tested-by: tests/unit/test_pipeline.py

Extracted from cli/main.py to keep the presentation layer thin and make the
core pipeline logic independently testable.
"""

from __future__ import annotations

import time
from pathlib import Path

import orjson
import structlog

from eedom.core.config import EedomSettings
from eedom.core.decision import assemble_decision
from eedom.core.diff import DependencyDiffDetector
from eedom.core.memo import generate_memo
from eedom.core.models import (
    DecisionVerdict,
    OperatingMode,
    PolicyEvaluation,
    ReviewDecision,
)
from eedom.core.normalizer import normalize_findings
from eedom.core.orchestrator import ScanOrchestrator
from eedom.core.pipeline_helpers import (  # noqa: F401
    count_transitive_deps_from_scan,
    parse_changes,
    resolve_git_sha,
    sbom_changes_to_requests,
)
from eedom.core.policy import OpaEvaluator
from eedom.core.sbom_diff import diff_sboms
from eedom.core.seal import create_seal, find_previous_seal_hash

logger = structlog.get_logger()


def _data_imports():
    """Lazy-import data-tier dependencies to avoid core→data layer violation."""
    from eedom.data.db import DecisionRepository, NullRepository, RepositoryProtocol
    from eedom.data.evidence import EvidenceStore
    from eedom.data.parquet_writer import append_decisions
    from eedom.data.pypi import PyPIClient
    from eedom.data.scanners.osv import OsvScanner
    from eedom.data.scanners.scancode import ScanCodeScanner
    from eedom.data.scanners.syft import SyftScanner
    from eedom.data.scanners.trivy import TrivyScanner

    return {
        "DecisionRepository": DecisionRepository,
        "NullRepository": NullRepository,
        "RepositoryProtocol": RepositoryProtocol,
        "EvidenceStore": EvidenceStore,
        "append_decisions": append_decisions,
        "PyPIClient": PyPIClient,
        "OsvScanner": OsvScanner,
        "ScanCodeScanner": ScanCodeScanner,
        "SyftScanner": SyftScanner,
        "TrivyScanner": TrivyScanner,
    }


class ReviewPipeline:
    """End-to-end review pipeline — stateless per call."""

    def __init__(self, config: EedomSettings, context=None) -> None:
        self._config = config
        self._context = context

    def evaluate(
        self,
        diff_text: str,
        pr_url: str,
        team: str,
        mode: OperatingMode,
        repo_path: Path,
        commit_sha: str | None = None,
    ) -> list[ReviewDecision]:
        """Run the full review pipeline on dependency changes.

        Returns a list of ReviewDecision objects (one per changed package).
        Returns an empty list if no dependency changes are detected.
        """
        from datetime import UTC, datetime

        config = self._config
        pipeline_start = time.monotonic()

        if commit_sha is None:
            commit_sha = resolve_git_sha(repo_path)

        run_ts = datetime.now(UTC).strftime("%Y%m%d%H%M")
        short_sha = (commit_sha or "unknown")[:12]
        run_id = f"{short_sha}/{run_ts}"

        detector = DependencyDiffDetector()
        changed_files = detector.detect_changed_files(diff_text)
        if not changed_files:
            return []

        req_changes = parse_changes(detector, diff_text, changed_files)
        if not req_changes:
            return []

        requests = detector.create_requests(
            changes=req_changes,
            ecosystem="pypi",
            team=team,
            pr_url=pr_url,
            operating_mode=mode,
        )
        for req in requests:
            req.commit_sha = commit_sha
        if not requests:
            return []

        d = _data_imports()
        evidence_path = Path(config.evidence_path)

        scanners = []
        for name in config.enabled_scanners:
            if name == "syft":
                scanners.append(d["SyftScanner"](evidence_dir=evidence_path))
            elif name == "osv-scanner":
                scanners.append(d["OsvScanner"]())
            elif name == "trivy":
                scanners.append(d["TrivyScanner"]())
            elif name == "scancode":
                scanners.append(d["ScanCodeScanner"](evidence_dir=evidence_path))

        orchestrator = ScanOrchestrator(
            scanners=scanners,
            combined_timeout=config.combined_scanner_timeout,
        )

        if self._context is None:
            opa = OpaEvaluator(
                policy_path=config.opa_policy_path,
                timeout=config.opa_timeout,
            )
        else:
            opa = None

        evidence = d["EvidenceStore"](root_path=config.evidence_path)
        pypi_client = d["PyPIClient"](timeout=config.pypi_timeout)

        try:
            db = d["DecisionRepository"](
                dsn=config.db_dsn,
                query_timeout=10,
            )
            if not db.connect():
                logger.warning("db_unavailable", msg="Falling back to NullRepository")
                db = d["NullRepository"]()
        except Exception:
            logger.warning("db_init_failed", msg="Falling back to NullRepository")
            db = d["NullRepository"]()

        decisions: list[ReviewDecision] = []

        try:
            # Run scanners ONCE before the per-package loop (F-005)
            scan_results = orchestrator.run(repo_path)

            for req in requests:
                # Pipeline timeout enforcement (F-007)
                elapsed = time.monotonic() - pipeline_start
                if elapsed >= config.pipeline_timeout:
                    logger.warning(
                        "pipeline_timeout_reached",
                        package=req.package_name,
                        elapsed=elapsed,
                    )
                    break

                logger.info(
                    "evaluating_package", package=req.package_name, version=req.target_version
                )

                try:
                    db.save_request(req)
                    db.save_scan_results(req.request_id, scan_results)

                    findings, _summary = normalize_findings(scan_results)

                    # Populate OPA metadata (F-012)
                    pypi_meta = pypi_client.fetch_metadata(req.package_name, req.target_version)
                    first_published_date = (
                        pypi_meta.get("first_published_date")
                        if pypi_meta.get("available")
                        else None
                    )
                    transitive_dep_count = count_transitive_deps_from_scan(scan_results)

                    package_metadata = {
                        "name": req.package_name,
                        "version": req.target_version,
                        "ecosystem": req.ecosystem,
                        "scope": req.scope,
                        "first_published_date": first_published_date,
                        "transitive_dep_count": transitive_dep_count,
                    }

                    if self._context is not None:
                        from eedom.core.policy_port import PolicyInput

                        pd = self._context.policy_engine.evaluate(
                            PolicyInput(findings=[], packages=[package_metadata], config={})
                        )
                        verdict_str = getattr(pd, "verdict", "needs_review")
                        try:
                            _v = DecisionVerdict(verdict_str)
                        except (ValueError, AttributeError):
                            _v = DecisionVerdict.needs_review
                        policy_eval = PolicyEvaluation(
                            decision=_v,
                            triggered_rules=getattr(pd, "triggered_rules", []),
                            policy_bundle_version="port-injected",
                        )
                    else:
                        assert opa is not None
                        policy_eval = opa.evaluate(findings, package_metadata)
                    db.save_policy_evaluation(req.request_id, policy_eval)

                    pipeline_duration = time.monotonic() - pipeline_start
                    evidence_bundle_path = evidence.get_path(run_id, req.package_name)

                    decision = assemble_decision(
                        request=req,
                        findings=findings,
                        scan_results=scan_results,
                        policy_evaluation=policy_eval,
                        evidence_bundle_path=evidence_bundle_path,
                        pipeline_duration=pipeline_duration,
                    )

                    memo = generate_memo(decision)
                    decision.memo_text = memo

                    db.save_decision(req.request_id, decision)

                    evidence.store(
                        run_id,
                        f"{req.package_name}/decision.json",
                        orjson.dumps(decision.model_dump(mode="json"), option=orjson.OPT_INDENT_2),
                    )
                    evidence.store(run_id, f"{req.package_name}/memo.md", memo)

                    decisions.append(decision)

                except Exception:
                    logger.exception("package_evaluation_failed", package=req.package_name)
                    decisions.append(
                        ReviewDecision(
                            request=req,
                            decision=DecisionVerdict.needs_review,
                            findings=[],
                            scan_results=scan_results,
                            policy_evaluation=PolicyEvaluation(
                                decision=DecisionVerdict.needs_review,
                                triggered_rules=["package evaluation failed unexpectedly"],
                                policy_bundle_version="unknown",
                            ),
                            pipeline_duration_seconds=time.monotonic() - pipeline_start,
                        )
                    )

            # Append decisions to the parquet audit log (fail-open)
            d["append_decisions"](Path(config.evidence_path), decisions, run_id)

            # Seal all evidence artifacts for this run (fail-open)
            try:
                evidence_run_dir = Path(config.evidence_path) / run_id
                previous_hash = find_previous_seal_hash(Path(config.evidence_path), run_id)
                create_seal(evidence_run_dir, run_id, commit_sha, previous_hash)
            except Exception:
                logger.exception("seal_creation_failed", run_id=run_id)

        finally:
            db.close()

        return decisions

    def evaluate_sbom(
        self,
        before_sbom: dict,
        after_sbom: dict,
        pr_url: str,
        team: str,
        mode: OperatingMode,
        repo_path: Path,
        commit_sha: str | None = None,
    ) -> list[ReviewDecision]:
        """Evaluate dependency changes using SBOM diff. Ecosystem-agnostic.

        Diffs two CycloneDX SBOMs (before/after) to discover changed packages
        across any ecosystem Syft supports, then runs them through the same
        scanner → normalize → OPA → decision → memo pipeline as evaluate().

        Returns a list of ReviewDecision objects (one per changed package).
        Returns an empty list when no dependency changes are found.
        """
        from datetime import UTC, datetime

        config = self._config
        pipeline_start = time.monotonic()

        if commit_sha is None:
            commit_sha = resolve_git_sha(repo_path)

        run_ts = datetime.now(UTC).strftime("%Y%m%d%H%M")
        short_sha = (commit_sha or "unknown")[:12]
        run_id = f"{short_sha}/{run_ts}"

        changes = diff_sboms(before_sbom, after_sbom)
        if not changes:
            return []

        requests = sbom_changes_to_requests(
            changes=changes,
            team=team,
            pr_url=pr_url,
            operating_mode=mode,
        )
        if not requests:
            return []

        d = _data_imports()
        evidence_path = Path(config.evidence_path)

        scanners = []
        for name in config.enabled_scanners:
            if name == "syft":
                scanners.append(d["SyftScanner"](evidence_dir=evidence_path))
            elif name == "osv-scanner":
                scanners.append(d["OsvScanner"]())
            elif name == "trivy":
                scanners.append(d["TrivyScanner"]())
            elif name == "scancode":
                scanners.append(d["ScanCodeScanner"](evidence_dir=evidence_path))

        orchestrator = ScanOrchestrator(
            scanners=scanners,
            combined_timeout=config.combined_scanner_timeout,
        )

        opa = OpaEvaluator(
            policy_path=config.opa_policy_path,
            timeout=config.opa_timeout,
        )

        evidence = d["EvidenceStore"](root_path=config.evidence_path)
        pypi_client = d["PyPIClient"](timeout=config.pypi_timeout)

        try:
            db = d["DecisionRepository"](
                dsn=config.db_dsn,
                query_timeout=10,
            )
            if not db.connect():
                logger.warning("db_unavailable", msg="Falling back to NullRepository")
                db = d["NullRepository"]()
        except Exception:
            logger.warning("db_init_failed", msg="Falling back to NullRepository")
            db = d["NullRepository"]()

        decisions: list[ReviewDecision] = []

        try:
            # Run scanners ONCE before the per-package loop (F-005)
            scan_results = orchestrator.run(repo_path)

            for req in requests:
                elapsed = time.monotonic() - pipeline_start
                if elapsed >= config.pipeline_timeout:
                    logger.warning(
                        "pipeline_timeout_reached",
                        package=req.package_name,
                        elapsed=elapsed,
                    )
                    break

                logger.info(
                    "evaluating_package_sbom",
                    package=req.package_name,
                    version=req.target_version,
                    ecosystem=req.ecosystem,
                )

                try:
                    db.save_request(req)
                    db.save_scan_results(req.request_id, scan_results)

                    findings, _summary = normalize_findings(scan_results)

                    pypi_meta = pypi_client.fetch_metadata(req.package_name, req.target_version)
                    first_published_date = (
                        pypi_meta.get("first_published_date")
                        if pypi_meta.get("available")
                        else None
                    )
                    transitive_dep_count = count_transitive_deps_from_scan(scan_results)

                    package_metadata = {
                        "name": req.package_name,
                        "version": req.target_version,
                        "ecosystem": req.ecosystem,
                        "scope": req.scope,
                        "first_published_date": first_published_date,
                        "transitive_dep_count": transitive_dep_count,
                    }

                    policy_eval = opa.evaluate(findings, package_metadata)
                    db.save_policy_evaluation(req.request_id, policy_eval)

                    pipeline_duration = time.monotonic() - pipeline_start
                    evidence_bundle_path = evidence.get_path(run_id, req.package_name)

                    decision = assemble_decision(
                        request=req,
                        findings=findings,
                        scan_results=scan_results,
                        policy_evaluation=policy_eval,
                        evidence_bundle_path=evidence_bundle_path,
                        pipeline_duration=pipeline_duration,
                    )

                    memo = generate_memo(decision)
                    decision.memo_text = memo

                    db.save_decision(req.request_id, decision)

                    evidence.store(
                        run_id,
                        f"{req.package_name}/decision.json",
                        orjson.dumps(decision.model_dump(mode="json"), option=orjson.OPT_INDENT_2),
                    )
                    evidence.store(run_id, f"{req.package_name}/memo.md", memo)

                    decisions.append(decision)

                except Exception:
                    logger.exception("package_evaluation_failed", package=req.package_name)
                    decisions.append(
                        ReviewDecision(
                            request=req,
                            decision=DecisionVerdict.needs_review,
                            findings=[],
                            scan_results=scan_results,
                            policy_evaluation=PolicyEvaluation(
                                decision=DecisionVerdict.needs_review,
                                triggered_rules=["package evaluation failed unexpectedly"],
                                policy_bundle_version="unknown",
                            ),
                            pipeline_duration_seconds=time.monotonic() - pipeline_start,
                        )
                    )

        finally:
            db.close()

        return decisions
