from __future__ import annotations

import time
from datetime import datetime, timezone

from .checks import (
    check_cloudtrail,
    check_ec2_rdp,
    check_ec2_ssh,
    check_iam_admin_privileges,
    check_iam_mfa,
    check_iam_password_policy,
    check_iam_root_mfa,
    check_monitoring,
    check_s3_encryption,
    check_s3_public_access,
    check_s3_versioning,
)
from .models import Finding
from .scoring import (
    GDPR_MULTIPLIER,
    NIS2_MULTIPLIER,
    calculate_scores,
    priority_order,
    severity_counts,
    status_counts,
)

# ---------------------------------------------------------------------------
# Canonical check-ID sets
# These constants are the single source of truth for what constitutes the
# ten COM7014-approved core controls vs. the extension controls.  The report
# and summary use these sets to separate the two tiers cleanly.
# ---------------------------------------------------------------------------

CORE_CHECK_IDS: frozenset[str] = frozenset({
    "S3-001",   # S3 Public Access Block
    "S3-002",   # S3 Default Server-Side Encryption Configuration
    "S3-003",   # S3 Versioning
    "IAM-001",  # IAM User MFA (console users)
    "IAM-002",  # IAM Account Password Policy
    "IAM-003",  # IAM Excessive Administrator Privileges
    "EC2-001",  # EC2 SSH Exposure
    "EC2-002",  # EC2 RDP Exposure
    "CT-001",   # CloudTrail Logging
    "MON-001",  # CloudTrail CloudWatch Logs Integration
})

EXTENSION_CHECK_IDS: frozenset[str] = frozenset({
    "IAM-004",  # Root Account MFA (additional, beyond approved scope)
})

TOOL_VERSION = "5.1.0"


class AuditEngine:
    def __init__(self, session):
        self.session = session

        # Clients are created lazily enough for testability but all are read-only
        # in the current implementation.
        self.s3 = session.client("s3")
        self.iam = session.client("iam")
        self.ec2 = session.client("ec2")
        self.cloudtrail = session.client("cloudtrail")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        check_functions = [
            lambda: check_s3_public_access(self.s3),
            lambda: check_s3_encryption(self.s3),
            lambda: check_s3_versioning(self.s3),
            lambda: check_iam_mfa(self.iam),
            lambda: check_iam_password_policy(self.iam),
            lambda: check_iam_admin_privileges(self.iam),
            lambda: check_iam_root_mfa(self.iam),
            lambda: check_ec2_ssh(self.ec2),
            lambda: check_ec2_rdp(self.ec2),
            lambda: check_cloudtrail(self.cloudtrail),
            lambda: check_monitoring(self.cloudtrail),
        ]

        for function in check_functions:
            started = time.perf_counter()
            try:
                result = function()
                findings.extend(result)
            except Exception as exc:
                # A check failure must not turn into a false PASS.
                from .models import Finding
                findings.append(Finding(
                    check_id="ENGINE-ERROR",
                    name="Unhandled check error",
                    service="Engine",
                    resource="N/A",
                    status="ERROR",
                    severity="INFO",
                    current_state="The check raised an unexpected exception.",
                    expected_state="The check completes safely.",
                    evidence={"exception_type": type(exc).__name__},
                    why_it_matters="The scanner could not safely evaluate this part of the environment.",
                    remediation=["Inspect the error and correct the scanner or AWS permission/configuration issue."],
                    verification="Re-run the audit after the issue is resolved.",
                    error=str(exc),
                ))
            finally:
                _ = time.perf_counter() - started

        return findings

    @staticmethod
    def build_summary(findings, duration: float, account_id: str, region: str) -> dict:
        scores = calculate_scores(findings)
        statuses = status_counts(findings)
        severities = severity_counts(findings)

        # Separate core from extension check IDs actually present in this run.
        all_ids = {f.check_id for f in findings if not f.check_id.startswith("ENGINE-ERROR")}
        core_ids_found = sorted(all_ids & CORE_CHECK_IDS)
        ext_ids_found = sorted(all_ids & EXTENSION_CHECK_IDS)

        # Coverage: how many core checks produced an evaluable result (PASS or FAIL)?
        # WARN and ERROR are partially evaluated; NOT_APPLICABLE is genuinely N/A.
        core_findings = [f for f in findings if f.check_id in CORE_CHECK_IDS]
        fully_evaluated = {
            f.check_id for f in core_findings
            if f.status in {"PASS", "FAIL"}
        }
        partially_evaluated = {
            f.check_id for f in core_findings
            if f.status in {"WARN", "ERROR"}
        }
        not_applicable = {
            f.check_id for f in core_findings
            if f.status == "NOT_APPLICABLE"
        }

        total_core = len(CORE_CHECK_IDS)
        applicable_core = total_core - len(not_applicable)
        coverage_pct = round(
            100.0 * len(fully_evaluated) / applicable_core, 1
        ) if applicable_core else 0.0
        confidence = "HIGH" if not partially_evaluated else "LIMITED"

        return {
            "metadata": {
                "tool": "AWS Cloud Security Auditor",
                "version": TOOL_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "account_id": account_id,
                "region": region,
                "read_only": True,
                "scope_note": "Scores apply only to the configured controls assessed by this tool.",
            },
            "checks": {
                "core_total": total_core,
                "core_evaluated": len(fully_evaluated),
                "core_check_ids": core_ids_found,
                "extension_check_ids": ext_ids_found,
                "status_counts": statuses,
                "severity_counts": severities,
            },
            "coverage": {
                "core_total": total_core,
                "core_applicable": applicable_core,
                "core_fully_evaluated": sorted(fully_evaluated),
                "core_partially_evaluated": sorted(partially_evaluated),
                "core_not_applicable": sorted(not_applicable),
                "coverage_percent": coverage_pct,
                "assessment_confidence": confidence,
                "note": (
                    "Coverage counts PASS/FAIL results as fully evaluated. "
                    "WARN/ERROR results are partially evaluated. "
                    "NOT_APPLICABLE controls are excluded from both the numerator and denominator of the coverage percentage."
                ),
            },
            "findings": [f.to_dict() for f in findings],
            "scores": scores,
            "score_methodology": {
                "security": (
                    "100 minus the sum of severity penalties for failed checks, capped at 0. "
                    "Each check_id contributes its penalty at most once (worst-case resource used); "
                    "multiple failed resources under the same check do not multiply the penalty."
                ),
                "gdpr": (
                    f"100 minus the sum of GDPR-mapped penalties (security penalty × {GDPR_MULTIPLIER:g}) "
                    "for failed checks, capped at 0. Per-check deduplication applies."
                ),
                "nis2": (
                    f"100 minus the sum of NIS2-mapped penalties (security penalty × {NIS2_MULTIPLIER:g}) "
                    "for failed checks, capped at 0. Per-check deduplication applies."
                ),
                "benchmark": "Severity thresholds reference CIS AWS Foundations Benchmark v1.5.0.",
                "important": (
                    "These are control-set indicators over the configured checks only. "
                    "They are not legal compliance certification, GDPR certification, "
                    "NIS2 certification, or whole-account security certification."
                ),
            },
            "timing": {
                "scan_seconds": round(duration, 3),
                "performance_target_seconds": 10.0,
            },
            "priority_order": priority_order(findings),
        }
