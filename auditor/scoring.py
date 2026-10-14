from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import Finding

# Penalties are intentionally explicit and documented.
SEVERITY_PENALTY = {
    "CRITICAL": 20.0,
    "HIGH": 10.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.0,
}

# The compliance penalties are separate from the security penalty. These
# multipliers are explicit methodology parameters and are applied when each
# Finding is constructed in checks.py.
GDPR_MULTIPLIER = 0.8
NIS2_MULTIPLIER = 0.8


def penalty_for(severity: str) -> float:
    return SEVERITY_PENALTY.get(severity.upper(), 0.0)


def calculate_scores(findings: Iterable[Finding]) -> dict[str, float]:
    """Calculate the three score indicators for this control set.

    Each check_id contributes its penalty at most once, using the worst-case
    (highest-penalty) failing finding for that check.  This makes the score
    independent of account size — an account with 50 misconfigured S3 buckets
    receives the same S3-001 penalty as one with a single misconfigured bucket.
    The penalty set is limited to the 10 core checks; IAM-004 (Root MFA) is an
    additional check and its penalty is included when present.

    Methodology reference: penalty weights are documented in scoring.py and are
    intended to be justified against experimental TP/TN/FP/FN results before
    the dissertation is finalised.
    """
    findings = list(findings)
    failed = [f for f in findings if f.status == "FAIL"]

    # De-duplicate by check_id, keeping the highest security_penalty per check.
    worst: dict[str, Finding] = {}
    for f in failed:
        if f.check_id not in worst or f.security_penalty > worst[f.check_id].security_penalty:
            worst[f.check_id] = f

    security_penalty = sum(f.security_penalty for f in worst.values())
    gdpr_penalty = sum(f.gdpr_penalty for f in worst.values())
    nis2_penalty = sum(f.nis2_penalty for f in worst.values())

    # A score is an indicator over this configured control set only.
    return {
        "security": max(0.0, min(100.0, 100.0 - security_penalty)),
        "gdpr": max(0.0, min(100.0, 100.0 - gdpr_penalty)),
        "nis2": max(0.0, min(100.0, 100.0 - nis2_penalty)),
    }


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    return dict(Counter(f.severity for f in findings if f.status == "FAIL"))


def status_counts(findings: Iterable[Finding]) -> dict[str, int]:
    return dict(Counter(f.status for f in findings))


def priority_order(findings: Iterable[Finding]) -> list[str]:
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    failed = [f for f in findings if f.status == "FAIL"]
    failed.sort(
        key=lambda f: (
            severity_rank.get(f.severity, 99),
            -max(f.security_penalty, f.gdpr_penalty, f.nis2_penalty),
            f.check_id,
        )
    )
    return [f"{f.check_id} — {f.name} ({f.severity})" for f in failed]
