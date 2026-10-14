from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    check_id: str
    name: str
    service: str
    resource: str
    status: str  # PASS, FAIL, WARN, ERROR, NOT_APPLICABLE
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    current_state: str
    expected_state: str
    evidence: dict[str, Any] = field(default_factory=dict)
    why_it_matters: str = ""
    gdpr: list[dict[str, str]] = field(default_factory=list)
    nis2: list[dict[str, str]] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    verification: str = ""
    security_penalty: float = 0.0
    gdpr_penalty: float = 0.0
    nis2_penalty: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditSummary:
    metadata: dict[str, Any]
    checks: dict[str, Any]
    findings: list[dict[str, Any]]
    scores: dict[str, float]
    score_methodology: dict[str, Any]
    timing: dict[str, float]
    priority_order: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
