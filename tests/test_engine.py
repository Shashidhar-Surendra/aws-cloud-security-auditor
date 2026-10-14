"""Unit tests for AuditEngine reliability properties.

These tests verify that the engine's control flow behaves correctly:
- One crashing check must not prevent subsequent checks from running.
- The engine must produce an ERROR finding for the failing check.
"""
from __future__ import annotations

from auditor.engine import AuditEngine, TOOL_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeSession:
    """Minimal session stub — clients are never used directly in these tests."""

    def client(self, service_name: str):
        return object()


def _make_engine_with_checks(*check_fns):
    """Return an AuditEngine whose check_functions list is replaced with the given callables."""
    engine = AuditEngine.__new__(AuditEngine)
    # Wire up the session (clients unused in overridden run)
    object.__setattr__(engine, "session", _FakeSession())
    engine._check_fns_override = list(check_fns)
    return engine


class _EngineWithOverride(AuditEngine):
    """Subclass that substitutes check_functions at test time without needing real AWS clients."""

    def __init__(self, check_fns):
        # Skip the real __init__ (which would call session.client("s3") etc.)
        self._check_fns = check_fns

    def run(self) -> list:
        import time
        from auditor.models import Finding

        findings = []
        for function in self._check_fns:
            try:
                result = function()
                findings.extend(result)
            except Exception as exc:
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
        return findings


def _pass_finding(check_id: str):
    from auditor.models import Finding
    return Finding(
        check_id=check_id,
        name=f"Test {check_id}",
        service="Test",
        resource="test-resource",
        status="PASS",
        severity="INFO",
        current_state="OK",
        expected_state="OK",
        evidence={},
        why_it_matters="",
        gdpr=[],
        nis2=[],
        remediation=[],
        verification="",
        security_penalty=0.0,
        gdpr_penalty=0.0,
        nis2_penalty=0.0,
        error=None,
    )


# ---------------------------------------------------------------------------
# Engine failure isolation
# ---------------------------------------------------------------------------

def test_engine_continues_after_check_exception():
    """Check 1 → PASS, Check 2 → raises, Check 3 → PASS.
    All three findings must be returned; Check 2 produces an ENGINE-ERROR finding.
    """
    def check1():
        return [_pass_finding("S3-001")]

    def check2():
        raise RuntimeError("simulated check crash")

    def check3():
        return [_pass_finding("IAM-001")]

    engine = _EngineWithOverride([check1, check2, check3])
    findings = engine.run()

    statuses = [f.status for f in findings]
    check_ids = [f.check_id for f in findings]

    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}: {findings}"
    assert statuses.count("PASS") == 2
    assert statuses.count("ERROR") == 1
    assert "ENGINE-ERROR" in check_ids
    # The crash must not prevent Check 3 from running
    assert "IAM-001" in check_ids


def test_engine_error_finding_contains_exception_info():
    """The ENGINE-ERROR finding must record the exception type."""
    def crashing_check():
        raise ValueError("bad value")

    engine = _EngineWithOverride([crashing_check])
    findings = engine.run()

    assert len(findings) == 1
    f = findings[0]
    assert f.status == "ERROR"
    assert f.check_id == "ENGINE-ERROR"
    assert f.evidence.get("exception_type") == "ValueError"
    assert "bad value" in (f.error or "")


def test_engine_all_checks_crash_returns_error_findings():
    """Even when every check crashes, the engine should return an ERROR finding per check."""
    def crash1():
        raise RuntimeError("crash1")

    def crash2():
        raise RuntimeError("crash2")

    engine = _EngineWithOverride([crash1, crash2])
    findings = engine.run()

    assert len(findings) == 2
    assert all(f.status == "ERROR" for f in findings)


# ---------------------------------------------------------------------------
# Version constant
# ---------------------------------------------------------------------------

def test_tool_version_is_v5():
    assert TOOL_VERSION == "5.1.0", (
        f"TOOL_VERSION should be '5.1.0', got '{TOOL_VERSION}'."
    )


def test_version_file_matches_tool_version():
    from pathlib import Path

    version_file = Path(__file__).resolve().parents[1] / "VERSION"
    assert version_file.read_text(encoding="utf-8").strip() == TOOL_VERSION


def test_coverage_excludes_not_applicable_from_denominator():
    """N/A core controls are excluded from both numerator and denominator."""
    from auditor.models import Finding

    def finding(check_id: str, status: str) -> Finding:
        return Finding(
            check_id=check_id,
            name=check_id,
            service="Test",
            resource="r",
            status=status,
            severity="INFO",
            current_state=status,
            expected_state="PASS",
        )

    findings = [
        finding("S3-001", "PASS"),
        finding("S3-002", "PASS"),
        finding("S3-003", "NOT_APPLICABLE"),
    ]
    summary = AuditEngine.build_summary(
        findings=findings,
        duration=0.1,
        account_id="123456789012",
        region="eu-central-1",
    )

    assert summary["coverage"]["core_total"] == 10
    assert summary["coverage"]["core_applicable"] == 9
    assert summary["coverage"]["coverage_percent"] == round(2 / 9 * 100, 1)
    assert "S3-003" in summary["coverage"]["core_not_applicable"]
