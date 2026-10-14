from pathlib import Path

from auditor.reporting import render_html


def _make_summary(finding_override=None):
    """Minimal valid summary dict matching the v5 engine output shape."""
    finding = {
        "check_id": "X-001",
        "name": "<script>alert(1)</script>",
        "service": "S3",
        "resource": "bucket",
        "status": "FAIL",
        "severity": "HIGH",
        "current_state": "bad",
        "expected_state": "good",
        "evidence": {"value": "<unsafe>"},
        "why_it_matters": "test",
        "gdpr": [],
        "nis2": [],
        "remediation": ["fix it"],
        "verification": "pass",
        "error": None,
        "security_penalty": 10.0,
        "gdpr_penalty": 0.0,
        "nis2_penalty": 0.0,
    }
    if finding_override:
        finding.update(finding_override)
    return {
        "metadata": {
            "version": "5.0.0",
            "generated_at": "2026-10-01T12:00:00+00:00",
            "account_id": "123456789012",
            "region": "eu-central-1",
        },
        "timing": {"scan_seconds": 1.2},
        "scores": {"security": 70, "gdpr": 68, "nis2": 72},
        "checks": {
            "core_total": 10,
            "core_evaluated": 9,
            "core_check_ids": ["CT-001"],
            "extension_check_ids": [],
            "status_counts": {"PASS": 8, "FAIL": 1, "WARN": 0, "NOT_APPLICABLE": 0, "ERROR": 0},
            "severity_counts": {},
        },
        "coverage": {
            "coverage_percent": 90.0,
            "assessment_confidence": "HIGH",
        },
        "findings": [finding],
        "priority_order": ["X-001 — test (HIGH)"],
    }


def test_report_escapes_html():
    summary = _make_summary()
    output = render_html(summary)
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;" in output


def test_report_contains_account_id():
    summary = _make_summary()
    output = render_html(summary)
    assert "123456789012" in output


def test_report_shows_coverage():
    summary = _make_summary()
    output = render_html(summary)
    assert "90.0%" in output or "90%" in output


def test_report_shows_remediation_impact():
    """A FAIL finding with security_penalty > 0 should show a projected impact line."""
    summary = _make_summary({"security_penalty": 10.0})
    output = render_html(summary)
    assert "Security +10" in output or "Security +10.0" in output
