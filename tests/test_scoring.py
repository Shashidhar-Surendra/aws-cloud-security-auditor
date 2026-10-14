from auditor.models import Finding
from auditor.scoring import calculate_scores, priority_order


def make_finding(status="FAIL", severity="HIGH"):
    return Finding(
        check_id="TEST-001",
        name="Test",
        service="Test",
        resource="resource",
        status=status,
        severity=severity,
        current_state="bad",
        expected_state="good",
        security_penalty=10 if status == "FAIL" else 0,
        gdpr_penalty=8 if status == "FAIL" else 0,
        nis2_penalty=8 if status == "FAIL" else 0,
    )


def test_failed_high_reduces_scores():
    scores = calculate_scores([make_finding()])
    assert scores == {"security": 90, "gdpr": 92, "nis2": 92}


def test_pass_does_not_reduce_scores():
    scores = calculate_scores([make_finding(status="PASS")])
    assert scores == {"security": 100, "gdpr": 100, "nis2": 100}


def test_priority_orders_high_before_medium():
    high = make_finding(severity="HIGH")
    medium = make_finding(severity="MEDIUM")
    medium.security_penalty = 5
    assert priority_order([medium, high])[0].startswith("TEST-001")


def test_same_check_id_deduplicated_in_scoring():
    """Two failed findings with the same check_id must not double-count the penalty."""
    from auditor.models import Finding

    def s3_fail(resource: str) -> Finding:
        return Finding(
            check_id="S3-001", name="S3 Public Access", service="S3",
            resource=resource, status="FAIL", severity="CRITICAL",
            current_state="open", expected_state="closed",
            security_penalty=20.0, gdpr_penalty=16.0, nis2_penalty=16.0,
        )

    one_bucket = calculate_scores([s3_fail("bucket-a")])
    two_buckets = calculate_scores([s3_fail("bucket-a"), s3_fail("bucket-b")])
    assert one_bucket == two_buckets, (
        "Score should not change when the same check fails on multiple resources"
    )


def test_different_check_ids_both_counted():
    """Two different check IDs that both fail must both contribute to the penalty."""
    from auditor.models import Finding

    def fail(check_id: str, penalty: float) -> Finding:
        return Finding(
            check_id=check_id, name="X", service="X", resource="r",
            status="FAIL", severity="HIGH",
            current_state="bad", expected_state="good",
            security_penalty=penalty, gdpr_penalty=0.0, nis2_penalty=0.0,
        )

    scores = calculate_scores([fail("S3-001", 20.0), fail("EC2-001", 10.0)])
    assert scores["security"] == 70.0


def test_compliance_penalties_use_explicit_multipliers():
    """The configured compliance multipliers match the intended 0.8 methodology."""
    from auditor.scoring import GDPR_MULTIPLIER, NIS2_MULTIPLIER
    assert GDPR_MULTIPLIER == 0.8
    assert NIS2_MULTIPLIER == 0.8


def test_finding_compliance_penalties_apply_configured_multipliers():
    """Finding construction applies the explicit GDPR/NIS2 multipliers."""
    from auditor.checks import _finding
    from auditor.scoring import GDPR_MULTIPLIER, NIS2_MULTIPLIER

    finding = _finding(
        check_id="EC2-001",
        name="Test EC2 SSH Exposure",
        service="EC2",
        resource="sg-test",
        status="FAIL",
        severity="HIGH",
        current_state="open",
        expected_state="restricted",
    )

    assert finding.security_penalty == 10.0
    assert finding.gdpr_penalty == 10.0 * GDPR_MULTIPLIER
    assert finding.nis2_penalty == 10.0 * NIS2_MULTIPLIER
