from pathlib import Path
from unittest.mock import MagicMock, patch

from auditor.runner import run_audit


def test_runner_calls_engine_and_reports(tmp_path):
    fake_summary = {"security_score": 90, "gdpr_score": 92, "nis2_score": 92}
    fake_findings = []
    fake_identity = {"Account": "123456789012"}

    fake_engine = MagicMock()
    fake_engine.run.return_value = fake_findings
    fake_engine.build_summary.return_value = fake_summary

    with patch("auditor.runner.boto3.Session") as session_cls, \
         patch("auditor.runner.AuditEngine", return_value=fake_engine), \
         patch("auditor.runner.write_html_report", return_value=tmp_path / "report.html") as html, \
         patch("auditor.runner.write_json_report", return_value=tmp_path / "report.json") as js:
        session = session_cls.return_value
        session.region_name = "eu-central-1"
        session.client.return_value.get_caller_identity.return_value = fake_identity

        result = run_audit("eu-central-1", "default", tmp_path)

    assert result["account_id"] == "123456789012"
    assert result["summary"] == fake_summary
    assert result["html_report"] == tmp_path / "report.html"
    assert result["json_report"] == tmp_path / "report.json"
    fake_engine.run.assert_called_once()
    fake_engine.build_summary.assert_called_once()


def test_runner_rejects_empty_region():
    import pytest
    with pytest.raises(ValueError):
        run_audit("", "default", Path("reports"))
