"""
Shared application runner for the AWS Cloud Security Auditor.

Both the CLI and GUI use this module so audit orchestration exists in one place.
The security-control implementation remains in auditor.engine/checks.py.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import boto3

from auditor.engine import AuditEngine
from auditor.reporting import write_html_report, write_json_report


def run_audit(
    region: str,
    profile: str = "default",
    output_dir: str | Path = "reports",
) -> dict[str, Any]:
    """Run one complete audit and return structured results.

    Parameters
    ----------
    region:
        AWS region to scan.
    profile:
        Existing AWS SDK/CLI profile. Credentials are not accepted or stored here.
    output_dir:
        Directory for generated HTML and JSON reports.

    Returns
    -------
    dict
        Structured result containing findings, summary, report paths,
        account/region metadata, and duration.
    """
    region = region.strip()
    profile = profile.strip() or "default"
    if not region:
        raise ValueError("AWS region cannot be empty.")

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    session = boto3.Session(profile_name=profile, region_name=region)

    # Identity is useful to prove which account was audited without exposing secrets.
    identity = session.client("sts").get_caller_identity()
    account_id = identity.get("Account", "unknown")
    effective_region = session.region_name or region

    engine = AuditEngine(session=session)
    findings = engine.run()
    duration = time.perf_counter() - started
    summary = engine.build_summary(findings, duration, account_id, effective_region)

    json_path = write_json_report(output, summary)
    json_path = write_json_report(output, summary)
    html_path = write_html_report(output, summary)

    return {
        "findings": findings,
        "summary": summary,
        "account_id": account_id,
        "region": effective_region,
        "profile": profile,
        "duration_seconds": duration,
        "html_report": Path(html_path),
        "json_report": Path(json_path),
    }
