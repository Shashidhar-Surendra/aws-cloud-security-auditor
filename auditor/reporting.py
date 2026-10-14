from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _score_label(score: float) -> str:
    if score >= 80:
        return "GOOD"
    if score >= 60:
        return "MODERATE RISK"
    return "HIGH RISK"


def _score_class(score: float) -> str:
    if score >= 80:
        return "good"
    if score >= 60:
        return "moderate"
    return "high"


def _finding_card(f: dict) -> str:
    status = f["status"]
    if status == "FAIL":
        severity = f["severity"]
    else:
        severity = status

    evidence_items = "".join(
        f"<li><b>{_esc(k)}:</b> {_esc(json.dumps(v, default=str) if isinstance(v, (dict, list)) else v)}</li>"
        for k, v in f.get("evidence", {}).items()
    )

    gdpr = "".join(
        f"<li><b>{_esc(x.get('reference'))}</b> — {_esc(x.get('rationale'))}</li>"
        for x in f.get("gdpr", [])
    ) or "<li>No GDPR mapping configured for this finding.</li>"

    nis2 = "".join(
        f"<li><b>{_esc(x.get('reference'))}</b> — {_esc(x.get('rationale'))}</li>"
        for x in f.get("nis2", [])
    ) or "<li>No NIS2 mapping configured for this finding.</li>"

    remediation = "".join(
        f"<li>{_esc(step)}</li>" for step in f.get("remediation", [])
    ) or "<li>No remediation steps configured.</li>"

    error = (
        f'<div class="warning"><b>Evaluation note:</b> {_esc(f["error"])}</div>'
        if f.get("error") else ""
    )

    return f"""
    <article class="finding">
      <div class="finding-head">
        <div>
          <span class="tag">{_esc(f["check_id"])}</span>
          <h2>{_esc(f["name"])}</h2>
        </div>
        <span class="severity {_esc(severity.lower())}">{_esc(severity)}</span>
      </div>

      <div class="grid">
        <div><b>Status</b><span>{_esc(status)}</span></div>
        <div><b>Service</b><span>{_esc(f["service"])}</span></div>
        <div><b>Resource</b><span>{_esc(f["resource"])}</span></div>
      </div>

      <h3>Current state</h3>
      <p>{_esc(f["current_state"])}</p>

      <h3>Expected state</h3>
      <p>{_esc(f["expected_state"])}</p>

      <h3>Why this matters</h3>
      <p>{_esc(f["why_it_matters"])}</p>

      <h3>Evidence</h3>
      <ul>{evidence_items or "<li>No evidence returned.</li>"}</ul>

      <div class="columns">
        <section>
          <h3>GDPR relevance</h3>
          <ul>{gdpr}</ul>
        </section>
        <section>
          <h3>NIS2 relevance</h3>
          <ul>{nis2}</ul>
        </section>
      </div>

      <h3>How to fix it</h3>
      <ol>{remediation}</ol>

      <h3>Verification</h3>
      <p>{_esc(f.get("verification", ""))}</p>

      {error}
    </article>
    """


def _remediation_impact_row(f: dict) -> str:
    """Render a projected remediation impact line if security_penalty > 0."""
    sp = f.get("security_penalty", 0)
    gp = f.get("gdpr_penalty", 0)
    np_ = f.get("nis2_penalty", 0)
    if sp == 0 and gp == 0 and np_ == 0:
        return ""
    parts = []
    if sp:
        parts.append(f"Security +{sp:.0f}")
    if gp:
        parts.append(f"GDPR +{gp:.0f}")
    if np_:
        parts.append(f"NIS2 +{np_:.0f}")
    return f'<p class="impact">Projected score improvement if remediated: {" | ".join(parts)}</p>'


def render_html(summary: dict) -> str:
    scores = summary["scores"]
    findings = summary["findings"]
    meta = summary["metadata"]
    checks = summary["checks"]
    cov = summary.get("coverage", {})
    failed = [f for f in findings if f["status"] == "FAIL"]
    warned = [f for f in findings if f["status"] == "WARN"]

    # Build finding cards, with impact row per finding
    def _card_with_impact(f: dict) -> str:
        card = _finding_card(f)
        impact = _remediation_impact_row(f)
        if impact:
            # Insert before closing </article>
            card = card.rstrip()
            if card.endswith("</article>"):
                card = card[:-len("</article>")] + impact + "\n    </article>\n"
        return card

    cards = "".join(_card_with_impact(f) for f in findings)
    priority = "".join(
        f"<li>{_esc(x)}</li>" for x in summary.get("priority_order", [])
    ) or "<li>No failed findings.</li>"

    statuses = checks.get("status_counts", {})
    core_eval = checks.get("core_evaluated", "?")
    core_total = checks.get("core_total", 10)
    cov_pct = cov.get("coverage_percent", "?")
    confidence = cov.get("assessment_confidence", "UNKNOWN")

    # Scan statistics block
    ext_ids = checks.get("extension_check_ids", [])
    ext_html = (
        f"<p>Extension check(s) also run: {_esc(', '.join(ext_ids))}</p>"
        if ext_ids else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS Cloud Security Audit</title>
<style>
:root {{
  --bg:#f3f4f6; --panel:#ffffff; --text:#111827; --muted:#6b7280;
  --border:#e5e7eb; --good:#166534; --moderate:#92400e; --high:#991b1b;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font-family:Inter,Arial,sans-serif; }}
.container {{ max-width:1180px; margin:auto; padding:28px 18px 60px; }}
header {{ background:#111827; color:white; border-radius:18px; padding:30px; margin-bottom:18px; }}
header h1 {{ margin:0 0 8px; font-size:30px; }}
header p {{ margin:4px 0; color:#9ca3af; font-size:14px; }}
.muted {{ color:#9ca3af; }}
.score-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin:18px 0; }}
.score {{ background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:22px; }}
.score .name {{ font-size:13px; color:var(--muted); font-weight:700; letter-spacing:.08em; }}
.score .number {{ font-size:38px; font-weight:800; margin:6px 0; }}
.score .label {{ font-weight:800; }}
.score.good .label {{ color:var(--good); }}
.score.moderate .label {{ color:var(--moderate); }}
.score.high .label {{ color:var(--high); }}
.summary {{ background:white; border:1px solid var(--border); border-radius:16px; padding:18px; margin-bottom:18px; }}
.summary h2 {{ margin-top:0; }}
.stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }}
.stat {{ background:#f9fafb; border-radius:10px; padding:12px; text-align:center; }}
.stat .sv {{ font-size:26px; font-weight:800; }}
.stat .sl {{ font-size:12px; color:var(--muted); }}
.columns {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
.finding {{ background:white; border:1px solid var(--border); border-radius:16px; padding:22px; margin:16px 0; }}
.finding-head {{ display:flex; justify-content:space-between; gap:12px; align-items:flex-start; }}
.finding h2 {{ margin:8px 0; }}
.finding h3 {{ font-size:15px; margin-bottom:6px; }}
.tag {{ background:#eef2ff; padding:5px 9px; border-radius:999px; font-size:12px; font-weight:800; }}
.severity {{ padding:7px 11px; border-radius:999px; font-size:12px; font-weight:900; }}
.severity.critical,.severity.high {{ background:#fee2e2; color:#991b1b; }}
.severity.medium {{ background:#ffedd5; color:#9a3412; }}
.severity.low,.severity.info,.severity.pass {{ background:#dcfce7; color:#166534; }}
.severity.warn {{ background:#fef3c7; color:#92400e; }}
.severity.not_applicable {{ background:#f3f4f6; color:#6b7280; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin:14px 0; }}
.grid div {{ background:#f9fafb; border-radius:10px; padding:12px; }}
.grid span {{ display:block; margin-top:4px; color:#374151; word-break:break-word; }}
li {{ margin:5px 0; line-height:1.45; }}
.warning {{ background:#fffbeb; border:1px solid #fcd34d; padding:12px; border-radius:10px; }}
.impact {{ background:#eff6ff; border:1px solid #bfdbfe; padding:10px 14px; border-radius:10px; font-size:14px; }}
.coverage-bar {{ background:#e5e7eb; border-radius:999px; height:10px; margin:6px 0; }}
.coverage-fill {{ background:#2563eb; border-radius:999px; height:10px; }}
footer {{ color:var(--muted); font-size:12px; margin-top:24px; }}
@media(max-width:760px) {{
 .score-grid,.columns,.grid,.stat-grid {{ grid-template-columns:1fr; }}
 .finding-head {{ flex-direction:column; }}
}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>AWS CLOUD SECURITY AUDIT</h1>
  <p>Account: {_esc(meta["account_id"])} &nbsp;·&nbsp; Region: {_esc(meta["region"])}</p>
  <p>Generated: {_esc(meta["generated_at"])} &nbsp;·&nbsp; Duration: {_esc(summary["timing"]["scan_seconds"])} s &nbsp;·&nbsp; Tool v{_esc(meta["version"])}</p>
</header>

<section class="score-grid">
  <div class="score {_score_class(scores["security"])}">
    <div class="name">SECURITY</div>
    <div class="number">{scores["security"]:.0f}/100</div>
    <div class="label">{_score_label(scores["security"])}</div>
  </div>
  <div class="score {_score_class(scores["gdpr"])}">
    <div class="name">GDPR ALIGNMENT INDICATOR</div>
    <div class="number">{scores["gdpr"]:.0f}/100</div>
    <div class="label">{_score_label(scores["gdpr"])}</div>
  </div>
  <div class="score {_score_class(scores["nis2"])}">
    <div class="name">NIS2 ALIGNMENT INDICATOR</div>
    <div class="number">{scores["nis2"]:.0f}/100</div>
    <div class="label">{_score_label(scores["nis2"])}</div>
  </div>
</section>

<section class="summary">
  <h2>Assessment Summary</h2>
  <p>{core_eval} of {core_total} core controls fully evaluated.{ext_html}</p>
  <div class="coverage-bar"><div class="coverage-fill" style="width:{cov_pct}%"></div></div>
  <p>Coverage: <b>{cov_pct}%</b> &nbsp;·&nbsp; Assessment confidence: <b>{_esc(confidence)}</b></p>
  <div class="stat-grid">
    <div class="stat"><div class="sv">{statuses.get("PASS", 0)}</div><div class="sl">PASS</div></div>
    <div class="stat"><div class="sv" style="color:#991b1b">{statuses.get("FAIL", 0)}</div><div class="sl">FAIL</div></div>
    <div class="stat"><div class="sv" style="color:#92400e">{statuses.get("WARN", 0)}</div><div class="sl">WARN</div></div>
    <div class="stat"><div class="sv">{statuses.get("NOT_APPLICABLE", 0)}</div><div class="sl">N/A</div></div>
  </div>
  <p style="font-size:12px;color:var(--muted)">Scores do not certify whole-account security or legal compliance. GDPR/NIS2 values are alignment indicators within this control set only.</p>
</section>

<section class="summary">
  <h2>Fix Priority</h2>
  <ol>{priority}</ol>
</section>

<section>
  <h2>Findings</h2>
  {cards}
</section>

<footer>
  AWS Cloud Security Auditor v{_esc(meta["version"])} &nbsp;·&nbsp;
  Read-only assessment. Results are limited to the configured checks and available AWS permissions.
</footer>
</div>
</body>
</html>
"""


def write_html_report(output_dir: Path, summary: dict) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"aws_audit_{stamp}.html"
    path.write_text(render_html(summary), encoding="utf-8")
    return path


def write_json_report(output_dir: Path, summary: dict) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"aws_audit_{stamp}.json"
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return path
