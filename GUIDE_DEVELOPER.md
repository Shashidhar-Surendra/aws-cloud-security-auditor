# Developer Guide

Quick setup for developers comfortable with Python and the command line.

---

## Prerequisites

- Python 3.11 or newer
- AWS CLI installed and configured
- Git (optional)
- An AWS account with a read-only IAM user — see [docs/required-iam-policy.json](required-iam-policy.json)

---

## 1. Get the code

```bash
git clone https://github.com/Shashidhar-Surendra/aws-cloud-security-auditor.git
cd aws-cloud-security-auditor
```

Or download and extract the ZIP from the GitHub releases page.

---

## 2. Create a virtual environment

```bash
python -m venv .venv

# Activate — Linux / macOS
source .venv/bin/activate

# Activate — Windows (Command Prompt)
.venv\Scripts\activate.bat

# Activate — Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

---

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

To install pinned versions for reproducible builds:

```bash
pip install -r requirements-lock.txt
```

---

## 4. Configure AWS credentials

Use a dedicated read-only IAM user — never your root account or admin credentials.

```bash
aws configure --profile audit
```

Or use environment variables:

```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=eu-central-1
```

The minimum IAM permissions are defined in [docs/required-iam-policy.json](required-iam-policy.json).

---

## 5. Run the audit

```bash
# Using the default AWS profile
python main.py --region eu-central-1

# Using a named profile
python main.py --region eu-central-1 --profile audit

# Custom output directory
python main.py --region eu-central-1 --output-dir /tmp/audit-results
```

### CLI arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--region` | None (required) | AWS region, e.g. `eu-central-1` |
| `--profile` | `default` | AWS CLI profile name |
| `--output-dir` | `reports` | Directory for HTML and JSON output |

---

## 6. Report output

Reports are saved to the output directory as:

```
reports/
├── aws_audit_YYYYMMDD_HHMMSS.html   ← Open in a browser
└── aws_audit_YYYYMMDD_HHMMSS.json   ← Machine-readable data
```

The JSON structure contains:

```json
{
  "account_id": "...",
  "region": "...",
  "timestamp": "...",
  "scores": {
    "security": 75.0,
    "gdpr": 80.0,
    "nis2": 80.0
  },
  "findings": [
    {
      "check_id": "S3-001",
      "name": "S3 Public Access Block",
      "status": "FAIL",
      "severity": "CRITICAL",
      "security_penalty": 20.0,
      "gdpr_penalty": 16.0,
      "nis2_penalty": 16.0,
      ...
    }
  ]
}
```

---

## 7. Run the tests

```bash
pytest tests/
```

To see verbose output:

```bash
pytest tests/ -v
```

Tests use mocked AWS responses — no real AWS credentials are needed to run the test suite.

---

## 8. Project structure

```
aws-cloud-security-auditor/
├── main.py               ← CLI entry point
├── launcher_gui.py       ← GUI launcher (tkinter)
├── run_audit_gui.bat     ← Windows double-click launcher
├── run_audit.sh          ← macOS/Linux shell launcher
├── requirements.txt
├── requirements-lock.txt
├── VERSION
├── auditor/
│   ├── checks.py         ← All 10+1 security checks
│   ├── engine.py         ← Orchestrates check execution
│   ├── runner.py         ← Entry point for the audit run
│   ├── scoring.py        ← Score calculation logic
│   ├── compliance.py     ← GDPR/NIS2 mapping
│   ├── reporting.py      ← HTML and JSON report generation
│   └── models.py         ← Finding dataclass
├── tests/
│   ├── conftest.py
│   ├── test_checks.py
│   ├── test_engine.py
│   ├── test_scoring.py
│   ├── test_reporting.py
│   ├── test_runner.py
│   └── test_launchers.py
└── docs/
    └── required-iam-policy.json
```

---

## 9. Scoring methodology

Penalty weights (from `auditor/scoring.py`):

| Severity | Security penalty | GDPR/NIS2 penalty |
|----------|-----------------|-------------------|
| CRITICAL | 20 | 16 (×0.8) |
| HIGH | 10 | 8 (×0.8) |
| MEDIUM | 5 | 4 (×0.8) |
| LOW | 2 | 1.6 (×0.8) |

Each check contributes its penalty at most once, regardless of how many resources fail. Scores are capped at 0–100.

---

## 10. Adding a new check

1. Add a function to `auditor/checks.py` following the existing pattern.
2. Register the check in `auditor/engine.py`.
3. Add a GDPR/NIS2 mapping in `auditor/compliance.py`.
4. Add tests in `tests/test_checks.py`.

The tool is designed to be extended. Keep new checks read-only.
