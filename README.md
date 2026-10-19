# AWS Cloud Security Auditor

**Version 5.1.0** | Read-only | Python 3.11+ | Windows · macOS · Linux

> A free, open-source tool that scans your AWS account for common security misconfigurations, scores your posture against the CIS AWS Foundations Benchmark v1.5.0, and maps findings to GDPR Article 32 and NIS2 Article 21 obligations. Designed for students, developers, and IT teams at small-to-medium enterprises (SMEs).

---

## What it does

- Runs **10 core security checks** across S3, IAM, EC2, CloudTrail, and CloudWatch
- Produces a **Security Score**, **GDPR Score**, and **NIS2 Score** (each out of 100)
- Generates a **human-readable HTML report** and a machine-readable **JSON report**
- Makes **zero changes** to your AWS account — read-only API calls only
- Explains each finding and provides **step-by-step remediation guidance**

---

## Security checks performed

| Check ID | Service | What it checks |
|----------|---------|----------------|
| S3-001 | S3 | Public access block enabled on all buckets |
| S3-002 | S3 | Default server-side encryption enabled |
| S3-003 | S3 | Versioning enabled on buckets |
| IAM-001 | IAM | MFA enabled for all IAM users with console access |
| IAM-002 | IAM | Password policy meets minimum strength requirements |
| IAM-003 | IAM | No IAM users with excessive administrator privileges |
| IAM-004 | IAM | MFA enabled on the root account |
| EC2-001 | EC2 | No security groups allow SSH (port 22) open to the world |
| EC2-002 | EC2 | No security groups allow RDP (port 3389) open to the world |
| CT-001 | CloudTrail | CloudTrail logging is enabled |
| MON-001 | CloudWatch | CloudTrail is integrated with CloudWatch monitoring |

---

## Choose your path

| I am… | Go to… |
|-------|--------|
| New to coding or AWS | [Non-Coder Guide (A to Z)](docs/GUIDE_NON_CODER.md) |
| Comfortable with Python and CLI | [Developer Guide](docs/GUIDE_DEVELOPER.md) |
| Looking to fix findings | [Remediation Guide](docs/REMEDIATION_GUIDE.md) |

---

## Quick start (developers)

```bash
# 1. Clone the repository
git clone https://github.com/Shashidhar-Surendra/aws-cloud-security-auditor.git
cd aws-cloud-security-auditor

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure AWS credentials (read-only IAM user recommended)
aws configure

# 5. Run the audit
python main.py --region eu-central-1 --output-dir reports

# 6. Open the report
# Reports are saved to:  reports/aws_audit_YYYYMMDD_HHMMSS.html
```

See [docs/required-iam-policy.json](docs/required-iam-policy.json) for the minimum IAM permissions needed.

---

## Report output

After the audit completes, two files are saved to the `reports/` folder:

- `aws_audit_YYYYMMDD_HHMMSS.html` — Open in any web browser. Shows scores, findings, and remediation steps.
- `aws_audit_YYYYMMDD_HHMMSS.json` — Machine-readable data for developers and integrations.

---

## Important limitations

- This tool is an **indicator**, not a certification. Scores reflect the implemented checks only.
- It does **not** guarantee GDPR or NIS2 legal compliance.
- It does **not** modify, remediate, or automatically fix any AWS resource.
- Some checks require specific IAM permissions. If permissions are missing, findings are marked `WARN` or `ENGINE-ERROR` rather than failing silently.
- Always run this tool against a **test or non-production AWS account** first.

---

## AWS costs

This tool makes read-only API calls. Most calls fall within AWS Free Tier limits. However:
- AWS may charge for API calls on some services depending on your account tier.
- Review [AWS Pricing](https://aws.amazon.com/pricing/) before running on a production account.

---

## Credential safety

- **Never share your AWS Access Key or Secret Key** with anyone.
- **Never commit credentials** to Git. The `.gitignore` in this repository blocks common credential files.
- Use a dedicated read-only IAM user for auditing — see [docs/required-iam-policy.json](docs/required-iam-policy.json).

---

## Running tests

```bash
pip install pytest
pytest tests/
```

---

## Project context

This tool was developed as part of an MSc Cybersecurity dissertation at Arden University Berlin (2026), titled:

> *AWS Cloud Security Misconfiguration Auditing Tool with GDPR and NIS2 Compliance Mapping for German SMEs*

---

## License

MIT License — see [LICENSE](LICENSE) for details.
