# AWS Cloud Security Auditor

![CI](https://github.com/YOUR_USERNAME/aws-cloud-security-auditor/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Version](https://img.shields.io/badge/version-5.1.0-green)
![Read-only](https://img.shields.io/badge/AWS-read--only-orange)

A read-only, evidence-based AWS security misconfiguration auditing prototype for the MSc COM7014 project (tool version 5.0.0).

> ⚠️ **Read-only tool. No changes are made to your AWS account.**

---

## Quick Start — choose your path

### 🖥️ Windows users (no coding needed)

1. Install [Python 3.11+](https://python.org) — tick **"Add Python to PATH"** during setup
2. Install dependencies once:
   ```
   pip install -r requirements.txt
   ```
3. Double-click **`run_audit_gui.bat`**
4. Select your AWS region, enter your profile name, click **▶ Run Audit**
5. The HTML report opens automatically when the scan finishes

> First time? See **[AWS Credentials Setup](#aws-credentials-setup)** below.

---

### 🍎🐧 macOS / Linux users (one-command setup)

```bash
chmod +x run_audit.sh
./run_audit.sh
```

The script creates a virtual environment, installs dependencies, asks for your region, runs the audit, and opens the HTML report automatically.

> First time? See **[AWS Credentials Setup](#aws-credentials-setup)** below.

---

### 💻 Developer / CLI

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt

aws configure --profile audit-readonly

python main.py --profile audit-readonly --region eu-central-1
```

Outputs are written to `reports/` by default. Use `--output-dir` to change the folder.

---

## AWS Credentials Setup

1. [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html) in your AWS account
2. Attach the **`AWSSecurityAuditorReadOnly`** policy — copy the JSON from [`docs/required-iam-policy.json`](docs/required-iam-policy.json)
3. Generate an Access Key for that user (IAM → Users → Security credentials)
4. Run `aws configure` and enter your Access Key ID and Secret Access Key:
   ```
   aws configure
   AWS Access Key ID: <paste here>
   AWS Secret Access Key: <paste here>
   Default region name: eu-central-1
   ```

> **Never hard-code credentials in source code.**

---

## Scope

### 10 core checks (COM7014 approved scope)

| Check ID | Control | Severity | Benchmark |
|----------|---------|----------|-----------|
| S3-001 | S3 public access block | CRITICAL | CIS 2.1.5 |
| S3-002 | S3 server-side encryption | HIGH | CIS 2.1.1 |
| S3-003 | S3 versioning | MEDIUM | — |
| IAM-001 | IAM user MFA | HIGH | CIS 1.10 |
| IAM-002 | IAM account password policy | HIGH | CIS 1.8–1.12 |
| IAM-003 | IAM excessive administrator privileges | HIGH | CIS 1.16 |
| EC2-001 | EC2 SSH exposure (port 22) | HIGH | CIS 5.2 |
| EC2-002 | EC2 RDP exposure (port 3389) | HIGH | CIS 5.2 |
| CT-001 | CloudTrail logging | HIGH | CIS 3.1 |
| MON-001 | CloudTrail CloudWatch Logs integration *(provisional)* | MEDIUM | CIS 4.x |

CIS references: CIS AWS Foundations Benchmark v1.5.0.

MON-001 is marked **provisional** because the monitoring control is not fully defined in the approved project scope.

### Additional check (beyond approved scope)

| Check ID | Control | Severity |
|----------|---------|----------|
| IAM-004 | Root account MFA | CRITICAL |

IAM-004 is included as a scope extension. Confirm with your supervisor before including it in the final submission.

### Known scope limitations

- **S3-001** evaluates the four Block Public Access settings only. Bucket-level ACL and bucket-policy analysis is outside scope.
- **CloudTrail** discovers trails in the configured session region only. Cross-region coverage requires a multi-region trail.
- **Scoring** applies each check's penalty at most once, regardless of how many resources fail.

---

## Scoring methodology

| Severity | Security penalty | GDPR indicator | NIS2 indicator |
|----------|-----------------|----------------|----------------|
| CRITICAL | −20 | −16 | −16 |
| HIGH | −10 | −8 | −8 |
| MEDIUM | −5 | −4 | −4 |
| LOW | −2 | −1.6 | −1.6 |
| INFO | 0 | 0 | 0 |

GDPR and NIS2 scores apply an 0.8 multiplier on mapped security penalties.

> **Important:** These scores represent only the controls in this tool. They are not AWS-wide security certification, GDPR compliance certification, or NIS2 compliance certification.

---

## Version and reproducibility

- Tool version: **5.0.0**
- `requirements-lock.txt` pins validated project dependencies
- Controlled experiments must record: Python version, OS/architecture, AWS region, tool version, dependency lock file

## Architecture

```
AWS → collectors/checks → Finding model → risk scoring → compliance mapping → HTML/JSON report
```

## Safety

- Read-only AWS API calls only (14 actions — see `docs/required-iam-policy.json`)
- Never hard-code credentials
- Test only in an AWS account you are authorised to assess
- The tool does not create, modify, or delete any AWS resources

## Before using as the dissertation-final version

This is a strong implementation baseline. Before final submission:
- Verify every AWS API/check against current AWS documentation
- Freeze the exact ten controls with your supervisor
- Verify every GDPR/NIS2 mapping against authoritative sources
- Run the controlled AWS test matrix and record real TP/TN/FP/FN results
- Add the final least-privilege IAM policy after all API calls are frozen


## User Interfaces

### Windows — non-technical users

Double-click `run_audit_gui.bat` to launch the desktop interface.

### macOS/Linux — non-technical users

Run:

```bash
./run_audit.sh
```

The launcher creates the local virtual environment, installs dependencies, asks for the AWS region/profile, and runs the existing CLI.

### Developers

Run the CLI directly:

```bash
python main.py --region eu-central-1 --profile default
```

The GUI and CLI both use `auditor.runner.run_audit()`. The security-control implementation remains in the auditor package.
