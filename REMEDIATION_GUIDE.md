# Remediation Guide

This guide explains each finding from the audit report: what it means, why it matters, how to fix it in the AWS Console, and how to verify the fix.

After fixing a finding, re-run the audit to confirm it now shows **PASS**.

---

## How to re-run the audit after a fix

```bash
python main.py --region eu-central-1 --output-dir reports
```

Open the new `.html` report and check that the finding now shows ✅ PASS.

---

## S3-001 — S3 Public Access Block

**What it means:** One or more S3 buckets do not have all four Public Access Block settings enabled. This means the bucket could be made publicly accessible, either now or in the future.

**Why it matters:** A publicly accessible S3 bucket can expose sensitive files (documents, backups, logs, credentials) to anyone on the internet. Under GDPR Article 32, organisations must implement appropriate technical measures to protect personal data. Under NIS2, data availability and confidentiality must be ensured.

**How to fix it:**

1. Open the [AWS S3 Console](https://s3.console.aws.amazon.com/s3/).
2. Click on the bucket that failed.
3. Go to the **Permissions** tab.
4. Under **Block public access (bucket settings)**, click **Edit**.
5. Tick all four checkboxes:
   - Block all public access
   - Block public access granted through new ACLs
   - Block public access granted through any ACLs
   - Block public access granted through new bucket policies
   - Block public access granted through any bucket policies
6. Click **Save changes**.

> ⚠️ If your application intentionally serves public content from S3 (e.g. a static website), do not block public access on that bucket. Review whether the content is intended to be public before making this change.

**Verify:** Re-run the audit. S3-001 should now show PASS.

---

## S3-002 — S3 Default Encryption

**What it means:** One or more S3 buckets do not have a default server-side encryption configuration. Files uploaded without explicit encryption settings will be stored unencrypted.

**Why it matters:** Unencrypted data at rest is a risk if storage media is accessed or stolen. GDPR Article 32 explicitly recommends encryption of personal data as a technical safeguard.

**How to fix it:**

1. Open the [AWS S3 Console](https://s3.console.aws.amazon.com/s3/).
2. Click on the bucket that failed.
3. Go to the **Properties** tab.
4. Scroll to **Default encryption** and click **Edit**.
5. Select **Server-side encryption with Amazon S3 managed keys (SSE-S3)** — this is the simplest option and has no additional cost.
6. Click **Save changes**.

**Verify:** Re-run the audit. S3-002 should now show PASS.

---

## S3-003 — S3 Versioning

**What it means:** One or more S3 buckets do not have versioning enabled. Without versioning, an accidentally deleted or overwritten file cannot be recovered.

**Why it matters:** Versioning protects against accidental data loss and ransomware-style overwrite attacks. GDPR and NIS2 both require measures to ensure data integrity and availability.

**How to fix it:**

1. Open the [AWS S3 Console](https://s3.console.aws.amazon.com/s3/).
2. Click on the bucket that failed.
3. Go to the **Properties** tab.
4. Under **Bucket Versioning**, click **Edit**.
5. Select **Enable** and click **Save changes**.

> ⚠️ Versioning increases storage costs because older versions of files are retained. If cost is a concern, configure an S3 Lifecycle Policy to expire old versions after a set number of days.

**Verify:** Re-run the audit. S3-003 should now show PASS.

---

## IAM-001 — IAM User MFA

**What it means:** One or more IAM users with AWS Console access do not have Multi-Factor Authentication (MFA) enabled. If their password is stolen, an attacker can sign in without any additional barrier.

**Why it matters:** MFA is one of the most effective controls against account compromise. GDPR Article 32 requires appropriate access controls. NIS2 Article 21 mandates multi-factor authentication for access to network and information systems.

**How to fix it:**

1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/).
2. Click **Users** and click on the user that needs MFA.
3. Go to the **Security credentials** tab.
4. Under **Multi-factor authentication (MFA)**, click **Assign MFA device**.
5. Choose **Authenticator app** (e.g. Google Authenticator, Microsoft Authenticator).
6. Follow the steps to scan the QR code with the authenticator app and enter two consecutive codes.
7. Click **Add MFA**.

Repeat for each user that does not have MFA.

**Verify:** Re-run the audit. IAM-001 should now show PASS.

---

## IAM-002 — IAM Password Policy

**What it means:** The account's IAM password policy does not meet minimum strength requirements. Weak passwords are easier to guess or crack.

**Why it matters:** A strong password policy reduces the risk of brute-force and credential-stuffing attacks. This is a basic access control required under both GDPR Article 32 and NIS2 Article 21.

**How to fix it:**

1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/).
2. Click **Account settings** in the left menu.
3. Under **Password policy**, click **Edit**.
4. Configure these minimum settings:
   - Minimum password length: **14** characters
   - Require at least one uppercase letter: ✅
   - Require at least one lowercase letter: ✅
   - Require at least one number: ✅
   - Require at least one non-alphanumeric character: ✅
   - Allow users to change their own password: ✅
   - Enable password expiration: optional (90 days recommended)
5. Click **Save changes**.

**Verify:** Re-run the audit. IAM-002 should now show PASS.

---

## IAM-003 — Excessive Administrator Privileges

**What it means:** One or more IAM users have a policy attached that grants full administrator access (`*:*` on all resources). This violates the principle of least privilege.

**Why it matters:** An account with full admin access can modify or delete any resource in the AWS account. If such an account is compromised, the damage is unrestricted. GDPR and NIS2 both require limiting access to only what is necessary.

**How to fix it:**

1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/).
2. Click **Users** and identify users with the `AdministratorAccess` policy attached.
3. Review whether that user genuinely needs full admin access.
4. If not, click on the user → **Permissions** tab → remove the `AdministratorAccess` policy.
5. Attach a more specific policy that grants only what the user needs (e.g. `SecurityAudit`, `ReadOnlyAccess`, or a custom policy).

> ⚠️ Be careful when removing admin access. Ensure at least one user retains admin access for account management. Do not remove access from your own account without a recovery plan.

**Verify:** Re-run the audit. IAM-003 should now show PASS.

---

## IAM-004 — Root Account MFA

**What it means:** The AWS root account (the account created when you first signed up for AWS) does not have MFA enabled. The root account has unrestricted access to every service and resource.

**Why it matters:** The root account cannot be restricted by IAM policies. If it is compromised, the entire AWS account is at risk. AWS and all major security frameworks strongly recommend enabling MFA on the root account immediately.

**How to fix it:**

1. Sign in to the AWS Console as the **root user** (using the email address you used to create the account).
2. Click on your account name in the top right → **Security credentials**.
3. Under **Multi-factor authentication (MFA)**, click **Assign MFA device**.
4. Choose **Authenticator app** and follow the steps to register it.

> After enabling root MFA, stop using the root account for day-to-day tasks. Create an IAM user with admin access for normal operations.

**Verify:** Re-run the audit. IAM-004 should now show PASS.

---

## EC2-001 — SSH Port Open to the World

**What it means:** One or more EC2 security groups allow inbound traffic on port 22 (SSH) from any IP address (`0.0.0.0/0` or `::/0`). This means anyone on the internet can attempt to connect to your servers via SSH.

**Why it matters:** Open SSH access is one of the most common attack vectors for server compromise. Automated scanners constantly probe for open SSH ports. GDPR and NIS2 both require appropriate network access controls.

**How to fix it:**

1. Open the [AWS EC2 Console](https://console.aws.amazon.com/ec2/).
2. Click **Security Groups** in the left menu.
3. Find the security group with the open SSH rule.
4. Click on the security group → **Inbound rules** tab → **Edit inbound rules**.
5. Find the rule for port 22 with source `0.0.0.0/0` or `::/0`.
6. Change the source to your specific IP address or IP range (e.g. `203.0.113.10/32` for a single IP).
7. Click **Save rules**.

> If you do not know your current IP address, search for "what is my IP" in a browser. Note that home and mobile IP addresses can change — use a VPN with a fixed IP or AWS Systems Manager Session Manager for more robust access.

**Verify:** Re-run the audit. EC2-001 should now show PASS.

---

## EC2-002 — RDP Port Open to the World

**What it means:** One or more EC2 security groups allow inbound traffic on port 3389 (RDP — Remote Desktop Protocol) from any IP address. This means anyone on the internet can attempt to connect to your Windows servers.

**Why it matters:** Open RDP access is a major attack vector for ransomware and credential attacks. Many ransomware incidents begin with an exposed RDP port. This is a CRITICAL finding.

**How to fix it:**

1. Open the [AWS EC2 Console](https://console.aws.amazon.com/ec2/).
2. Click **Security Groups** in the left menu.
3. Find the security group with the open RDP rule.
4. Click on the security group → **Inbound rules** tab → **Edit inbound rules**.
5. Find the rule for port 3389 with source `0.0.0.0/0` or `::/0`.
6. Change the source to your specific IP address (e.g. `203.0.113.10/32`).
7. Click **Save rules**.

**Verify:** Re-run the audit. EC2-002 should now show PASS.

---

## CT-001 — CloudTrail Logging

**What it means:** AWS CloudTrail is not enabled in this region. CloudTrail records all API calls made in your account — who did what, when, and from where.

**Why it matters:** Without CloudTrail, you have no audit trail of activity in your account. If a security incident occurs, you cannot investigate what happened. GDPR Article 32 requires logging for accountability. NIS2 Article 21 requires audit logging.

**How to fix it:**

1. Open the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/).
2. Click **Create trail**.
3. Enter a trail name (e.g. `management-events-trail`).
4. Under **Storage location**, choose or create an S3 bucket for logs.
5. Under **CloudWatch Logs**, enable log delivery to CloudWatch (this also fixes MON-001).
6. Keep **Management events** enabled (Read and Write).
7. Click **Create trail**.

> CloudTrail has a small cost for storing logs in S3. Review [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) for details.

**Verify:** Re-run the audit. CT-001 should now show PASS.

---

## MON-001 — CloudTrail Monitoring Integration

**What it means:** CloudTrail is not sending logs to Amazon CloudWatch Logs. Without this integration, you receive no real-time alerts for suspicious activity.

**Why it matters:** CloudWatch integration enables you to set up alarms for events such as root account login, IAM policy changes, or failed sign-in attempts. NIS2 Article 21 requires active monitoring of security events.

**How to fix it:**

If you already have a CloudTrail trail:

1. Open the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/).
2. Click on your existing trail.
3. Under **CloudWatch Logs**, click **Edit**.
4. Enable **CloudWatch Logs** and select or create a log group (e.g. `CloudTrail/ManagementEvents`).
5. Create or select an IAM role that allows CloudTrail to write to CloudWatch.
6. Click **Save changes**.

If you do not have a trail yet, follow the CT-001 steps above — they include enabling CloudWatch Logs.

**Verify:** Re-run the audit. MON-001 should now show PASS.

---

## After all findings are fixed

Re-run the audit one final time:

```bash
python main.py --region eu-central-1 --output-dir reports
```

A fully remediated account should show scores of **100/100** for Security, GDPR, and NIS2 — or close to it, depending on your specific account configuration.

> Remember: this tool measures a specific set of controls. A score of 100 does not mean your account is fully secure or legally compliant with GDPR or NIS2 — it means you have addressed the checks this tool implements. Use this as a starting point, not a final certification.
