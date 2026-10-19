# Complete Guide for Non-Coders (A to Z)

This guide explains how to use the AWS Cloud Security Auditor from scratch — even if you have never used Python or the command line before. Follow each step in order.

**Time needed:** approximately 30–45 minutes the first time.

**What you will have at the end:** an HTML report showing the security health of your AWS account, with clear steps to fix any problems found.

---

## Before you begin

You need:
- A computer running **Windows 10/11**, **macOS**, or **Linux**
- An **AWS account** (see Step 1 if you do not have one)
- An internet connection

You do **not** need any coding knowledge.

---

## Step 1 — Create an AWS account (skip if you already have one)

1. Go to [https://aws.amazon.com](https://aws.amazon.com) and click **Create an AWS Account**.
2. Enter your email address and choose an account name.
3. Follow the sign-up steps. AWS will ask for a credit or debit card — this is for identity verification. Most API calls made by this tool fall within the AWS Free Tier.
4. Once your account is active, sign in to the **AWS Management Console**.

> **Important:** AWS charges for some services. Review [AWS Pricing](https://aws.amazon.com/pricing/) and use a test account where possible.

---

## Step 2 — Create a read-only IAM user for the audit

You should never run this tool using your root AWS account credentials. Instead, create a dedicated read-only user.

1. In the AWS Console, search for **IAM** and open it.
2. Click **Users** in the left menu, then click **Create user**.
3. Enter a username such as `audit-user` and click **Next**.
4. Select **Attach policies directly**.
5. Search for `SecurityAudit` and tick the checkbox next to **SecurityAudit** (AWS managed policy).
6. Click **Next**, then **Create user**.
7. Click on the new user's name, then go to the **Security credentials** tab.
8. Scroll to **Access keys** and click **Create access key**.
9. Select **Command Line Interface (CLI)** and click **Next**, then **Create access key**.
10. **Copy or download the Access Key ID and Secret Access Key now** — you will not be able to see the secret key again.

> **Never share these keys with anyone and never paste them into a chat or email.**

---

## Step 3 — Install Python

### Windows

1. Go to [https://www.python.org/downloads/](https://www.python.org/downloads/)
2. Click the yellow **Download Python 3.x.x** button (any version 3.11 or newer).
3. Run the installer. **Important:** on the first screen, tick the box that says **"Add Python to PATH"** before clicking Install Now.
4. Wait for the installation to finish.
5. To verify, open the **Start menu**, search for **Command Prompt**, and type:
   ```
   python --version
   ```
   You should see something like `Python 3.12.0`.

### macOS

1. Go to [https://www.python.org/downloads/](https://www.python.org/downloads/) and download the macOS installer.
2. Run the `.pkg` file and follow the steps.
3. Open **Terminal** (search for it in Spotlight with `Cmd + Space`) and type:
   ```
   python3 --version
   ```

### Linux (Ubuntu/Debian)

Open a Terminal and run:
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv
```

---

## Step 4 — Download the tool

### Option A — Download as ZIP (easiest, no Git needed)

1. Go to [https://github.com/Shashidhar-Surendra/aws-cloud-security-auditor](https://github.com/Shashidhar-Surendra/aws-cloud-security-auditor)
2. Click the green **Code** button, then click **Download ZIP**.
3. Extract (unzip) the downloaded file to a folder you can find easily, such as your **Desktop** or **Documents**.

### Option B — Clone with Git (if you have Git installed)

```bash
git clone https://github.com/Shashidhar-Surendra/aws-cloud-security-auditor.git
```

---

## Step 5 — Install the AWS CLI

The AWS CLI lets you configure your AWS credentials so the tool can connect to your account.

### Windows

1. Go to [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/) and download the Windows installer.
2. Run the `.msi` installer and follow the steps.
3. Open **Command Prompt** and verify:
   ```
   aws --version
   ```

### macOS

```bash
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

### Linux

```bash
sudo apt-get install awscli
```

---

## Step 6 — Configure your AWS credentials

Open a terminal (Command Prompt on Windows, Terminal on macOS/Linux) and run:

```
aws configure
```

You will be asked four questions:

```
AWS Access Key ID:      [paste the key you copied in Step 2]
AWS Secret Access Key:  [paste the secret key from Step 2]
Default region name:    eu-central-1
Default output format:  json
```

> Replace `eu-central-1` with the AWS region your account uses. Common regions: `eu-west-1`, `us-east-1`, `ap-southeast-1`.

---

## Step 7 — Run the audit

### Windows — easiest method

1. Open the folder where you extracted the tool.
2. Double-click the file called **`run_audit_gui.bat`**.
3. A window will open and guide you through the audit.
4. When asked for a region, type your AWS region (e.g. `eu-central-1`) and press Enter.
5. Press Enter again to use the default profile.
6. Wait for the audit to finish. This usually takes 1–3 minutes.

### macOS / Linux

1. Open Terminal and navigate to the tool folder:
   ```bash
   cd ~/Desktop/aws-cloud-security-auditor
   ```
2. Make the launcher executable (first time only):
   ```bash
   chmod +x run_audit.sh
   ```
3. Run the launcher:
   ```bash
   ./run_audit.sh
   ```
4. Follow the on-screen prompts to enter your region.

### All platforms — command line method

```bash
# Navigate to the tool folder
cd aws-cloud-security-auditor

# Install dependencies (first time only)
pip install -r requirements.txt

# Run the audit
python main.py --region eu-central-1 --output-dir reports
```

---

## Step 8 — Find and open your report

After the audit finishes, reports are saved to the `reports/` folder inside the tool directory.

Look for a file named like:
```
aws_audit_20261015_143022.html
```

To open it:
- **Windows:** double-click the `.html` file — it opens in your web browser.
- **macOS:** double-click the `.html` file, or right-click → Open With → Safari/Chrome.
- **Linux:** right-click → Open With → Firefox/Chrome.

---

## Step 9 — Understand the report

The HTML report contains:

**Scores (top of the page)**
- **Security Score** — overall security posture out of 100
- **GDPR Score** — alignment with GDPR Article 32 requirements
- **NIS2 Score** — alignment with NIS2 Article 21 requirements

**Finding statuses**
| Status | Meaning |
|--------|---------|
| ✅ PASS | The check passed — no issue found |
| ❌ FAIL | A misconfiguration was detected — action recommended |
| ⚠️ WARN | Could not fully evaluate — often a permissions issue |
| 🔴 ENGINE-ERROR | The check could not run — see the error message |

**For each FAIL finding, the report shows:**
- What is wrong
- Why it matters (GDPR/NIS2 context)
- How to fix it (step-by-step in the AWS Console)

To fix findings, follow the [Remediation Guide](REMEDIATION_GUIDE.md).

---

## Step 10 — Re-run to verify fixes

After fixing a finding in the AWS Console, run the tool again:

```
python main.py --region eu-central-1 --output-dir reports
```

A new report will be generated. The finding should now show **PASS**.

---

## Troubleshooting

**"Python was not found"**
- Windows: re-run the Python installer and make sure **"Add Python to PATH"** is ticked.
- macOS/Linux: use `python3` instead of `python`.

**"NoCredentialsError"**
- Run `aws configure` again and re-enter your Access Key ID and Secret Access Key.

**"ProfileNotFound"**
- Press Enter when asked for a profile to use the default, or check that the profile name is correct.

**"AccessDenied" on some checks**
- The IAM user may be missing permissions. Attach the `SecurityAudit` policy as described in Step 2.

**"Could not connect to AWS"**
- Check your internet connection.

---

## Clean up after testing

If you created a test IAM user just for this audit, consider deleting it after you are done:

1. In the AWS Console, open **IAM → Users**.
2. Select the audit user and click **Delete**.
3. Also delete the access key if you no longer need it: go to the user → Security credentials → Access keys → Delete.

This reduces unnecessary access in your AWS account.
