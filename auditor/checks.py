from __future__ import annotations

import json
from typing import Any

import botocore.exceptions

from .compliance import get_mapping
from .models import Finding
from .scoring import GDPR_MULTIPLIER, NIS2_MULTIPLIER, penalty_for


def _finding(
    *,
    check_id: str,
    name: str,
    service: str,
    resource: str,
    status: str,
    severity: str,
    current_state: str,
    expected_state: str,
    evidence: dict[str, Any] | None = None,
    why: str = "",
    remediation: list[str] | None = None,
    verification: str = "",
    error: str | None = None,
) -> Finding:
    gdpr, nis2 = get_mapping(check_id)
    base = penalty_for(severity) if status == "FAIL" else 0.0

    # Separate compliance indicators: only findings with an explicit mapping
    # contribute to those indicators.
    gdpr_penalty = base * GDPR_MULTIPLIER if gdpr and status == "FAIL" else 0.0
    nis2_penalty = base * NIS2_MULTIPLIER if nis2 and status == "FAIL" else 0.0

    return Finding(
        check_id=check_id,
        name=name,
        service=service,
        resource=resource,
        status=status,
        severity=severity,
        current_state=current_state,
        expected_state=expected_state,
        evidence=evidence or {},
        why_it_matters=why,
        gdpr=gdpr,
        nis2=nis2,
        remediation=remediation or [],
        verification=verification,
        security_penalty=base,
        gdpr_penalty=gdpr_penalty,
        nis2_penalty=nis2_penalty,
        error=error,
    )


def _error_finding(check_id: str, name: str, service: str, error: Exception) -> Finding:
    return _finding(
        check_id=check_id,
        name=name,
        service=service,
        resource="N/A",
        status="WARN",
        severity="INFO",
        current_state="Control could not be evaluated.",
        expected_state="Control evaluated successfully.",
        evidence={"error_type": type(error).__name__},
        why="The scanner could not safely determine the control state.",
        remediation=["Review the required read-only AWS permissions and retry the audit."],
        verification="Re-run the audit after the required permission is available.",
        error=str(error),
    )


def check_s3_public_access(s3) -> list[Finding]:
    """S3-001: Verify that the four S3 Block Public Access settings are enabled per bucket.

    Scope note: this check evaluates the four Block Public Access controls only
    (BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets).
    Bucket-level ACL and resource-based bucket-policy analysis is outside the
    defined scope of this tool and this check.  This limitation must be stated
    in the dissertation.
    """
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        return [_finding(
            check_id="S3-001", name="S3 Public Access Block", service="S3",
            resource="AWS account", status="NOT_APPLICABLE", severity="INFO",
            current_state="No S3 buckets exist in the assessed account.",
            expected_state="All S3 buckets have the four Block Public Access controls enabled.",
            evidence={"bucket_count": 0},
        )]
    for bucket in buckets:
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            expected_keys = [
                "BlockPublicAcls",
                "BlockPublicPolicy",
                "IgnorePublicAcls",
                "RestrictPublicBuckets",
            ]
            bad = [k for k in expected_keys if cfg.get(k) is not True]
            if bad:
                findings.append(_finding(
                    check_id="S3-001",
                    name="S3 Public Access",
                    service="S3",
                    resource=name,
                    status="FAIL",
                    severity="CRITICAL",
                    current_state=f"Public access block controls not fully enabled: {', '.join(bad)}",
                    expected_state="All four S3 Block Public Access controls enabled.",
                    evidence={"public_access_block": cfg, "failed_controls": bad},
                    why="Publicly accessible object storage can expose cloud data to unintended parties.",
                    remediation=[
                        "Open Amazon S3 and select the affected bucket.",
                        "Open Permissions and review Block Public Access.",
                        "Enable the required public-access blocking controls.",
                        "Review bucket policies/ACLs for unintended public access.",
                        "Re-run the audit and confirm PASS.",
                    ],
                    verification=(
                        "All four S3 Block Public Access controls evaluate to true. "
                        "Bucket-policy and ACL exposure requires separate review because it is outside this check's scope."
                    ),
                ))
            else:
                findings.append(_finding(
                    check_id="S3-001", name="S3 Public Access", service="S3",
                    resource=name, status="PASS", severity="INFO",
                    current_state="All four Block Public Access controls are enabled.",
                    expected_state="All four controls enabled.",
                    evidence={"public_access_block": cfg},
                ))
        except botocore.exceptions.ClientError as exc:
            findings.append(_error_finding("S3-001", "S3 Public Access", "S3", exc))
    return findings


def check_s3_encryption(s3) -> list[Finding]:
    """S3-002: Verify that a default server-side encryption configuration is set per bucket.

    Scope note: this check evaluates the bucket-level default SSE configuration only.
    It does not evaluate whether individual objects are actually encrypted (object-level
    encryption status requires per-object API calls and is outside this tool's scope).
    The distinction between 'default encryption configured' and 'all objects encrypted'
    must be stated in the dissertation.

    As of January 2023, AWS applies AES-256 encryption to all new objects by default even
    without an explicit bucket configuration; however, CIS AWS Foundations Benchmark v1.5.0
    still recommends an explicit configuration be present (CIS 2.1.1).
    """
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        return [_finding(
            check_id="S3-002", name="S3 Default Server-Side Encryption Configuration", service="S3",
            resource="AWS account", status="NOT_APPLICABLE", severity="INFO",
            current_state="No S3 buckets exist in the assessed account.",
            expected_state="All S3 buckets have a default server-side encryption configuration.",
            evidence={"bucket_count": 0},
        )]
    for bucket in buckets:
        name = bucket["Name"]
        try:
            enc = s3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration", {})
            rules = enc.get("Rules", [])
            algorithms = []
            for rule in rules:
                default = rule.get("ApplyServerSideEncryptionByDefault", {})
                if default.get("SSEAlgorithm"):
                    algorithms.append(default["SSEAlgorithm"])
            enabled = bool(algorithms)
            findings.append(_finding(
                check_id="S3-002",
                name="S3 Default Server-Side Encryption Configuration",
                service="S3", resource=name,
                status="PASS" if enabled else "FAIL",
                severity="INFO" if enabled else "HIGH",
                current_state=(
                    f"Default SSE configuration present with algorithm(s): {algorithms}"
                    if enabled
                    else "No explicit default server-side encryption configuration detected."
                ),
                expected_state=(
                    "An explicit default server-side encryption configuration is present "
                    "(CIS AWS Foundations Benchmark v1.5.0, CIS 2.1.1)."
                ),
                evidence={"algorithms": algorithms, "raw_rule_count": len(rules)},
                why=(
                    "An explicit default encryption configuration reduces reliance on implicit "
                    "AWS defaults and provides a documented control for audit purposes."
                ),
                remediation=[
                    "Open S3 and select the affected bucket.",
                    "Open Properties → Default encryption.",
                    "Enable an appropriate server-side encryption option (SSE-S3 or SSE-KMS).",
                    "Save and re-run the audit.",
                ],
                verification=(
                    "get_bucket_encryption returns a ServerSideEncryptionConfiguration with "
                    "at least one rule containing a valid SSEAlgorithm."
                ),
            ))
        except botocore.exceptions.ClientError as exc:
            # Some AWS accounts/buckets return an error when no encryption
            # configuration exists; treat that as a detectable FAIL, not a crash.
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"}:
                findings.append(_finding(
                    check_id="S3-002",
                    name="S3 Default Server-Side Encryption Configuration",
                    service="S3", resource=name,
                    status="FAIL", severity="HIGH",
                    current_state="No default server-side encryption configuration detected.",
                    expected_state=(
                        "An explicit default server-side encryption configuration is present "
                        "(CIS AWS Foundations Benchmark v1.5.0, CIS 2.1.1)."
                    ),
                    evidence={"aws_error_code": code},
                    why=(
                        "An explicit default encryption configuration reduces reliance on implicit "
                        "AWS defaults and provides a documented control for audit purposes."
                    ),
                    remediation=[
                        "Open S3 → affected bucket → Properties → Default encryption.",
                        "Enable an appropriate server-side encryption option.",
                        "Re-run the audit.",
                    ],
                    verification=(
                        "get_bucket_encryption returns a ServerSideEncryptionConfiguration with "
                        "at least one rule containing a valid SSEAlgorithm."
                    ),
                ))
            else:
                findings.append(_error_finding("S3-002", "S3 Default Server-Side Encryption Configuration", "S3", exc))
    return findings


def check_s3_versioning(s3) -> list[Finding]:
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        return [_finding(
            check_id="S3-003", name="S3 Versioning", service="S3",
            resource="AWS account", status="NOT_APPLICABLE", severity="INFO",
            current_state="No S3 buckets exist in the assessed account.",
            expected_state="All S3 buckets have versioning enabled.",
            evidence={"bucket_count": 0},
        )]
    for bucket in buckets:
        name = bucket["Name"]
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            status = v.get("Status")
            enabled = status == "Enabled"
            findings.append(_finding(
                check_id="S3-003", name="S3 Versioning", service="S3", resource=name,
                status="PASS" if enabled else "FAIL",
                severity="INFO" if enabled else "MEDIUM",
                current_state=f"Versioning status: {status or 'Disabled/Not configured'}",
                expected_state="Versioning enabled.",
                evidence={"versioning": v},
                why="Versioning can support recovery from accidental or malicious object changes.",
                remediation=[
                    "Open S3 and select the affected bucket.",
                    "Open Properties → Bucket Versioning.",
                    "Enable versioning.",
                    "Re-run the audit.",
                ],
                verification="Bucket versioning status equals Enabled.",
            ))
        except botocore.exceptions.ClientError as exc:
            findings.append(_error_finding("S3-003", "S3 Versioning", "S3", exc))
    return findings


def check_iam_root_mfa(iam) -> list[Finding]:
    """IAM-004: Check that MFA is enabled on the AWS root account."""
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        mfa_enabled = summary.get("AccountMFAEnabled", 0)
        return [_finding(
            check_id="IAM-004",
            name="Root Account MFA",
            service="IAM",
            resource="AWS root account",
            status="PASS" if mfa_enabled else "FAIL",
            severity="INFO" if mfa_enabled else "CRITICAL",
            current_state=f"Root account MFA enabled: {'Yes' if mfa_enabled else 'No'}",
            expected_state="MFA device configured on the AWS root account.",
            evidence={"AccountMFAEnabled": mfa_enabled},
            why=(
                "The root account has unrestricted access to every AWS resource and cannot be "
                "restricted by IAM policies. Without MFA, a compromised root password gives an "
                "attacker complete and irrevocable account control."
            ),
            remediation=[
                "Sign in to the AWS Management Console as the root user.",
                "Open 'My Security Credentials' from the account menu.",
                "Under 'Multi-factor authentication (MFA)', choose 'Activate MFA'.",
                "Use a hardware MFA key or authenticator app.",
                "Do not store the root credentials alongside other account credentials.",
                "Re-run the audit to confirm PASS.",
            ],
            verification="AccountMFAEnabled equals 1 in the IAM account summary.",
        )]
    except botocore.exceptions.ClientError as exc:
        return [_error_finding("IAM-004", "Root Account MFA", "IAM", exc)]


def check_iam_mfa(iam) -> list[Finding]:
    """IAM-001: Check that all IAM users with console/password access have MFA enabled.

    Scope: evaluates only users with a console login profile (password-based authentication).
    Purely programmatic users (access keys only, no login profile) are excluded because
    MFA cannot be enforced on API key usage in the same way.

    Status logic per user:
      PASS           — console user with at least one MFA device.
      FAIL           — console user with no MFA device.
      NOT_APPLICABLE — user has no login profile (programmatic-only).
      WARN           — cannot determine login profile status (AccessDenied on GetLoginProfile).
    """
    findings = []
    paginator = iam.get_paginator("list_users")
    users = [u for page in paginator.paginate() for u in page.get("Users", [])]

    if not users:
        return [_finding(
            check_id="IAM-001", name="IAM User MFA", service="IAM",
            resource="AWS account", status="NOT_APPLICABLE", severity="INFO",
            current_state="No IAM users found in the assessed account.",
            expected_state="All console-access IAM users have MFA enabled.",
            evidence={"user_count": 0},
        )]

    for user in users:
        username = user["UserName"]
        try:
            # Determine whether this user has console/password access.
            # get_login_profile raises NoSuchEntity if no password is configured.
            try:
                iam.get_login_profile(UserName=username)
                has_console = True
            except botocore.exceptions.ClientError as lp_exc:
                lp_code = lp_exc.response.get("Error", {}).get("Code", "")
                if lp_code == "NoSuchEntity":
                    has_console = False
                elif lp_code in {"AccessDenied", "AccessDeniedException"}:
                    # Cannot determine — report WARN rather than assume safe.
                    findings.append(_finding(
                        check_id="IAM-001", name="IAM User MFA", service="IAM",
                        resource=username, status="WARN", severity="HIGH",
                        current_state="Could not determine whether the user has a console login profile (AccessDenied on GetLoginProfile).",
                        expected_state="Console-access IAM users have MFA enabled.",
                        evidence={"error": lp_code},
                        why="MFA adds an additional authentication factor and can reduce account-compromise risk.",
                        remediation=["Grant the audit role iam:GetLoginProfile and re-run the audit."],
                        verification="User login profile status is determinable and MFA is configured if applicable.",
                    ))
                    continue
                else:
                    raise  # unexpected error — bubble up to outer except

            if not has_console:
                findings.append(_finding(
                    check_id="IAM-001", name="IAM User MFA", service="IAM",
                    resource=username, status="NOT_APPLICABLE", severity="INFO",
                    current_state="User has no IAM console login profile; MFA check does not apply.",
                    expected_state="Programmatic-only users are excluded from this control.",
                    evidence={"has_console_login": False},
                ))
                continue

            mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            enabled = len(mfa) > 0
            findings.append(_finding(
                check_id="IAM-001", name="IAM User MFA", service="IAM", resource=username,
                status="PASS" if enabled else "FAIL",
                severity="INFO" if enabled else "HIGH",
                current_state=f"MFA devices attached: {len(mfa)}",
                expected_state="At least one MFA device configured for this console-access IAM user.",
                evidence={"mfa_device_count": len(mfa), "has_console_login": True},
                why="MFA adds an additional authentication factor and can reduce account-compromise risk.",
                remediation=[
                    "Open IAM and select the affected user.",
                    "Open Security credentials.",
                    "Assign an appropriate MFA device.",
                    "Re-run the audit.",
                ],
                verification="At least one MFA device is returned for the user.",
            ))
        except botocore.exceptions.ClientError as exc:
            findings.append(_error_finding("IAM-001", "IAM User MFA", "IAM", exc))
    return findings


def check_iam_password_policy(iam) -> list[Finding]:
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except botocore.exceptions.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            return [_finding(
                check_id="IAM-002", name="IAM Password Policy", service="IAM",
                resource="AWS account", status="FAIL", severity="HIGH",
                current_state="No account password policy detected.",
                expected_state="A documented strong account password policy.",
                evidence={"aws_error_code": code},
                why="A weak or absent password policy can increase the risk of compromised IAM passwords.",
                remediation=[
                    "Open IAM → Account settings → Password policy.",
                    "Configure a strong password policy appropriate to the environment.",
                    "Re-run the audit.",
                ],
                verification="AWS returns a configured account password policy.",
            )]
        return [_error_finding("IAM-002", "IAM Password Policy", "IAM", exc)]

    # Thresholds are taken from CIS AWS Foundations Benchmark v1.5.0, section 1:
    #   CIS 1.8  — Minimum password length >= 14
    #   CIS 1.9  — Require at least one uppercase letter
    #   CIS 1.10 — Require at least one lowercase letter
    #   CIS 1.11 — Require at least one symbol
    #   CIS 1.12 — Require at least one number
    # These thresholds must be cited in the dissertation methodology chapter
    # and cross-referenced against the approved project benchmark.
    requirements = {
        "MinimumPasswordLength": 14,    # CIS 1.8
        "RequireSymbols": True,         # CIS 1.11
        "RequireNumbers": True,         # CIS 1.12
        "RequireUppercaseCharacters": True,  # CIS 1.9
        "RequireLowercaseCharacters": True,  # CIS 1.10
    }
    failed = {
        k: {"expected": v, "actual": policy.get(k)}
        for k, v in requirements.items()
        if policy.get(k) != v and not (
            isinstance(v, int) and isinstance(policy.get(k), int) and policy.get(k, 0) >= v
        )
    }
    return [_finding(
        check_id="IAM-002", name="IAM Password Policy", service="IAM",
        resource="AWS account", status="FAIL" if failed else "PASS",
        severity="HIGH" if failed else "INFO",
        current_state=json.dumps(policy, default=str),
        expected_state=(
            "Password policy meets CIS AWS Foundations Benchmark v1.5.0 thresholds: "
            "minimum 14 characters (CIS 1.8), uppercase (1.9), lowercase (1.10), "
            "symbol (1.11), number (1.12)."
        ),
        evidence={
            "password_policy": policy,
            "failed_requirements": failed,
            "benchmark": "CIS AWS Foundations Benchmark v1.5.0, section 1",
        },
        why="Password-policy weaknesses can increase the risk of account compromise where password-based IAM authentication is used.",
        remediation=[
            "Open IAM → Account settings → Password policy.",
            "Configure the password policy to meet CIS AWS Foundations Benchmark v1.5.0 thresholds.",
            "Minimum 14 characters, require uppercase, lowercase, numbers, and symbols.",
            "Re-run the audit.",
        ],
        verification="All defined CIS 1.8–1.12 password-policy requirements are satisfied.",
    )]


def _statement_is_admin(statement: dict[str, Any]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = statement.get("Action", [])
    resources = statement.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


def _policy_document(iam, policy_arn: str) -> dict[str, Any]:
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy["DefaultVersionId"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    doc = version["PolicyVersion"]["Document"]
    # boto3 normally returns a decoded dict, but handle string safely.
    if isinstance(doc, str):
        import urllib.parse
        doc = json.loads(urllib.parse.unquote(doc))
    return doc


def check_iam_admin_privileges(iam) -> list[Finding]:
    """IAM-003: Detect directly-attached or inline IAM user policies that grant Action='*'/Resource='*'.

    Scope: evaluates inline and directly attached managed policies on IAM users only.
    Group-derived and role-derived privilege paths are outside the current implementation
    scope and must be stated as a limitation in the dissertation.

    Status logic:
      FAIL — at least one inspected policy confirms wildcard admin-style permission.
      WARN — no confirmed admin policy, but at least one policy could not be inspected
             (e.g. AccessDenied on GetPolicyVersion).  Cannot safely report PASS.
      PASS — all relevant policies successfully inspected and no wildcard admin found.
    """
    findings = []
    paginator = iam.get_paginator("list_users")
    users = [u for page in paginator.paginate() for u in page.get("Users", [])]

    if not users:
        return [_finding(
            check_id="IAM-003", name="IAM Excessive Administrator Privileges",
            service="IAM", resource="AWS account",
            status="NOT_APPLICABLE", severity="INFO",
            current_state="No IAM users found in the assessed account.",
            expected_state="IAM users receive only the permissions required for their role.",
            evidence={"user_count": 0},
        )]

    for user in users:
        username = user["UserName"]
        confirmed_admin: list[str] = []
        uninspectable: list[str] = []

        try:
            inline_paginator = iam.get_paginator("list_user_policies")
            for page in inline_paginator.paginate(UserName=username):
                for p in page.get("PolicyNames", []):
                    try:
                        doc = iam.get_user_policy(UserName=username, PolicyName=p)["PolicyDocument"]
                        if isinstance(doc, str):
                            import urllib.parse
                            doc = json.loads(urllib.parse.unquote(doc))
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        if any(_statement_is_admin(s) for s in statements):
                            confirmed_admin.append(f"inline:{p}")
                    except botocore.exceptions.ClientError:
                        uninspectable.append(f"inline:{p}")

            attached_paginator = iam.get_paginator("list_attached_user_policies")
            for page in attached_paginator.paginate(UserName=username):
                for p in page.get("AttachedPolicies", []):
                    try:
                        doc = _policy_document(iam, p["PolicyArn"])
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        if any(_statement_is_admin(s) for s in statements):
                            confirmed_admin.append(f"attached:{p['PolicyArn']}")
                    except botocore.exceptions.ClientError:
                        uninspectable.append(f"attached:{p['PolicyArn']}")

            # Determine status — uninspectable policies must never silently become PASS.
            if confirmed_admin:
                status, severity = "FAIL", "HIGH"
                current = f"Confirmed wildcard admin-style policies: {confirmed_admin}"
                if uninspectable:
                    current += f"; additionally {len(uninspectable)} policy/ies could not be inspected."
            elif uninspectable:
                status, severity = "WARN", "HIGH"
                current = (
                    f"No confirmed admin policy, but {len(uninspectable)} policy/ies could not be inspected "
                    f"and cannot be ruled out: {uninspectable}"
                )
            else:
                status, severity = "PASS", "INFO"
                current = "All inspected policies: no wildcard admin-style permission detected."

            findings.append(_finding(
                check_id="IAM-003", name="IAM Excessive Administrator Privileges",
                service="IAM", resource=username, status=status, severity=severity,
                current_state=current,
                expected_state="Users receive only the permissions required for their role (least privilege).",
                evidence={
                    "confirmed_admin_policies": confirmed_admin,
                    "uninspectable_policies": uninspectable,
                    "scope_note": (
                        "Evaluates inline and directly attached user policies only. "
                        "Group-derived and role-derived privilege paths are outside this check's scope."
                    ),
                },
                why="Broad administrator permissions increase the potential impact of credential compromise or misuse.",
                remediation=[
                    "Review the confirmed wildcard policy statements listed in the evidence.",
                    "Replace Action='*' and Resource='*' with least-privilege permissions for the user's role.",
                    "Separate administrative duties where appropriate.",
                    "For uninspectable policies: obtain the required read permissions and re-run.",
                    "Re-run the audit to confirm PASS.",
                ],
                verification=(
                    "No inline or directly attached wildcard admin-style policy is detected. "
                    "No policy is uninspectable."
                ),
            ))
        except botocore.exceptions.ClientError as exc:
            findings.append(_error_finding("IAM-003", "IAM Excessive Administrator Privileges", "IAM", exc))

    return findings


def _check_open_port(sg, port: int, check_id: str, name: str) -> list[Finding]:
    findings = []
    paginator = sg.get_paginator("describe_security_groups")
    groups = []
    for page in paginator.paginate():
        groups.extend(page.get("SecurityGroups", []))
    for group in groups:
        group_id = group["GroupId"]
        for perm in group.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            protocol = perm.get("IpProtocol")
            port_matches = (
                protocol == "-1"
                or (
                    from_port is not None
                    and to_port is not None
                    and from_port <= port <= to_port
                )
            )
            public_ipv4 = [
                r.get("CidrIp")
                for r in perm.get("IpRanges", [])
                if r.get("CidrIp") == "0.0.0.0/0"
            ]
            public_ipv6 = [
                r.get("CidrIpv6")
                for r in perm.get("Ipv6Ranges", [])
                if r.get("CidrIpv6") == "::/0"
            ]
            if port_matches and (public_ipv4 or public_ipv6):
                    findings.append(_finding(
                        check_id=check_id, name=name, service="EC2",
                        resource=group_id, status="FAIL", severity="HIGH",
                        current_state=f"Security group permits public access affecting port {port}.",
                        expected_state=f"Port {port} should not be open to 0.0.0.0/0 unless explicitly justified.",
                        evidence={"security_group": group_id, "permission": perm},
                        why=f"Internet-exposed remote administration ports can increase attack surface.",
                        remediation=[
                            f"Open EC2 → Security Groups → {group_id}.",
                            f"Review inbound rules affecting port {port}.",
                            "Restrict the source CIDR to trusted networks or remove the rule if unnecessary.",
                            "Re-run the audit.",
                        ],
                        verification=f"No inbound rule exposing port {port} to 0.0.0.0/0 remains.",
                    ))
    if not findings:
        findings.append(_finding(
            check_id=check_id, name=name, service="EC2", resource="all security groups",
            status="PASS", severity="INFO",
            current_state=f"No tested security group exposes port {port} to 0.0.0.0/0.",
            expected_state=f"Port {port} not publicly exposed.",
            evidence={"port": port},
        ))
    return findings


def check_ec2_ssh(ec2) -> list[Finding]:
    return _check_open_port(ec2, 22, "EC2-001", "EC2 SSH Exposure")


def check_ec2_rdp(ec2) -> list[Finding]:
    return _check_open_port(ec2, 3389, "EC2-002", "EC2 RDP Exposure")


def check_cloudtrail(cloudtrail) -> list[Finding]:
    """CT-001: Check that at least one CloudTrail trail is actively logging.

    Region scope: describe_trails(includeShadowTrails=False) returns only trails
    created in the session's configured region.  Multi-region trail coverage is
    evaluated by the IsMultiRegionTrail field in the evidence, but this check
    does not require a multi-region trail.  The region scope must be documented
    in the dissertation methodology.
    """
    findings = []
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            return [_finding(
                check_id="CT-001", name="CloudTrail Logging", service="CloudTrail",
                resource="AWS account", status="FAIL", severity="HIGH",
                current_state="No CloudTrail trail detected.",
                expected_state="At least one appropriate CloudTrail trail exists and is logging.",
                evidence={"trail_count": 0},
                why="Without suitable audit logging, investigation and detection of account activity can be impaired.",
                remediation=[
                    "Open AWS CloudTrail.",
                    "Create or review an appropriate trail.",
                    "Enable logging for the required regions/resources according to the project requirements.",
                    "Re-run the audit.",
                ],
                verification="At least one discovered trail has logging enabled.",
            )]

        statuses = []
        for trail in trails:
            arn = trail.get("TrailARN")
            name = trail.get("Name")
            status = cloudtrail.get_trail_status(Name=arn or name)
            statuses.append({
                "name": name,
                "arn": arn,
                "is_logging": status.get("IsLogging", False),
                "is_multi_region": trail.get("IsMultiRegionTrail", False),
            })

        logging_trails = [x for x in statuses if x["is_logging"]]
        if logging_trails:
            findings.append(_finding(
                check_id="CT-001", name="CloudTrail Logging", service="CloudTrail",
                resource="AWS account", status="PASS", severity="INFO",
                current_state=f"{len(logging_trails)} discovered trail(s) currently logging.",
                expected_state="At least one appropriate CloudTrail trail actively logging.",
                evidence={"trails": statuses},
            ))
        else:
            findings.append(_finding(
                check_id="CT-001", name="CloudTrail Logging", service="CloudTrail",
                resource="AWS account", status="FAIL", severity="HIGH",
                current_state="CloudTrail trails were discovered but none reported IsLogging=true.",
                expected_state="At least one appropriate trail actively logging.",
                evidence={"trails": statuses},
                why="Without active audit logging, investigation and detection of account activity can be impaired.",
                remediation=[
                    "Open AWS CloudTrail and inspect the discovered trails.",
                    "Enable logging for the appropriate trail.",
                    "Re-run the audit.",
                ],
                verification="At least one appropriate trail returns IsLogging=true.",
            ))
    except botocore.exceptions.ClientError as exc:
        findings.append(_error_finding("CT-001", "CloudTrail Logging", "CloudTrail", exc))
    return findings


def check_monitoring(cloudtrail) -> list[Finding]:
    """MON-001: Verify that at least one actively logging CloudTrail trail has
    CloudWatch Logs integration configured.

    Control definition (CIS AWS Foundations Benchmark v1.5.0, section 4):
    PASS          — at least one trail satisfies ALL of:
                    (a) IsLogging = true, AND
                    (b) CloudWatchLogsLogGroupArn is non-empty.
    FAIL          — trails exist but none satisfies both conditions.
    NOT_APPLICABLE — no trails exist in the assessed region (CT-001 already covers this).
    WARN          — API call to describe_trails or get_trail_status was partially denied.

    Rationale for control selection: CIS 4.x recommends that CloudTrail trails
    deliver events to CloudWatch Logs to enable near-real-time alerting and
    centralised log storage. This is a foundational monitoring capability for
    incident detection in cloud environments (NIST SP 800-53 AU-6).
    """
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            return [_finding(
                check_id="MON-001", name="CloudTrail Monitoring Integration",
                service="Monitoring", resource="AWS account",
                status="NOT_APPLICABLE", severity="INFO",
                current_state="No CloudTrail trails exist in the assessed region; monitoring integration cannot be evaluated.",
                expected_state="At least one actively logging trail with CloudWatch Logs integration configured.",
                evidence={"trail_count": 0,
                          "note": "CT-001 covers the absence of trails. MON-001 is NOT_APPLICABLE when no trails exist."},
            )]

        configured = []
        for trail in trails:
            trail_name = trail.get("Name")
            arn = trail.get("TrailARN")
            status = cloudtrail.get_trail_status(Name=arn or trail_name)
            configured.append({
                "name": trail_name,
                "arn": arn,
                "is_logging": status.get("IsLogging", False),
                "cloudwatch_log_group_arn": trail.get("CloudWatchLogsLogGroupArn") or None,
                "is_multi_region": trail.get("IsMultiRegionTrail", False),
            })

        # PASS: at least one trail is logging AND has CWL integration.
        qualifying = [
            x for x in configured
            if x["is_logging"] and x["cloudwatch_log_group_arn"]
        ]
        if qualifying:
            return [_finding(
                check_id="MON-001", name="CloudTrail Monitoring Integration",
                service="Monitoring", resource="AWS account", status="PASS",
                severity="INFO",
                current_state=(
                    f"{len(qualifying)} of {len(configured)} discovered trail(s) are actively logging "
                    f"with CloudWatch Logs integration configured."
                ),
                expected_state=(
                    "At least one actively logging trail has CloudWatch Logs integration configured "
                    "(CIS AWS Foundations Benchmark v1.5.0, section 4)."
                ),
                evidence={"trails": configured, "qualifying_trails": [x["name"] for x in qualifying]},
            )]

        # FAIL: trails exist but none qualifies.
        return [_finding(
            check_id="MON-001", name="CloudTrail Monitoring Integration",
            service="Monitoring", resource="AWS account", status="FAIL",
            severity="MEDIUM",
            current_state=(
                "No actively logging trail with CloudWatch Logs integration was detected. "
                f"Trails evaluated: {[x['name'] for x in configured]}."
            ),
            expected_state=(
                "At least one actively logging trail has CloudWatch Logs integration configured "
                "(CIS AWS Foundations Benchmark v1.5.0, section 4)."
            ),
            evidence={"trails": configured},
            why=(
                "Without CloudWatch Logs integration, CloudTrail events are not available for "
                "near-real-time alerting and centralised security monitoring. This can delay "
                "detection of unauthorised activity."
            ),
            remediation=[
                "Open AWS CloudTrail and select the appropriate trail.",
                "Under 'CloudWatch Logs', configure a log group and an appropriate IAM role.",
                "Verify that log delivery is active in CloudWatch Logs.",
                "Re-run the audit.",
            ],
            verification=(
                "get_trail_status returns IsLogging=true and the trail has a "
                "non-empty CloudWatchLogsLogGroupArn."
            ),
        )]
    except botocore.exceptions.ClientError as exc:
        return [_error_finding("MON-001", "CloudTrail Monitoring Integration", "Monitoring", exc)]
