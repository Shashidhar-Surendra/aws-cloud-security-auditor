"""Unit tests for the auditor check functions.

These tests use lightweight mock objects so no real AWS credentials are
required.  They verify the check logic — not the AWS API itself.
"""
from __future__ import annotations

import pytest

import botocore.exceptions

from auditor.checks import (
    check_cloudtrail,
    check_ec2_rdp,
    check_ec2_ssh,
    check_iam_admin_privileges,
    check_iam_mfa,
    check_iam_password_policy,
    check_iam_root_mfa,
    check_monitoring,
    check_s3_encryption,
    check_s3_public_access,
    check_s3_versioning,
)


# ---------------------------------------------------------------------------
# Minimal mock helpers
# ---------------------------------------------------------------------------

def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "mocked"}}, "MockOperation"
    )


class _PageIterator:
    """Mimic a boto3 paginator that returns a single page."""
    def __init__(self, pages: list[dict]):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class MockS3:
    def __init__(self, buckets=None, public_block=None, encryption=None, versioning=None,
                 encryption_error_code=None, public_block_error_code=None):
        self._buckets = [{"Name": "test-bucket"}] if buckets is None else buckets
        self._public_block = public_block
        self._encryption = encryption
        self._encryption_error_code = encryption_error_code
        self._public_block_error_code = public_block_error_code
        self._versioning = versioning

    def list_buckets(self):
        return {"Buckets": self._buckets}

    def get_public_access_block(self, Bucket):
        if self._public_block_error_code:
            raise _client_error(self._public_block_error_code)
        if self._public_block is None:
            raise _client_error("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self._public_block}

    def get_bucket_encryption(self, Bucket):
        if self._encryption_error_code:
            raise _client_error(self._encryption_error_code)
        return {"ServerSideEncryptionConfiguration": self._encryption or {}}

    def get_bucket_versioning(self, Bucket):
        return self._versioning or {}


class MockIAM:
    """Mock boto3 IAM client supporting paginators, login profiles, and MFA."""

    def __init__(
        self,
        users=None,
        mfa_map=None,
        password_policy=None,
        no_password_policy=False,
        account_mfa_enabled=1,
        # Per-user login profile: True = has console, False = programmatic only
        login_profile_map=None,
        # Per-user inline policy names
        inline_policy_map=None,
        # Per-user inline policy documents
        inline_policy_docs=None,
        # Per-user attached policy list [{"PolicyName": x, "PolicyArn": y}]
        attached_policy_map=None,
        # PolicyArn → policy document
        policy_doc_map=None,
        admin_policy_users=None,  # shortcut: list of usernames with admin policy
    ):
        self._users = users or []
        self._mfa_map = mfa_map or {}
        self._password_policy = password_policy
        self._no_password_policy = no_password_policy
        self._account_mfa_enabled = account_mfa_enabled
        # By default every user has a console login profile
        self._login_profile_map = login_profile_map or {
            u["UserName"]: True for u in self._users
        }
        self._inline_policy_map = inline_policy_map or {}
        self._inline_policy_docs = inline_policy_docs or {}
        self._attached_policy_map = attached_policy_map or {}
        self._policy_doc_map = policy_doc_map or {}

        # Shortcut: wire up a simple AdministratorAccess-like policy for listed users
        if admin_policy_users:
            for uname in admin_policy_users:
                arn = f"arn:aws:iam::aws:policy/AdministratorAccess_{uname}"
                self._attached_policy_map.setdefault(uname, [])
                self._attached_policy_map[uname].append(
                    {"PolicyName": "AdministratorAccess", "PolicyArn": arn}
                )
                self._policy_doc_map[arn] = {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }

    # --- paginators ---
    def get_paginator(self, operation_name: str):
        if operation_name == "list_users":
            return _PageIterator([{"Users": self._users}])
        if operation_name == "list_user_policies":
            inline_map = self._inline_policy_map

            class _LP:
                def paginate(self, UserName="", **kwargs):
                    names = inline_map.get(UserName, [])
                    return iter([{"PolicyNames": names}])

            return _LP()
        if operation_name == "list_attached_user_policies":
            attached_map = self._attached_policy_map

            class _AP:
                def paginate(self, UserName="", **kwargs):
                    policies = attached_map.get(UserName, [])
                    return iter([{"AttachedPolicies": policies}])

            return _AP()
        raise NotImplementedError(f"No paginator mock for {operation_name}")

    # --- non-paginated calls ---
    def list_users(self):
        return {"Users": self._users}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": self._mfa_map.get(UserName, [])}

    def get_login_profile(self, UserName):
        has_profile = self._login_profile_map.get(UserName, True)
        if not has_profile:
            raise _client_error("NoSuchEntity")
        return {"LoginProfile": {"UserName": UserName}}

    def get_account_password_policy(self):
        if self._no_password_policy:
            raise _client_error("NoSuchEntity")
        return {"PasswordPolicy": self._password_policy or {}}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": self._account_mfa_enabled}}

    # IAM-003 helpers
    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyDocument": self._inline_policy_docs.get(PolicyName, {"Statement": []})}

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1", "PolicyArn": PolicyArn}}

    def get_policy_version(self, PolicyArn, VersionId):
        doc = self._policy_doc_map.get(PolicyArn, {"Statement": []})
        return {"PolicyVersion": {"Document": doc}}


class MockEC2:
    def __init__(self, security_groups=None, pages=None):
        """
        `pages` is a list of lists of security groups, one per page.
        If omitted, all groups go on a single page.
        """
        if pages is not None:
            self._pages = pages
        else:
            self._pages = [security_groups or []]

    def get_paginator(self, operation_name: str):
        if operation_name == "describe_security_groups":
            pages = self._pages

            class _SGPaginator:
                def paginate(self, **kwargs):
                    return iter([{"SecurityGroups": p} for p in pages])

            return _SGPaginator()
        raise NotImplementedError(f"No paginator mock for {operation_name}")


def _open_sg(port: int, group_id: str = "sg-test", ipv4=True, ipv6=False):
    """Build a minimal security group with a public inbound rule."""
    ip_ranges = [{"CidrIp": "0.0.0.0/0"}] if ipv4 else []
    ipv6_ranges = [{"CidrIpv6": "::/0"}] if ipv6 else []
    return {
        "GroupId": group_id,
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": ip_ranges,
            "Ipv6Ranges": ipv6_ranges,
        }],
    }


class MockCloudTrail:
    def __init__(self, trails=None, logging_map=None, cw_log_map=None, raise_error=None):
        self._trails = trails or []
        self._logging_map = logging_map or {}
        self._cw_log_map = cw_log_map or {}
        self._raise_error = raise_error

    def describe_trails(self, includeShadowTrails=True):
        if self._raise_error:
            raise _client_error(self._raise_error)
        result = []
        for t in self._trails:
            entry = {"Name": t, "TrailARN": f"arn:aws:cloudtrail:eu-central-1:123:{t}"}
            cw_arn = self._cw_log_map.get(t)
            if cw_arn:
                entry["CloudWatchLogsLogGroupArn"] = cw_arn
            result.append(entry)
        return {"trailList": result}

    def get_trail_status(self, Name):
        trail_name = Name.split(":")[-1] if ":" in Name else Name
        return {"IsLogging": self._logging_map.get(trail_name, False)}


class MockLogs:
    pass


# ---------------------------------------------------------------------------
# S3-001: Public Access Block
# ---------------------------------------------------------------------------

ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True,
}


def test_s3_public_access_all_blocked_is_pass():
    s3 = MockS3(public_block=ALL_BLOCKED)
    findings = check_s3_public_access(s3)
    assert len(findings) == 1
    assert findings[0].status == "PASS"
    assert findings[0].check_id == "S3-001"


def test_s3_public_access_partial_block_is_fail():
    partial = dict(ALL_BLOCKED)
    partial["BlockPublicAcls"] = False
    s3 = MockS3(public_block=partial)
    findings = check_s3_public_access(s3)
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "CRITICAL"
    assert "BlockPublicAcls" in findings[0].evidence.get("failed_controls", [])


def test_s3_public_access_no_buckets_is_not_applicable():
    s3 = MockS3(buckets=[])
    findings = check_s3_public_access(s3)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"
    assert findings[0].check_id == "S3-001"


def test_s3_public_access_api_error_returns_warn():
    s3 = MockS3(public_block_error_code="AccessDenied")
    findings = check_s3_public_access(s3)
    assert findings[0].status == "WARN"


# ---------------------------------------------------------------------------
# S3-002: Default Server-Side Encryption Configuration
# ---------------------------------------------------------------------------

def test_s3_encryption_present_is_pass():
    enc_config = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}
    s3 = MockS3(encryption=enc_config)
    findings = check_s3_encryption(s3)
    assert findings[0].status == "PASS"
    assert "aws:kms" in findings[0].evidence["algorithms"]


def test_s3_encryption_missing_config_error_is_fail():
    s3 = MockS3(encryption_error_code="ServerSideEncryptionConfigurationNotFoundError")
    findings = check_s3_encryption(s3)
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "HIGH"


def test_s3_encryption_no_rules_is_fail():
    s3 = MockS3(encryption={"Rules": []})
    findings = check_s3_encryption(s3)
    assert findings[0].status == "FAIL"


def test_s3_encryption_no_buckets_is_not_applicable():
    s3 = MockS3(buckets=[])
    findings = check_s3_encryption(s3)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# S3-003: Versioning
# ---------------------------------------------------------------------------

def test_s3_versioning_enabled_is_pass():
    s3 = MockS3(versioning={"Status": "Enabled"})
    findings = check_s3_versioning(s3)
    assert findings[0].status == "PASS"


def test_s3_versioning_disabled_is_fail():
    s3 = MockS3(versioning={"Status": "Disabled"})
    findings = check_s3_versioning(s3)
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "MEDIUM"


def test_s3_versioning_suspended_is_fail():
    s3 = MockS3(versioning={"Status": "Suspended"})
    findings = check_s3_versioning(s3)
    assert findings[0].status == "FAIL"


def test_s3_versioning_no_buckets_is_not_applicable():
    s3 = MockS3(buckets=[])
    findings = check_s3_versioning(s3)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# IAM-001: User MFA (console users only)
# ---------------------------------------------------------------------------

def test_iam_mfa_console_user_with_mfa_is_pass():
    iam = MockIAM(
        users=[{"UserName": "alice"}],
        mfa_map={"alice": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}]},
        login_profile_map={"alice": True},
    )
    findings = check_iam_mfa(iam)
    assert any(f.status == "PASS" and f.resource == "alice" for f in findings)


def test_iam_mfa_console_user_without_mfa_is_fail():
    iam = MockIAM(
        users=[{"UserName": "bob"}],
        mfa_map={},
        login_profile_map={"bob": True},
    )
    findings = check_iam_mfa(iam)
    assert any(f.status == "FAIL" and f.resource == "bob" for f in findings)


def test_iam_mfa_programmatic_user_is_not_applicable():
    """A user with no console login profile should be NOT_APPLICABLE."""
    iam = MockIAM(
        users=[{"UserName": "svc-account"}],
        mfa_map={},
        login_profile_map={"svc-account": False},
    )
    findings = check_iam_mfa(iam)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"
    assert findings[0].resource == "svc-account"


def test_iam_mfa_no_users_is_not_applicable():
    iam = MockIAM(users=[])
    findings = check_iam_mfa(iam)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"


def test_iam_mfa_mixed_users():
    """Console user without MFA = FAIL; programmatic user = NOT_APPLICABLE."""
    iam = MockIAM(
        users=[{"UserName": "alice"}, {"UserName": "svc"}],
        mfa_map={"alice": [], "svc": []},
        login_profile_map={"alice": True, "svc": False},
    )
    findings = check_iam_mfa(iam)
    statuses = {f.resource: f.status for f in findings}
    assert statuses["alice"] == "FAIL"
    assert statuses["svc"] == "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# IAM-002: Password policy
# ---------------------------------------------------------------------------

STRONG_POLICY = {
    "MinimumPasswordLength": 14,
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
}


def test_password_policy_strong_is_pass():
    iam = MockIAM(password_policy=STRONG_POLICY)
    findings = check_iam_password_policy(iam)
    assert findings[0].status == "PASS"


def test_password_policy_weak_length_is_fail():
    weak = dict(STRONG_POLICY)
    weak["MinimumPasswordLength"] = 8
    iam = MockIAM(password_policy=weak)
    findings = check_iam_password_policy(iam)
    assert findings[0].status == "FAIL"
    assert "MinimumPasswordLength" in findings[0].evidence.get("failed_requirements", {})


def test_password_policy_absent_is_fail():
    iam = MockIAM(no_password_policy=True)
    findings = check_iam_password_policy(iam)
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "HIGH"


def test_password_policy_missing_symbol_is_fail():
    policy = dict(STRONG_POLICY)
    policy["RequireSymbols"] = False
    iam = MockIAM(password_policy=policy)
    findings = check_iam_password_policy(iam)
    assert findings[0].status == "FAIL"
    assert "RequireSymbols" in findings[0].evidence.get("failed_requirements", {})


# ---------------------------------------------------------------------------
# IAM-003: Excessive administrator privileges
# ---------------------------------------------------------------------------

def test_iam_admin_no_users_is_not_applicable():
    iam = MockIAM(users=[])
    findings = check_iam_admin_privileges(iam)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"


def test_iam_admin_least_privilege_user_is_pass():
    iam = MockIAM(users=[{"UserName": "developer"}])
    findings = check_iam_admin_privileges(iam)
    assert any(f.status == "PASS" and f.resource == "developer" for f in findings)


def test_iam_admin_direct_admin_policy_is_fail():
    iam = MockIAM(
        users=[{"UserName": "poweruser"}],
        admin_policy_users=["poweruser"],
    )
    findings = check_iam_admin_privileges(iam)
    assert any(f.status == "FAIL" and f.resource == "poweruser" for f in findings)
    found = next(f for f in findings if f.resource == "poweruser")
    assert found.severity == "HIGH"
    assert len(found.evidence.get("confirmed_admin_policies", [])) > 0


# ---------------------------------------------------------------------------
# IAM-004: Root MFA
# ---------------------------------------------------------------------------

def test_root_mfa_enabled_is_pass():
    iam = MockIAM(account_mfa_enabled=1)
    findings = check_iam_root_mfa(iam)
    assert len(findings) == 1
    assert findings[0].status == "PASS"
    assert findings[0].check_id == "IAM-004"


def test_root_mfa_disabled_is_fail_critical():
    iam = MockIAM(account_mfa_enabled=0)
    findings = check_iam_root_mfa(iam)
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].security_penalty == 20.0


def test_root_mfa_evidence_key_present():
    iam = MockIAM(account_mfa_enabled=0)
    findings = check_iam_root_mfa(iam)
    assert "AccountMFAEnabled" in findings[0].evidence


# ---------------------------------------------------------------------------
# EC2-001: SSH exposure
# ---------------------------------------------------------------------------

def test_ec2_ssh_open_ipv4_is_fail():
    ec2 = MockEC2(security_groups=[_open_sg(22)])
    findings = check_ec2_ssh(ec2)
    assert any(f.status == "FAIL" for f in findings)
    failed = next(f for f in findings if f.status == "FAIL")
    assert failed.check_id == "EC2-001"
    assert failed.severity == "HIGH"


def test_ec2_ssh_open_ipv6_is_fail():
    ec2 = MockEC2(security_groups=[_open_sg(22, ipv4=False, ipv6=True)])
    findings = check_ec2_ssh(ec2)
    assert any(f.status == "FAIL" for f in findings)


def test_ec2_ssh_restricted_is_pass():
    restricted_sg = {
        "GroupId": "sg-private",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            "Ipv6Ranges": [],
        }],
    }
    ec2 = MockEC2(security_groups=[restricted_sg])
    findings = check_ec2_ssh(ec2)
    assert all(f.status == "PASS" for f in findings)


def test_ec2_ssh_all_protocol_rule_is_fail():
    """A rule with IpProtocol=-1 (all traffic) should also trigger the check."""
    sg = {
        "GroupId": "sg-all",
        "IpPermissions": [{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }],
    }
    ec2 = MockEC2(security_groups=[sg])
    findings = check_ec2_ssh(ec2)
    assert any(f.status == "FAIL" for f in findings)


def test_ec2_ssh_no_groups_is_pass():
    ec2 = MockEC2(security_groups=[])
    findings = check_ec2_ssh(ec2)
    assert len(findings) == 1
    assert findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# EC2-002: RDP exposure
# ---------------------------------------------------------------------------

def test_ec2_rdp_open_is_fail():
    ec2 = MockEC2(security_groups=[_open_sg(3389)])
    findings = check_ec2_rdp(ec2)
    assert any(f.status == "FAIL" for f in findings)
    failed = next(f for f in findings if f.status == "FAIL")
    assert failed.check_id == "EC2-002"


def test_ec2_rdp_not_open_is_pass():
    ec2 = MockEC2(security_groups=[])
    findings = check_ec2_rdp(ec2)
    assert findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# CT-001: CloudTrail logging
# ---------------------------------------------------------------------------

def test_cloudtrail_no_trails_is_fail():
    ct = MockCloudTrail(trails=[])
    findings = check_cloudtrail(ct)
    assert findings[0].status == "FAIL"
    assert findings[0].check_id == "CT-001"


def test_cloudtrail_active_trail_is_pass():
    ct = MockCloudTrail(
        trails=["management-events"],
        logging_map={"management-events": True},
    )
    findings = check_cloudtrail(ct)
    assert findings[0].status == "PASS"


def test_cloudtrail_trail_exists_but_stopped_is_fail():
    ct = MockCloudTrail(
        trails=["management-events"],
        logging_map={"management-events": False},
    )
    findings = check_cloudtrail(ct)
    assert findings[0].status == "FAIL"


def test_cloudtrail_api_error_returns_warn():
    ct = MockCloudTrail(raise_error="AccessDenied")
    findings = check_cloudtrail(ct)
    assert findings[0].status == "WARN"


# ---------------------------------------------------------------------------
# MON-001: CloudTrail CloudWatch Logs integration
# ---------------------------------------------------------------------------

def test_monitoring_no_trails_is_not_applicable():
    ct = MockCloudTrail(trails=[])
    findings = check_monitoring(ct)
    assert len(findings) == 1
    assert findings[0].status == "NOT_APPLICABLE"
    assert findings[0].check_id == "MON-001"


def test_monitoring_logging_with_cw_is_pass():
    ct = MockCloudTrail(
        trails=["trail1"],
        logging_map={"trail1": True},
        cw_log_map={"trail1": "arn:aws:logs:eu-central-1:123:log-group:/cloudtrail"},
    )
    findings = check_monitoring(ct)
    assert findings[0].status == "PASS"


def test_monitoring_logging_without_cw_is_fail():
    ct = MockCloudTrail(
        trails=["trail1"],
        logging_map={"trail1": True},
        cw_log_map={},
    )
    findings = check_monitoring(ct)
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "MEDIUM"


def test_monitoring_trail_exists_not_logging_no_cw_is_fail():
    ct = MockCloudTrail(
        trails=["trail1"],
        logging_map={"trail1": False},
        cw_log_map={},
    )
    findings = check_monitoring(ct)
    assert findings[0].status == "FAIL"


def test_monitoring_api_error_returns_warn():
    ct = MockCloudTrail(raise_error="AccessDenied")
    findings = check_monitoring(ct)
    assert findings[0].status == "WARN"


# ---------------------------------------------------------------------------
# IAM-001: list_mfa_devices AccessDenied → WARN
# ---------------------------------------------------------------------------

def test_iam_mfa_list_mfa_devices_access_denied_is_warn():
    """AccessDenied on list_mfa_devices for a console user should produce WARN, not ERROR."""

    class MockIAMWithMFADenied(MockIAM):
        def list_mfa_devices(self, UserName):
            raise _client_error("AccessDenied")

    iam = MockIAMWithMFADenied(
        users=[{"UserName": "alice"}],
        login_profile_map={"alice": True},
    )
    findings = check_iam_mfa(iam)
    assert len(findings) == 1
    assert findings[0].status == "WARN"
    assert findings[0].check_id == "IAM-001"


# ---------------------------------------------------------------------------
# IAM pagination: multi-page list_users
# ---------------------------------------------------------------------------

def test_iam_mfa_multi_page_users_all_processed():
    """Paginator processes users across multiple pages — both should be evaluated."""

    class _MultiPageIAM(MockIAM):
        def get_paginator(self, operation_name: str):
            if operation_name == "list_users":
                # Two pages, two users each
                return _PageIterator([
                    {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]},
                    {"Users": [{"UserName": "carol"}, {"UserName": "dave"}]},
                ])
            return super().get_paginator(operation_name)

    iam = _MultiPageIAM(
        users=[],  # paginator bypasses this
        mfa_map={
            "alice": [{"SerialNumber": "arn:mfa/alice"}],
            "bob": [],
            "carol": [{"SerialNumber": "arn:mfa/carol"}],
            "dave": [],
        },
        login_profile_map={"alice": True, "bob": True, "carol": True, "dave": True},
    )
    findings = check_iam_mfa(iam)
    resources = {f.resource for f in findings}
    assert resources == {"alice", "bob", "carol", "dave"}, \
        "All four users across both pages must be evaluated"
    statuses = {f.resource: f.status for f in findings}
    assert statuses["alice"] == "PASS"
    assert statuses["bob"] == "FAIL"
    assert statuses["carol"] == "PASS"
    assert statuses["dave"] == "FAIL"


# ---------------------------------------------------------------------------
# EC2 pagination: multi-page describe_security_groups
# ---------------------------------------------------------------------------

def test_ec2_ssh_multi_page_groups_all_processed():
    """EC2 paginator processes security groups across multiple pages."""
    # Page 1: restricted SG (should not trigger FAIL)
    restricted = {
        "GroupId": "sg-restricted",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            "Ipv6Ranges": [],
        }],
    }
    # Page 2: open SG (should trigger FAIL)
    open_sg = _open_sg(22, group_id="sg-open")
    ec2 = MockEC2(pages=[[restricted], [open_sg]])
    findings = check_ec2_ssh(ec2)
    fail_ids = [f.resource for f in findings if f.status == "FAIL"]
    assert "sg-open" in fail_ids, "Open SG on page 2 must be detected"


def test_s3_public_access_verification_does_not_claim_policy_acl_inspection():
    """S3-001 must not claim that policy/ACL exposure was inspected by this check."""
    from unittest.mock import Mock
    from auditor.checks import check_s3_public_access

    s3 = Mock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "bucket-a"}]}
    s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    }
    findings = check_s3_public_access(s3)
    assert findings[0].status == "FAIL"
    verification = findings[0].verification
    assert "evaluate to true" in verification
    assert "outside this check's scope" in verification
