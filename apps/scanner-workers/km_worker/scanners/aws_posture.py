from __future__ import annotations


from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

SENSITIVE_PORTS = {
    22: ("SSH", "high"),
    23: ("Telnet", "high"),
    445: ("SMB", "high"),
    1433: ("MSSQL", "high"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"),
    6379: ("Redis", "high"),
    9200: ("Elasticsearch", "high"),
    27017: ("MongoDB", "high"),
}


class AWSPosture(Adapter):
    name = "aws-posture"
    category = "cloud"
    binary_key = None
    display = "AWS posture"

    def run(self, ctx: JobContext) -> dict:
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:
            raise AdapterError("boto3 is not installed in the worker") from exc
        creds = (ctx.job.get("credentials") or {}).get("fields") or {}
        provider = (ctx.job.get("credentials") or {}).get("provider")
        if provider != "aws":
            raise AdapterError("AWS posture checks require an AWS connection")
        regions = ctx.config.get("regions") or [creds.get("region") or "us-east-1"]
        regions = [str(r) for r in regions][:4]
        checks = set(ctx.config.get("checks") or list(CHECKS))
        session = boto3.Session(
            aws_access_key_id=creds.get("access_key_id"),
            aws_secret_access_key=creds.get("secret_access_key"),
            aws_session_token=creds.get("session_token") or None,
            region_name=regions[0],
        )
        summary: dict = {"regions": regions, "checks": sorted(checks), "errors": [], "account": ""}
        try:
            identity = session.client("sts").get_caller_identity()
            summary["account"] = identity.get("Account", "")
        except (ClientError, BotoCoreError) as exc:
            raise AdapterError(f"AWS access could not be validated with STS: {_error_text(exc)}") from exc
        ctx.progress(12, "aws-posture", f"Authenticated to AWS account {summary['account']}")
        count = 0
        for name in checks:
            fn = CHECKS.get(name)
            if not fn:
                continue
            ctx.raise_if_cancelled()
            try:
                added = fn(self, ctx, session, regions, summary)
                count += added
            except (ClientError, BotoCoreError) as exc:
                summary["errors"].append({"check": name, "error": _error_text(exc)[:300]})
                ctx.note("aws-posture", f"{name} could not complete: {_error_text(exc)[:120]}")
            except Exception as exc:  # defensive: a single check must not abort the assessment
                summary["errors"].append({"check": name, "error": str(exc)[:300]})
        ctx.progress(92, "aws-posture", f"{count} posture findings")
        summary.update({"findings": count, "account_id": summary["account"]})
        return summary

    def _add(self, ctx, title, severity, description, remediation, evidence):
        ctx.add_result(
            NormalizedResult(
                title=title,
                severity=severity,
                confidence="certain",
                endpoint=f"aws:{evidence.get('account', 'account')}",
                cwe="CWE-693",
                description=description,
                remediation=remediation,
                evidence=evidence,
            )
        )
        return 1


def _error_text(exc) -> str:
    if hasattr(exc, "response"):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'Error')}: {err.get('Message', str(exc))}"
    return str(exc)


def check_root_mfa(adapter, ctx, session, regions, summary):
    iam = session.client("iam")
    data = iam.get_account_summary()["SummaryMap"]
    count = 0
    if not data.get("AccountMFAEnabled", 1):
        count += adapter._add(
            ctx,
            "AWS root account does not have MFA enabled",
            "critical",
            "The root account is the most privileged identity in the AWS account and is not protected by multi-factor authentication.",
            "Enable a hardware or virtual MFA device on the root user, then stop using root for daily operations.",
            {"account": summary.get("account"), "AccountMFAEnabled": data.get("AccountMFAEnabled")},
        )
    if data.get("AccountAccessKeysPresent", 0):
        count += adapter._add(
            ctx,
            "AWS root account has active access keys",
            "high",
            "Root access keys exist. Long-lived root credentials are extremely sensitive and cannot be restricted by IAM policy.",
            "Delete root access keys and use IAM roles or IAM users with least privilege instead.",
            {"account": summary.get("account"), "AccountAccessKeysPresent": data.get("AccountAccessKeysPresent")},
        )
    return count


def check_cloudtrail(adapter, ctx, session, regions, summary):
    total = 0
    for region in regions:
        try:
            client = session.client("cloudtrail", region_name=region)
            trails = client.describe_trails(includeShadowTrails=True).get("trailList", [])
            if not trails:
                total += adapter._add(
                    ctx,
                    f"CloudTrail is not configured in {region}",
                    "high",
                    "No CloudTrail trail was found. API activity in this region may not be recorded, limiting detection and investigation.",
                    "Create a multi-region organisation trail that delivers to a protected, encrypted S3 bucket with log file validation.",
                    {"account": summary.get("account"), "region": region, "trails": 0},
                )
                continue
            logging = False
            multi = False
            for trail in trails:
                if trail.get("IsMultiRegionTrail"):
                    multi = True
                status = client.get_trail_status(Name=trail.get("TrailARN") or trail.get("Name")).get("IsLogging", False)
                logging = logging or bool(status)
            if not logging:
                total += adapter._add(
                    ctx,
                    f"CloudTrail is not logging in {region}",
                    "high",
                    "A trail exists but is not actively logging. Security-relevant API calls are not being retained.",
                    "Enable logging on the trail and verify delivery to the destination bucket.",
                    {"account": summary.get("account"), "region": region, "logging": False},
                )
            elif not multi:
                total += adapter._add(
                    ctx,
                    "CloudTrail is not multi-region",
                    "medium",
                    "The trail covers a single region. Activity in other regions may not be captured.",
                    "Configure the trail as multi-region or create equivalent trails in every active region.",
                    {"account": summary.get("account"), "region": region},
                )
        except Exception as exc:
            if hasattr(exc, "response") and exc.response.get("Error", {}).get("Code") in {"AccessDenied", "AccessDeniedException"}:
                summary["errors"].append({"check": "cloudtrail", "region": region, "error": _error_text(exc)})
                continue
            raise
    return total


def check_s3(adapter, ctx, session, regions, summary):
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    count = 0
    for bucket in buckets[:60]:
        name = bucket["Name"]
        try:
            block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(block.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                count += adapter._add(
                    ctx,
                    f"S3 bucket public access block is incomplete: {name}",
                    "high",
                    "The bucket does not block every public access path. A misconfigured policy or ACL could expose objects.",
                    "Enable all four S3 Block Public Access settings on the bucket and at the account level.",
                    {"account": summary.get("account"), "bucket": name, "configuration": block},
                )
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
                count += adapter._add(
                    ctx,
                    f"S3 bucket has no public access block: {name}",
                    "high",
                    "No Block Public Access configuration exists, so a bucket policy or ACL could make objects public.",
                    "Enable all four Block Public Access settings on the bucket.",
                    {"account": summary.get("account"), "bucket": name},
                )
            elif code not in {"AccessDenied", "AccessDeniedException"}:
                summary["errors"].append({"check": "s3", "bucket": name, "error": _error_text(exc)[:200]})
        try:
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            if status.get("IsPublic"):
                count += adapter._add(
                    ctx,
                    f"S3 bucket policy allows public access: {name}",
                    "critical",
                    "The bucket policy is publicly accessible. Anyone on the internet may be able to read or modify objects depending on the policy statements.",
                    "Remove public principals from the bucket policy, enable Block Public Access and serve public content through CloudFront with an OAC.",
                    {"account": summary.get("account"), "bucket": name, "policy_status": status},
                )
        except Exception:
            pass
    return count


def check_password_policy(adapter, ctx, session, regions, summary):
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return adapter._add(
            ctx,
            "AWS account has no IAM password policy",
            "medium",
            "No custom password policy is configured, so IAM passwords rely on weak defaults.",
            "Configure a password policy requiring at least 14 characters, uppercase, lowercase, numbers and symbols, with reuse prevention.",
            {"account": summary.get("account")},
        )
    count = 0
    if int(policy.get("MinimumPasswordLength", 0)) < 12:
        count += adapter._add(
            ctx,
            "IAM password policy minimum length is below 12 characters",
            "medium",
            "Short passwords increase the likelihood of successful password guessing against IAM users.",
            "Raise MinimumPasswordLength to at least 14 and require complexity.",
            {"account": summary.get("account"), "minimum_length": policy.get("MinimumPasswordLength")},
        )
    if not policy.get("RequireSymbols") or not policy.get("RequireNumbers"):
        count += adapter._add(
            ctx,
            "IAM password policy does not require symbols and numbers",
            "low",
            "The password policy permits simpler passwords than recommended.",
            "Require symbols, numbers and both letter cases, and enable password reuse prevention.",
            {"account": summary.get("account"), "policy": policy},
        )
    return count


def check_security_groups(adapter, ctx, session, regions, summary):
    count = 0
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        for group in groups[:200]:
            for permission in group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                cidrs = [r.get("CidrIp") for r in permission.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
                cidrs += [r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
                if not cidrs:
                    continue
                for port, (service, severity) in SENSITIVE_PORTS.items():
                    if from_port is not None and to_port is not None and from_port <= port <= to_port:
                        count += adapter._add(
                            ctx,
                            f"Security group exposes {service} to the internet: {group.get('GroupName')}",
                            severity,
                            f"{service} (port {port}) is reachable from 0.0.0.0/0 or ::/0 in security group {group.get('GroupId')}.",
                            "Restrict the rule to known CIDR ranges or place the service behind a VPN/bastion. Remove the public rule if it is not required.",
                            {"account": summary.get("account"), "region": region, "group_id": group.get("GroupId"),
                             "group_name": group.get("GroupName"), "protocol": permission.get("IpProtocol"),
                             "from_port": from_port, "to_port": to_port, "cidrs": cidrs},
                        )
                        break
                else:
                    if permission.get("IpProtocol") == "-1":
                        count += adapter._add(
                            ctx,
                            f"Security group allows all traffic from the internet: {group.get('GroupName')}",
                            "critical",
                            "An all-protocol rule permits every port from the entire internet.",
                            "Remove the 0.0.0.0/0 all-protocol rule and allow only required ports from trusted sources.",
                            {"account": summary.get("account"), "region": region, "group_id": group.get("GroupId")},
                        )
    return count


def check_stale_keys(adapter, ctx, session, regions, summary):
    import datetime
    iam = session.client("iam")
    count = 0
    now = datetime.datetime.now(datetime.timezone.utc)
    for user in iam.list_users().get("Users", [])[:100]:
        username = user["UserName"]
        for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
            if key.get("Status") != "Active":
                continue
            created = key.get("CreateDate")
            if created and (now - created).days > 90:
                count += adapter._add(
                    ctx,
                    f"IAM access key older than 90 days: {username}",
                    "medium",
                    f"Active access key {key.get('AccessKeyId', '')[:8]}… was created {(now - created).days} days ago. Long-lived keys increase exposure if leaked.",
                    "Rotate the key, use IAM roles or short-lived credentials, and set a rotation reminder.",
                    {"account": summary.get("account"), "user": username, "age_days": (now - created).days},
                )
    return count


CHECKS = {
    "root_mfa": check_root_mfa,
    "cloudtrail": check_cloudtrail,
    "s3_public_access": check_s3,
    "password_policy": check_password_policy,
    "open_security_groups": check_security_groups,
    "stale_keys": check_stale_keys,
}
