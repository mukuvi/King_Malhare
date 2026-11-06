from __future__ import annotations

import json
import time

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError


def severity_from(value) -> str:
    if isinstance(value, dict):
        value = value.get("Label") or value.get("label") or "medium"
    text = str(value or "medium").lower()
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    if text in {"informational", "information"}:
        return "info"
    return "medium"


class Prowler(Adapter):
    name = "prowler"
    category = "cloud"
    binary_key = "prowler"
    display = "Prowler"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "prowler"
        credentials = (ctx.job.get("credentials") or {}).get("fields") or {}
        provider = str(ctx.config.get("provider", "aws") or "aws")
        if provider != (ctx.job.get("credentials") or {}).get("provider"):
            raise AdapterError("Prowler provider does not match the cloud connection")
        env = {}
        temp_files = []
        if provider == "aws":
            env.update({
                "AWS_ACCESS_KEY_ID": credentials.get("access_key_id", ""),
                "AWS_SECRET_ACCESS_KEY": credentials.get("secret_access_key", ""),
                "AWS_DEFAULT_REGION": credentials.get("region", "us-east-1"),
            })
            if credentials.get("session_token"):
                env["AWS_SESSION_TOKEN"] = credentials["session_token"]
        elif provider == "azure":
            env.update({
                "AZURE_TENANT_ID": credentials.get("tenant_id", ""),
                "AZURE_CLIENT_ID": credentials.get("client_id", ""),
                "AZURE_CLIENT_SECRET": credentials.get("client_secret", ""),
                "AZURE_SUBSCRIPTION_ID": credentials.get("subscription_id", ""),
            })
        elif provider == "gcp":
            blob = credentials.get("service_account_json", "")
            try:
                json.loads(blob)
            except json.JSONDecodeError as exc:
                raise AdapterError("GCP service account JSON is invalid") from exc
            cred_path = ctx.workdir / "gcp-credentials.json"
            cred_path.write_text(blob)
            temp_files.append(cred_path)
            env["GOOGLE_APPLICATION_CREDENTIALS"] = str(cred_path)
        outdir = ctx.workdir / "prowler"
        outdir.mkdir(exist_ok=True)
        args = [binary, provider, "--output-directory", str(outdir), "--output-formats", "json", "--no-banner", "--quiet"]
        ctx.progress(10, "prowler", f"Running {provider} posture checks")
        execution_id = ctx.start_execution(f"prowler {provider} <read-only credentials>")
        result = ctx.run_command(args, timeout=min(840, max(180, int(ctx.deadline - time.monotonic()))), env=env, label="prowler")
        ctx.finish_execution(execution_id, result)
        for f in temp_files:
            try:
                f.unlink()
            except OSError:
                pass
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "prowler is unavailable")
        files = list(outdir.rglob("*.json")) + list(outdir.rglob("*.ocsf.json"))
        if not files:
            raise AdapterError(f"Prowler produced no JSON output (exit {result.exit_code}): {result.stderr[-700:]}")
        ctx.progress(80, "prowler", "Normalizing posture findings")
        count = 0
        for file in files:
            try:
                data = json.loads(file.read_text(errors="ignore"))
            except (json.JSONDecodeError, OSError):
                continue
            records = data if isinstance(data, list) else [data]
            for record in records:
                if not isinstance(record, dict):
                    continue
                status = str(record.get("status_code") or record.get("Status") or "").upper()
                if status and status != "FAIL":
                    continue
                check_id = str(record.get("check_id") or record.get("CheckID") or record.get("finding_info", {}).get("uid") or "prowler-check")
                title = str(record.get("title") or record.get("CheckTitle") or record.get("finding_info", {}).get("title") or check_id)
                description = str(record.get("description") or record.get("Risk") or record.get("status_extended") or record.get("StatusExtended") or "Prowler reported a failed control.")
                remediation = record.get("remediation") or {}
                if isinstance(remediation, dict):
                    remediation = remediation.get("desc") or remediation.get("recommendation") or ""
                remediation = str(remediation or record.get("Remediation") or "Apply the Prowler control remediation and re-run the assessment.")
                resource = record.get("resource_uid") or record.get("ResourceArn") or record.get("resource") or ""
                if isinstance(resource, dict):
                    resource = resource.get("uid") or resource.get("name") or ""
                endpoint = str(record.get("account_uid") or credentials.get("subscription_id") or credentials.get("region") or provider)
                ctx.add_result(
                    NormalizedResult(
                        title=f"Cloud control failed: {title}"[:240],
                        severity=severity_from(record.get("severity") or record.get("Severity")),
                        confidence="certain",
                        endpoint=endpoint,
                        cwe="CWE-693",
                        description=description[:5000],
                        remediation=remediation[:5000],
                        evidence={"check_id": check_id, "resource": str(resource)[:500], "provider": provider,
                                  "status": status, "service": record.get("service_name") or record.get("ServiceName")},
                    )
                )
                count += 1
                if count >= 500:
                    break
            if count >= 500:
                break
        return {"provider": provider, "files": len(files), "findings": count, "exit_code": result.exit_code}
