from __future__ import annotations

import json
import time

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

LEVEL_SEVERITY = {"danger": "high", "warning": "medium", "info": "low", "low": "low", "medium": "medium", "high": "high"}


class ScoutSuite(Adapter):
    name = "scoutsuite"
    category = "cloud"
    binary_key = "scoutsuite"
    display = "ScoutSuite"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "scoutsuite"
        credentials = (ctx.job.get("credentials") or {}).get("fields") or {}
        provider = str(ctx.config.get("provider", "aws") or "aws")
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
            })
        elif provider == "gcp":
            blob = credentials.get("service_account_json", "")
            cred_path = ctx.workdir / "gcp-credentials.json"
            cred_path.write_text(blob)
            temp_files.append(cred_path)
            env["GOOGLE_APPLICATION_CREDENTIALS"] = str(cred_path)
        outdir = ctx.workdir / "scoutsuite"
        outdir.mkdir(exist_ok=True)
        args = [binary, provider, "--no-browser", "--report-dir", str(outdir), "--result-format", "json"]
        ctx.progress(10, "scoutsuite", f"Running {provider} configuration collection")
        execution_id = ctx.start_execution(f"scoutsuite {provider} <read-only credentials>")
        result = ctx.run_command(args, timeout=min(840, max(180, int(ctx.deadline - time.monotonic()))), env=env, label="scoutsuite")
        ctx.finish_execution(execution_id, result)
        for f in temp_files:
            try:
                f.unlink()
            except OSError:
                pass
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "ScoutSuite is unavailable")
        payloads = []
        for file in list(outdir.rglob("*.json")) + list(outdir.rglob("*.js")):
            try:
                raw = file.read_text(errors="ignore")
            except OSError:
                continue
            raw = raw.strip()
            if raw.startswith("scoutsuite_results"):
                raw = raw.split("=", 1)[1].strip().rstrip(";")
            try:
                payloads.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        if not payloads:
            raise AdapterError(f"ScoutSuite produced no parseable results (exit {result.exit_code}): {result.stderr[-700:]}")
        ctx.progress(82, "scoutsuite", "Normalizing configuration findings")
        count = 0
        seen = set()
        for payload in payloads:
            for path, finding in self._walk(payload):
                if not isinstance(finding, dict):
                    continue
                flagged = finding.get("flagged_items")
                try:
                    flagged_count = int(flagged) if not isinstance(flagged, list) else len(flagged)
                except (TypeError, ValueError):
                    continue
                if flagged_count <= 0:
                    continue
                key = path
                if key in seen:
                    continue
                seen.add(key)
                title = path.split(".")[-1].replace("-", " ").replace("_", " ").strip().title()
                description = str(finding.get("description") or finding.get("rationale") or title)
                remediation = str(finding.get("remediation") or "Review the ScoutSuite finding and apply the recommended configuration change.")
                endpoint = str(payload.get("account_id") or payload.get("environment") or provider)
                ctx.add_result(
                    NormalizedResult(
                        title=f"Cloud configuration: {title}"[:240],
                        severity=LEVEL_SEVERITY.get(str(finding.get("level", "")).lower(), "medium"),
                        confidence="firm",
                        endpoint=endpoint,
                        cwe="CWE-693",
                        description=description[:5000],
                        remediation=remediation[:5000],
                        evidence={"scoutsuite_path": path, "flagged_items": flagged_count,
                                  "level": finding.get("level"), "service": path.split(".")[1] if "." in path else ""},
                    )
                )
                count += 1
                if count >= 400:
                    break
            if count >= 400:
                break
        return {"provider": provider, "findings": count, "files": len(payloads), "exit_code": result.exit_code}

    def _walk(self, node, path="root", depth=0):
        if depth > 7:
            return
        if isinstance(node, dict):
            if "flagged_items" in node and "description" in node:
                yield path, node
                return
            for key, value in list(node.items())[:60]:
                yield from self._walk(value, f"{path}.{key}", depth + 1)
        elif isinstance(node, list):
            for index, value in enumerate(node[:20]):
                yield from self._walk(value, f"{path}[{index}]", depth + 1)
