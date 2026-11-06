from __future__ import annotations

import json
import time

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError


class Trivy(Adapter):
    name = "trivy"
    category = "infrastructure"
    binary_key = "trivy"
    display = "Trivy"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "trivy"
        scan_type = str(ctx.config.get("scan_type", "image") or "image")
        if scan_type not in {"image", "fs"}:
            raise AdapterError("Trivy scan type must be image or fs")
        target = ctx.target.target
        if scan_type == "fs" and not target.startswith("/"):
            raise AdapterError("Filesystem scans require an absolute path that is mounted into the worker")
        severities = ctx.config.get("severity") or ["CRITICAL", "HIGH", "MEDIUM"]
        args = [binary, scan_type, "--format", "json", "--quiet", "--severity", ",".join(str(s) for s in severities), "--timeout", "10m", target]
        ctx.progress(10, "trivy", f"Scanning {target}")
        execution_id = ctx.start_execution(f"trivy {scan_type} <target>")
        result = ctx.run_command(args, timeout=min(840, max(120, int(ctx.deadline - time.monotonic()))), label="trivy")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "trivy is unavailable")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"Trivy JSON could not be parsed (exit {result.exit_code}): {result.stderr[-500:]}") from exc
        ctx.progress(82, "trivy", "Normalizing results")
        count = 0
        for resultset in data.get("Results", []) or []:
            result_target = resultset.get("Target", target)
            for vuln in resultset.get("Vulnerabilities", []) or []:
                cve = vuln.get("VulnerabilityID", "") if str(vuln.get("VulnerabilityID", "")).startswith("CVE-") else ""
                cvss = None
                cvss_data = vuln.get("CVSS") or {}
                for source in cvss_data.values():
                    if isinstance(source, dict):
                        for key in ("V3Score", "V2Score"):
                            if source.get(key):
                                try:
                                    cvss = float(source[key])
                                    break
                                except (TypeError, ValueError):
                                    pass
                    if cvss:
                        break
                title = vuln.get("Title") or vuln.get("VulnerabilityID") or "Vulnerable dependency"
                pkg = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                ctx.add_result(
                    NormalizedResult(
                        title=f"{vuln.get('VulnerabilityID', 'Vulnerability')}: {title}"[:240],
                        severity=str(vuln.get("Severity", "medium")).lower(),
                        confidence="certain",
                        cve=cve,
                        cvss=cvss,
                        endpoint=result_target,
                        cwe="CWE-1395",
                        description=(vuln.get("Description") or title)[:5000],
                        remediation=(f"Upgrade {pkg} from {installed} to {fixed}." if fixed else f"No fixed version is listed for {pkg} {installed}; apply the vendor mitigation or replace the package."),
                        evidence={"package": pkg, "installed_version": installed, "fixed_version": fixed,
                                  "vulnerability_id": vuln.get("VulnerabilityID"), "primary_url": vuln.get("PrimaryURL"),
                                  "references": (vuln.get("References") or [])[:5]},
                    )
                )
                count += 1
            for misconfig in resultset.get("Misconfigurations", []) or []:
                if str(misconfig.get("Status", "FAIL")).upper() == "PASS":
                    continue
                ctx.add_result(
                    NormalizedResult(
                        title=f"Misconfiguration: {misconfig.get('Title', misconfig.get('ID', 'unknown'))}",
                        severity=str(misconfig.get("Severity", "MEDIUM")).lower(),
                        confidence="firm",
                        endpoint=result_target,
                        cwe="CWE-693",
                        description=(misconfig.get("Description") or misconfig.get("Message") or "Configuration check failed")[:5000],
                        remediation=(misconfig.get("Resolution") or "Review the configuration against the referenced benchmark.")[:5000],
                        evidence={"id": misconfig.get("ID"), "message": misconfig.get("Message"),
                                  "namespace": misconfig.get("Namespace"), "references": (misconfig.get("References") or [])[:5]},
                    )
                )
                count += 1
        return {"results": len(data.get("Results", []) or []), "findings": count, "scan_type": scan_type, "target": target}
