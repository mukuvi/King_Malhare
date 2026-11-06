from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "warn": "low",
    "warning": "low",
    "info": "info",
    "ok": None,
}


class TestSSL(Adapter):
    name = "testssl"
    category = "network"
    binary_key = "testssl"
    display = "testssl.sh"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "testssl.sh"
        target = ctx.target.target
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme in {"https", ""} else 80)
        endpoint = f"{host}:{port}"
        output_file = ctx.workdir / "testssl.json"
        args = [binary, "--quiet", "--color", "0", "--jsonfile", str(output_file), endpoint]
        ctx.progress(10, "testssl", f"TLS assessment for {endpoint}")
        execution_id = ctx.start_execution("testssl.sh <host:port>")
        remaining = max(120, int(ctx.deadline - time.monotonic()))
        result = ctx.run_command(args, timeout=min(600, remaining), label="testssl")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "testssl.sh is unavailable")
        if not output_file.exists():
            raise AdapterError(f"testssl.sh did not produce JSON (exit {result.exit_code}): {result.stderr[-500:]}")
        try:
            raw = json.loads(output_file.read_text(errors="ignore"))
        except (json.JSONDecodeError, OSError) as exc:
            raise AdapterError(f"testssl JSON could not be parsed: {exc}") from exc
        entries = raw if isinstance(raw, list) else raw.get("scanResult", [])
        ctx.progress(85, "testssl", f"{len(entries)} checks parsed")
        count = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            severity = SEVERITY_MAP.get(str(entry.get("severity", "info")).lower())
            if not severity:
                continue
            finding = str(entry.get("finding") or entry.get("id") or "").strip()
            if not finding:
                continue
            cve = entry.get("cve") or ""
            cwe = entry.get("cwe") or ""
            if cwe and not str(cwe).upper().startswith("CWE-"):
                cwe = f"CWE-{cwe}"
            ctx.add_result(
                NormalizedResult(
                    title=f"TLS: {finding[:180]}",
                    severity=severity,
                    confidence="certain" if severity in {"critical", "high"} else "firm",
                    endpoint=endpoint,
                    cve=str(cve)[:100],
                    cwe=str(cwe)[:100],
                    description=str(entry.get("finding") or finding) + ". Reported by testssl.sh; review the protocol or certificate detail in the evidence.",
                    remediation=str(entry.get("hint") or "Update the TLS configuration to disable weak protocols/ciphers and present a valid certificate chain."),
                    evidence={
                        "id": entry.get("id"),
                        "severity": entry.get("severity"),
                        "finding": finding,
                        "cve": cve,
                        "cwe": cwe,
                        "hint": (entry.get("hint") or "")[:1000],
                    },
                )
            )
            count += 1
            if count >= 300:
                break
        return {"checks": len(entries), "findings": count, "endpoint": endpoint, "exit_code": result.exit_code}

    @staticmethod
    def _fmt_time(seconds: float) -> str:
        return time.strftime("%H:%M:%S", time.gmtime(seconds))
