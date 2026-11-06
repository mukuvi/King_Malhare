from __future__ import annotations

import json
import re
import time
from urllib.parse import urlparse

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

SEVERE_PATTERNS = [
    (re.compile(r"(?i)sql injection|xss|cross site scripting|remote code execution|command injection|file inclusion"), "high", "CWE-89"),
    (re.compile(r"(?i)outdated|vulnerable|eol|end of life"), "medium", "CWE-1104"),
    (re.compile(r"(?i)admin|backup|config|\.git|\.env|database|password"), "medium", "CWE-538"),
    (re.compile(r"(?i)header|cookie|clickjack|x-frame|content-security|referrer"), "low", "CWE-693"),
]


class Nikto(Adapter):
    name = "nikto"
    category = "web"
    binary_key = "nikto"
    display = "Nikto"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "nikto"
        target = ctx.target.target
        max_time = str(ctx.config.get("max_time", "5m") or "5m")
        output_file = ctx.workdir / "nikto.json"
        args = [
            binary, "-h", target, "-Format", "json", "-output", str(output_file),
            "-nointeractive", "-ask", "no", "-maxtime", max_time,
        ]
        ctx.progress(10, "nikto", "Running server audit")
        execution_id = ctx.start_execution(f"nikto -h <target> -maxtime {max_time}")
        remaining = max(90, int(ctx.deadline - time.monotonic()))
        result = ctx.run_command(args, timeout=min(600, remaining), label="nikto")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "nikto is unavailable")
        data = None
        if output_file.exists():
            try:
                raw = output_file.read_text(errors="ignore")
                data = json.loads(raw)
            except (json.JSONDecodeError, OSError):
                data = None
        if data is None:
            # Nikto may write a leading banner before JSON. Try the first JSON object.
            combined = result.stdout + "\n" + result.stderr
            match = re.search(r"(\{.*\}|\[.*\])", combined, re.S)
            if match:
                try:
                    data = json.loads(match.group(1))
                except json.JSONDecodeError:
                    data = None
        if data is None:
            raise AdapterError(f"Nikto did not return parseable JSON (exit {result.exit_code}): {result.stderr[-500:]}")
        records = self._extract_records(data)
        ctx.progress(85, "nikto", f"{len(records)} observations")
        host = urlparse(target).hostname or target
        for record in records[:500]:
            message = str(record.get("msg") or record.get("message") or record.get("finding") or "Nikto observation").strip()
            if not message:
                continue
            severity, cwe = "medium", "CWE-693"
            for pattern, sev, cw in SEVERE_PATTERNS:
                if pattern.search(message):
                    severity, cwe = sev, cw
                    break
            url = str(record.get("url") or record.get("uri") or target)
            if url.startswith("/"):
                scheme = urlparse(target).scheme or "https"
                url = f"{scheme}://{host}{url}"
            method = str(record.get("method") or "GET")
            nikto_id = str(record.get("id") or record.get("osvdb") or "")
            ctx.add_result(
                NormalizedResult(
                    title=f"Nikto: {message[:170]}",
                    severity=severity,
                    confidence="tentative",
                    endpoint=url,
                    cwe=cwe,
                    description=f"Nikto reported: {message}. This is scanner output; confirm the condition and its impact before treating it as a confirmed vulnerability.",
                    remediation="Review the reported path or configuration, remove unnecessary exposure and retest.",
                    evidence={"nikto_id": nikto_id, "method": method, "uri": record.get("uri"), "url": url},
                    raw={k: record.get(k) for k in ("id", "osvdb", "method", "uri", "msg")},
                )
            )
        return {"observations": len(records), "findings": len(ctx.results), "exit_code": result.exit_code, "maxtime": max_time}

    @staticmethod
    def _extract_records(data) -> list[dict]:
        if isinstance(data, list):
            out = []
            for item in data:
                if isinstance(item, dict):
                    if isinstance(item.get("vulnerabilities"), list):
                        for v in item["vulnerabilities"]:
                            if isinstance(v, dict):
                                out.append(v)
                    else:
                        out.append(item)
            if out:
                return out
        if isinstance(data, dict):
            for key in ("vulnerabilities", "findings", "items", "scans"):
                value = data.get(key)
                if isinstance(value, list):
                    return [v for v in value if isinstance(v, dict)]
            if "msg" in data:
                return [data]
        return []
