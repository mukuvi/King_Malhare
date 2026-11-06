from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

PARAM_RE = re.compile(r"Parameter:\s*(.+?)\s*\((GET|POST|COOKIE|URI)\)", re.I)
DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.I)
TYPE_RE = re.compile(r"Type:\s*(.+)", re.I)
PAYLOAD_RE = re.compile(r"Payload:\s*(.+)", re.I)
TITLE_RE = re.compile(r"Title:\s*(.+)", re.I)


class SQLMap(Adapter):
    name = "sqlmap"
    category = "web"
    binary_key = "sqlmap"
    display = "SQLMap"

    def run(self, ctx: JobContext) -> dict:
        scope = ctx.job.get("scope") or {}
        if not scope.get("intrusive_allowed"):
            raise AdapterError("SQLMap requires an authorization that permits intrusive testing")
        target = ctx.target.target
        parsed = urlparse(target)
        if not parsed.query:
            raise AdapterError("SQLMap requires a target URL with at least one query parameter. Use an asset scoped to the specific parameterized endpoint.")
        binary = self.binary() or "sqlmap"
        level = max(1, min(2, int(ctx.config.get("level", 1) or 1)))
        risk = max(1, min(2, int(ctx.config.get("risk", 1) or 1)))
        technique = str(ctx.config.get("technique", "B") or "B")
        if technique not in {"B", "E", "BE"}:
            raise AdapterError("Only boolean and error-based techniques are permitted")
        args = [
            binary, "-u", target, "--batch", "--smart",
            "--level", str(level), "--risk", str(risk), "--technique", technique,
            "--timeout", "10", "--retries", "1", "--threads", "1",
            "--disable-coloring", "--output-dir", str(ctx.workdir / "sqlmap"),
        ]
        ctx.progress(10, "sqlmap", "Bounded injection verification started")
        execution_id = ctx.start_execution(f"sqlmap -u <target> --level {level} --risk {risk} --technique {technique}")
        started = time.monotonic()
        result = ctx.run_command(args, timeout=min(600, max(120, int(ctx.deadline - started))), label="sqlmap")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "sqlmap is unavailable")
        output = result.stdout + "\n" + result.stderr
        params = []
        current = None
        dbms = ""
        for line in output.splitlines():
            line = line.strip()
            match = PARAM_RE.search(line)
            if match:
                current = {"parameter": match.group(1), "method": match.group(2), "technique": "", "payload": "", "title": ""}
                params.append(current)
                continue
            if current is not None:
                if not current["technique"]:
                    m = TYPE_RE.search(line)
                    if m:
                        current["technique"] = m.group(1)
                if not current["payload"]:
                    m = PAYLOAD_RE.search(line)
                    if m:
                        current["payload"] = m.group(1)
                if not current["title"]:
                    m = TITLE_RE.search(line)
                    if m:
                        current["title"] = m.group(1)
            m = DBMS_RE.search(line)
            if m:
                dbms = m.group(1)
        injectable = "is vulnerable" in output.lower() or bool(params)
        if injectable:
            for item in params:
                ctx.add_result(
                    NormalizedResult(
                        title=f"SQL injection in parameter '{item['parameter']}'",
                        severity="critical",
                        confidence="certain",
                        endpoint=target,
                        cwe="CWE-89",
                        description=f"SQLMap confirmed that the {item['method']} parameter '{item['parameter']}' is injectable"
                        + (f" using {item['technique']}" if item.get("technique") else "")
                        + (f" (back-end DBMS: {dbms})" if dbms else "")
                        + ". An attacker can alter query semantics and potentially read or modify database contents.",
                        remediation="Use parameterized queries/prepared statements for every database operation, enforce least-privilege database accounts and add input validation as defence in depth. Retest the exact parameter after the fix.",
                        evidence={
                            "parameter": item["parameter"],
                            "method": item["method"],
                            "technique": item.get("technique"),
                            "title": item.get("title"),
                            "dbms": dbms,
                            "output_excerpt": output[:2000],
                        },
                    )
                )
        if not injectable and result.exit_code not in (0, None):
            raise AdapterError(f"SQLMap exited {result.exit_code}: {result.stderr[-500:]}")
        ctx.progress(92, "sqlmap", "Verification complete")
        return {
            "injectable_parameters": len(params),
            "dbms": dbms,
            "level": level,
            "risk": risk,
            "technique": technique,
            "exit_code": result.exit_code,
        }
