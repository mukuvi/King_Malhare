from __future__ import annotations

import json
import time

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError


class Nuclei(Adapter):
    name = "nuclei"
    category = "web"
    binary_key = "nuclei"
    display = "Nuclei"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "nuclei"
        target = ctx.target.target
        severity = ctx.config.get("severity") or ["medium", "high", "critical"]
        tags = ctx.config.get("tags") or []
        rate = int(ctx.config.get("rate_limit", 40) or 40)
        timeout = int(ctx.config.get("timeout", 10) or 10)

        args = [
            binary, "-u", target, "-jsonl", "-silent", "-no-color",
            "-disable-update-check", "-no-interactsh",
            "-rate-limit", str(rate), "-timeout", str(timeout),
            "-severity", ",".join(str(s) for s in severity),
        ]
        # -stats writes progress lines to stderr; keep the JSONL stream clean on stdout.
        args += ["-stats", "-stats-interval", "10"]
        template_path = None
        bundled = __import__("pathlib").Path(__file__).resolve().parent.parent / "nuclei_templates"
        if ctx.config.get("templates"):
            template_path = str(ctx.config["templates"])
            args += ["-t", template_path]
        else:
            import os
            from ..config import config

            if config.NUCLEI_TEMPLATES:
                args += ["-t", config.NUCLEI_TEMPLATES]
                template_path = config.NUCLEI_TEMPLATES
            else:
                home_templates = os.path.expanduser("~/.local/nuclei-templates")
                if os.path.isdir(home_templates):
                    template_path = home_templates
                elif os.path.isdir(bundled):
                    args += ["-t", str(bundled)]
                    template_path = str(bundled)
        if tags:
            args += ["-tags", ",".join(str(t) for t in tags)]
        ctx.progress(10, "nuclei", "Running template set")
        execution_id = ctx.start_execution("nuclei -u <target> " + " ".join(args[3:]))
        stats_seen: list[str] = []

        def on_line(line: str):
            if line.startswith("[") and "templates" in line:
                stats_seen.append(line[:200])
                ctx.progress(min(85, 10 + len(stats_seen) * 5), "nuclei", line[:180])

        remaining = max(60, int(ctx.deadline - time.monotonic()))
        result = ctx.run_command(args, timeout=min(840, remaining), label="nuclei", line_callback=on_line)
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "nuclei is unavailable")
        records = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        combined = (result.stderr or "") + (result.stdout or "")
        if not template_path and "no templates" in combined.lower():
            raise AdapterError("Nuclei has no templates installed. Set NUCLEI_TEMPLATES or install the nuclei-templates repository in the worker image.")
        if result.exit_code not in (0, None) and not records:
            raise AdapterError(f"nuclei exited {result.exit_code}: {result.stderr[-700:]}")
        ctx.progress(80, "nuclei", f"Parsing {len(records)} template matches")
        for record in records:
            self._normalize(ctx, record)
        ctx.progress(95, "nuclei", f"{len(ctx.results)} findings")
        return {
            "templates": template_path or "default template set",
            "tags": tags,
            "severity": severity,
            "matches": len(records),
            "findings": len(ctx.results),
            "stats": stats_seen[-4:],
        }

    def _normalize(self, ctx: JobContext, record: dict) -> None:
        info = record.get("info") or {}
        classification = info.get("classification") or {}
        name = (info.get("name") or record.get("template-id") or "Nuclei template match").strip()
        template_id = record.get("template-id", "")
        severity = (info.get("severity") or "info").lower()
        if severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
            severity = "info"
        if severity == "unknown":
            severity = "info"
        cve = self._first(classification.get("cve-id"))
        cwe = self._first(classification.get("cwe-id"))
        if cwe and not str(cwe).upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        cvss = None
        for key in ("cvss-score", "cvss_score"):
            try:
                if classification.get(key) is not None:
                    cvss = float(classification[key])
                    break
            except (TypeError, ValueError):
                pass
        endpoint = record.get("matched-at") or record.get("host") or ctx.target.target
        evidence = {
            "template_id": template_id,
            "matcher": record.get("matcher-name", ""),
            "extracted": record.get("extracted-results", [])[:20],
            "request": (record.get("request") or "")[:1500],
            "response": (record.get("response") or "")[:2500],
            "host": record.get("host", ""),
        }
        description = info.get("description") or f"The Nuclei template {template_id} matched the target response. Review the evidence to confirm exploitability in this context."
        remediation = info.get("remediation") or "Review the matched template and apply the vendor or configuration guidance. Retest after remediation."
        if template_id and template_id not in name:
            name = f"{name} ({template_id})"
        ctx.add_result(
            NormalizedResult(
                title=name,
                severity=severity,
                confidence="firm",
                cve=str(cve or ""),
                cwe=str(cwe or ""),
                cvss=cvss,
                endpoint=str(endpoint)[:2000],
                description=str(description)[:5000],
                remediation=str(remediation)[:5000],
                evidence=evidence,
                raw={k: record.get(k) for k in ("template-id", "type", "host", "matched-at", "matcher-name", "timestamp")},
            )
        )

    @staticmethod
    def _first(value):
        if isinstance(value, list):
            return value[0] if value else ""
        return value or ""
