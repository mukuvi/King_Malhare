from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import config
from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError


class Checkov(Adapter):
    name = "checkov"
    category = "infrastructure"
    binary_key = "checkov"
    display = "Checkov"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "checkov"
        target = str(ctx.config.get("scan_path") or ctx.target.target)
        if not config.CHECKOV_ALLOWED_ROOT:
            raise AdapterError("Checkov is disabled: set CHECKOV_ALLOWED_ROOT to a directory mounted into the worker.")
        root = Path(config.CHECKOV_ALLOWED_ROOT).resolve()
        try:
            path = Path(target).resolve()
            path.relative_to(root)
        except (ValueError, OSError):
            raise AdapterError("Checkov target must be a local path inside CHECKOV_ALLOWED_ROOT")
        if not path.exists():
            raise AdapterError(f"Checkov target does not exist in the worker: {path}")
        framework = str(ctx.config.get("framework", "all") or "all")
        args = [binary, "-d", str(path), "-o", "json", "--compact", "--quiet"]
        if framework != "all":
            args += ["--framework", framework]
        ctx.progress(10, "checkov", f"Static analysis of {path.name}")
        execution_id = ctx.start_execution(f"checkov -d <allowlisted path> --framework {framework}")
        result = ctx.run_command(args, timeout=min(840, max(120, int(ctx.deadline - time.monotonic()))), label="checkov")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "checkov is unavailable")
        raw = result.stdout.strip()
        if not raw.startswith("{") and not raw.startswith("["):
            raise AdapterError(f"Checkov did not produce JSON (exit {result.exit_code}): {result.stderr[-500:]}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"Checkov JSON could not be parsed: {exc}") from exc
        payloads = data if isinstance(data, list) else [data]
        count = 0
        for payload in payloads:
            results = payload.get("results", {}) if isinstance(payload, dict) else {}
            for check in results.get("failed_checks", []) or []:
                severity = str(check.get("severity") or "medium").lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "medium"
                ctx.add_result(
                    NormalizedResult(
                        title=f"Checkov: {check.get('check_name') or check.get('check_id')}"[:240],
                        severity=severity,
                        confidence="firm",
                        endpoint=f"{check.get('file_path', target)}:{check.get('file_line_range', ['', ''])[0] if isinstance(check.get('file_line_range'), list) else ''}",
                        cwe="CWE-693",
                        description=(check.get("check_name") or "IaC check failed") + ". " + (check.get("guideline") or "The infrastructure definition failed a security benchmark check.")[:4500],
                        remediation=(check.get("guideline") or "Review the Checkov guidance and update the infrastructure definition.")[:5000],
                        evidence={"check_id": check.get("check_id"), "bc_check_id": check.get("bc_check_id"),
                                  "file": check.get("file_path"), "resource": check.get("resource"), "framework": framework},
                    )
                )
                count += 1
        return {"failed_checks": count, "framework": framework, "path": str(path), "findings": count}
