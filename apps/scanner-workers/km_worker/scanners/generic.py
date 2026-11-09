from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from ..config import config
from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError
from .extra import allowed_path, extract_host, extract_host_port, map_severity


def _first(value, default=""):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value not in (None, "") else default


def _stringify(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)[:4000]
    return str(value or "")[:4000]


class GenericKaliAdapter(Adapter):
    """Run a real Kali CLI tool through an argument vector.

    The catalog supplies the command template and parser. This adapter never
    invokes a shell, never fabricates findings and reports missing binaries as
    unavailable. Tools marked intrusive require an authorization that allows
    intrusive testing.
    """

    command: list[str] = []
    output_mode = "text"
    output_name = "output.txt"
    parser = "raw"
    intrusive = False
    timeout = 600

    @classmethod
    def binary(cls) -> str | None:
        if not cls.binary_key:
            return None
        return config.BINARIES.get(cls.binary_key, cls.binary_key)

    @classmethod
    def probe(cls) -> dict:
        binary = cls.binary()
        if not binary:
            return {"available": False, "version": "", "path": "", "error": f"{cls.display} has no binary configured"}
        path = shutil.which(binary)
        if not path:
            return {"available": False, "version": "", "path": binary, "error": f"{binary} is not installed in the worker image"}
        version = ""
        for args in (["--version"], ["-version"], ["-V"], ["version"], ["-h"]):
            try:
                proc = subprocess.run(
                    [path, *args],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"},
                )
                raw = re.sub(r"\x1b\[[0-9;]*m", "", (proc.stdout or "") + (proc.stderr or ""))
                version = next((line.strip() for line in raw.splitlines() if line.strip()), "")
                if version:
                    break
            except (subprocess.TimeoutExpired, OSError):
                continue
        return {"available": True, "version": version[:160], "path": path, "error": ""}

    def _args(self, ctx: JobContext) -> list[str]:
        binary = self.binary() or self.binary_key or self.name
        host = extract_host(ctx.target.target)
        port = extract_host_port(ctx.target.target)[1]
        output_path = ctx.workdir / self.output_name
        needs_scan_path = any("{scan_path}" in token for token in self.command)
        replacements = {
            "{binary}": binary,
            "{target}": ctx.target.target,
            "{host}": host,
            "{port}": str(port),
            "{wordlist}": str(config.DIR_WORDLIST),
            "{workdir}": str(ctx.workdir),
            "{output}": str(output_path),
            "{scan_path}": str(allowed_path(str(ctx.config.get("scan_path") or ctx.target.target))) if needs_scan_path else "",
        }
        args = []
        for token in self.command:
            value = token
            for key, replacement in replacements.items():
                value = value.replace(key, replacement)
            value = re.sub(r"\{config\.([a-zA-Z0-9_]+)\}", lambda m: str(ctx.config.get(m.group(1), "")), value)
            args.append(value)
        return args

    def _records(self, data) -> list[dict]:
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)][:100]
        if isinstance(data, dict):
            for key in ("results", "matches", "findings", "vulnerabilities", "items", "data", "issues", "alerts", "endpoints", "urls", "records", "plugins"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)][:100]
            return [data]
        return []

    def _finding_from_record(self, ctx: JobContext, record: dict) -> NormalizedResult:
        title = _first(
            record.get("title")
            or record.get("name")
            or record.get("check_id")
            or record.get("rule_id")
            or record.get("template-id")
            or record.get("vulnerability")
            or record.get("id")
            or record.get("type")
            or record.get("issue"),
            f"{self.display} result",
        )
        severity = map_severity(
            record.get("severity") or record.get("risk") or record.get("level") or record.get("confidence"),
            "info",
        )
        endpoint = _first(
            record.get("url")
            or record.get("endpoint")
            or record.get("host")
            or record.get("target")
            or record.get("matched-at")
            or record.get("path")
            or record.get("file"),
            ctx.target.target,
        )
        identifier = str(record.get("cve") or record.get("cve_id") or record.get("id") or "")
        cve = identifier if identifier.upper().startswith("CVE-") else ""
        cwe = str(record.get("cwe") or record.get("cwe_id") or "")
        description = _first(
            record.get("description")
            or record.get("message")
            or record.get("detail")
            or record.get("info")
            or record.get("title"),
            _stringify(record),
        )
        remediation = _first(
            record.get("remediation")
            or record.get("recommendation")
            or record.get("solution")
            or record.get("fix")
            or record.get("resolution"),
            "Review the tool output, confirm the weakness and apply the vendor or configuration guidance. Retest after remediation.",
        )
        return NormalizedResult(
            title=str(title)[:240],
            severity=severity,
            confidence="firm",
            endpoint=str(endpoint)[:2000],
            cve=cve,
            cwe=cwe,
            description=str(description)[:5000],
            remediation=str(remediation)[:5000],
            evidence={"tool": self.name, "record": record},
            raw={"tool": self.name},
        )

    def _raw_finding(self, ctx: JobContext, stdout: str, stderr: str, exit_code: int | None, output_path: Path | None) -> NormalizedResult:
        excerpt = (stdout or "").strip()
        if not excerpt and output_path and output_path.exists():
            excerpt = output_path.read_text(errors="ignore").strip()
        if not excerpt:
            excerpt = "(the tool produced no stdout)"
        evidence = {
            "tool": self.name,
            "command": " ".join(self._args(ctx)),
            "exit_code": exit_code,
            "stdout": excerpt[:4000],
            "stderr": (stderr or "")[:2000],
        }
        return NormalizedResult(
            title=f"{self.display} completed"[:240],
            severity="info",
            confidence="firm",
            endpoint=ctx.target.target,
            description=(
                f"{self.display} completed against {ctx.target.target} and produced output. "
                "Review the evidence for exposed information, misconfiguration or a confirmed weakness."
            ),
            remediation=(
                "Review the tool output and confirm any exposure or weakness before treating it as a finding. "
                "Apply the vendor or configuration guidance and retest after remediation."
            ),
            evidence=evidence,
            raw={"tool": self.name, "exit_code": exit_code},
        )

    def run(self, ctx: JobContext) -> dict:
        if self.intrusive and not bool(ctx.scope.get("intrusive_allowed")):
            raise AdapterError("This tool requires an authorization that explicitly permits intrusive testing")
        args = self._args(ctx)
        output_path = ctx.workdir / self.output_name
        ctx.progress(10, self.name, f"{self.display} starting against {ctx.target.target}")
        execution_id = ctx.start_execution(self.display + " " + " ".join(args[1:]))
        result = ctx.run_command(args, timeout=self.timeout, label=self.name)
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or f"{self.display} is unavailable")
        if result.status == "failed" and not (result.stdout or "").strip() and not output_path.exists():
            raise AdapterError(f"{self.display} failed (exit {result.exit_code}): {result.stderr[-700:]}")

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if self.output_mode == "file" and output_path.exists():
            stdout = output_path.read_text(errors="ignore")

        findings: list[NormalizedResult] = []
        parsed = False
        if self.parser in {"json", "jsonl"} and stdout.strip():
            try:
                if self.parser == "json":
                    data = json.loads(stdout)
                    records = self._records(data)
                else:
                    records = []
                    for line in stdout.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(record, dict):
                            records.append(record)
                    records = records[:100]
                if records:
                    for record in records[:100]:
                        findings.append(self._finding_from_record(ctx, record))
                    parsed = True
            except json.JSONDecodeError:
                parsed = False

        if not parsed and self.parser == "lines" and stdout.strip():
            lines = [line.strip() for line in stdout.splitlines() if line.strip()][:100]
            for line in lines:
                findings.append(
                    NormalizedResult(
                        title=f"{self.display}: {line[:180]}"[:240],
                        severity="info",
                        confidence="firm",
                        endpoint=ctx.target.target,
                        description=line[:5000],
                        remediation="Review the tool output, confirm the weakness and apply the appropriate remediation.",
                        evidence={"tool": self.name, "line": line},
                    )
                )
            parsed = True

        if not findings:
            findings.append(self._raw_finding(ctx, stdout, stderr, result.exit_code, output_path if self.output_mode == "file" else None))

        for finding in findings[:100]:
            ctx.add_result(finding)
        ctx.progress(95, self.name, f"{len(ctx.results)} findings")
        return {
            "tool": self.name,
            "exit_code": result.exit_code,
            "findings": len(ctx.results),
            "output_bytes": len(stdout),
            "parser": self.parser,
        }
