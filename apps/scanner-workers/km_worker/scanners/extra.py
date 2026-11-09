from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import httpx

from ..config import config
from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError
from .gobuster import HOT_PATTERNS


def map_severity(value, default: str = "medium") -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "error": "high",
        "warning": "medium",
        "note": "low",
    }
    return mapping.get(str(value or "").strip().lower(), default)


def extract_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return parsed.hostname or target


def extract_host_port(target: str, default_port: int = 443) -> tuple[str, int]:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return parsed.hostname or target, parsed.port or default_port


def allowed_path(target: str) -> Path:
    if not config.CHECKOV_ALLOWED_ROOT:
        raise AdapterError("This scanner is disabled: set CHECKOV_ALLOWED_ROOT to a directory mounted into the worker.")
    root = Path(config.CHECKOV_ALLOWED_ROOT).resolve()
    try:
        path = Path(target).resolve()
        path.relative_to(root)
    except (ValueError, OSError):
        raise AdapterError("Scan target must be a local path inside CHECKOV_ALLOWED_ROOT")
    if not path.exists():
        raise AdapterError(f"Scan target does not exist in the worker: {path}")
    return path


class JSONAdapter(Adapter):
    output_name = "output.json"
    timeout = 600

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        raise NotImplementedError

    def load(self, output_path: Path):
        return json.loads(output_path.read_text(errors="ignore"))

    def parse(self, ctx: JobContext, data):
        raise NotImplementedError

    def summary(self, ctx: JobContext, data) -> dict:
        return {}

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or self.binary_key
        output_path = ctx.workdir / self.output_name
        args = self.build_args(ctx, output_path)
        ctx.progress(10, self.name, f"{self.display} starting against {ctx.target.target}")
        execution_id = ctx.start_execution(self.display + " " + " ".join(args[1:]))
        result = ctx.run_command(args, timeout=self.timeout, label=self.name)
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or f"{self.display} is unavailable")
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise AdapterError(f"{self.display} produced no output (exit {result.exit_code}): {result.stderr[-700:]}")
        try:
            data = self.load(output_path)
        except (json.JSONDecodeError, OSError) as exc:
            raise AdapterError(f"{self.display} output could not be parsed: {exc}") from exc
        findings = self.parse(ctx, data) or []
        for finding in findings:
            ctx.add_result(finding)
        ctx.progress(95, self.name, f"{len(ctx.results)} findings")
        return {"findings": len(ctx.results), "exit_code": result.exit_code, **self.summary(ctx, data)}


class JSONLAdapter(JSONAdapter):
    output_name = "output.jsonl"

    def load(self, output_path: Path):
        records = []
        for line in output_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


class Ffuf(JSONAdapter):
    name = "ffuf"
    category = "web"
    binary_key = "ffuf"
    display = "ffuf"
    output_name = "ffuf.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        binary = self.binary() or "ffuf"
        wordlist = config.DIR_WORDLIST
        preset = str(ctx.config.get("wordlist", "common"))
        if preset == "small":
            words = wordlist.read_text(errors="ignore").splitlines()[:30]
            custom = ctx.workdir / "wordlist.txt"
            custom.write_text("\n".join(words))
            wordlist = custom
        threads = max(1, min(20, int(ctx.config.get("threads", 10) or 10)))
        target = ctx.target.target.rstrip("/") + "/FUZZ"
        args = [
            binary, "-u", target, "-w", str(wordlist), "-t", str(threads),
            "-mc", "200,204,301,302,401,403", "-of", "json", "-o", str(output_path), "-s",
        ]
        extensions = ctx.config.get("extensions") or []
        if extensions:
            args += ["-e", ",".join("." + str(item).lstrip(".") for item in extensions)]
        return args

    def parse(self, ctx: JobContext, data):
        results = data.get("results", []) if isinstance(data, dict) else []
        out = []
        for record in results[:300]:
            path = str((record.get("input") or {}).get("FUZZ") or "")
            if not path.startswith("/"):
                path = "/" + path
            url = record.get("url") or ctx.target.target.rstrip("/") + path
            status = int(record.get("status", 0) or 0)
            length = int(record.get("length", 0) or 0)
            category = None
            for pattern, severity, title, remediation in HOT_PATTERNS:
                if pattern.search(path.lower()):
                    category = (severity, title, remediation)
                    break
            if not category:
                continue
            severity = category[0]
            if status in (401, 403) and severity in {"critical", "high"}:
                severity = "info"
            out.append(
                NormalizedResult(
                    title=f"{category[1]}: {path}",
                    severity=severity,
                    confidence="firm" if status in (200, 204, 301, 302) else "tentative",
                    endpoint=url,
                    cwe="CWE-538",
                    description=f"ffuf found {path} returning HTTP {status} (size {length} bytes). Confirm the content and whether the path should be publicly reachable.",
                    remediation=category[2],
                    evidence={"path": path, "status": status, "length": length, "wordlist": ctx.config.get("wordlist", "common")},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"paths_found": len(data.get("results", []) if isinstance(data, dict) else [])}


class WhatWeb(JSONAdapter):
    name = "whatweb"
    category = "web"
    binary_key = "whatweb"
    display = "WhatWeb"
    output_name = "whatweb.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        return [self.binary() or "whatweb", f"--log-json={output_path}", "--no-errors", "--color=never", ctx.target.target]

    def load(self, output_path: Path):
        text = output_path.read_text(errors="ignore").strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return [json.loads(line) for line in text.splitlines() if line.strip()]

    def parse(self, ctx: JobContext, data):
        records = data if isinstance(data, list) else [data]
        out = []
        for record in records:
            if not isinstance(record, dict):
                continue
            target = record.get("target") or ctx.target.target
            plugins = record.get("plugins") or {}
            for name, details in list(plugins.items())[:50]:
                version = ""
                if isinstance(details, dict):
                    version = ", ".join(str(item) for item in (details.get("version") or []) if item)
                out.append(
                    NormalizedResult(
                        title=f"Technology detected: {name}",
                        severity="info",
                        confidence="firm",
                        endpoint=target,
                        cwe="CWE-200",
                        description=f"WhatWeb identified {name}" + (f" version {version}" if version else "") + ". Technology and version disclosure can help an attacker choose exploits.",
                        remediation="Remove unnecessary version banners, keep the component patched and hide stack details where possible.",
                        evidence={"technology": name, "version": version, "plugins": details},
                    )
                )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        records = data if isinstance(data, list) else [data]
        return {"technologies": sum(len((r.get("plugins") or {})) for r in records if isinstance(r, dict))}


class WafW00f(JSONAdapter):
    name = "wafw00f"
    category = "web"
    binary_key = "wafw00f"
    display = "WAFW00F"
    output_name = "wafw00f.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        return [self.binary() or "wafw00f", "-o", str(output_path), "-f", "json", ctx.target.target]

    def parse(self, ctx: JobContext, data):
        records = data if isinstance(data, list) else [data]
        out = []
        for record in records:
            if not isinstance(record, dict):
                continue
            detected = bool(record.get("detected"))
            firewall = record.get("firewall") or record.get("manufacturer") or "unknown"
            out.append(
                NormalizedResult(
                    title=f"WAF detected: {firewall}" if detected else "No WAF detected",
                    severity="info",
                    confidence="firm",
                    endpoint=record.get("url") or ctx.target.target,
                    cwe="CWE-693",
                    description="A web application firewall was detected in front of the target." if detected else "No web application firewall was identified by WAFW00F.",
                    remediation="Ensure WAF rules are tuned, monitored and updated; do not rely on the WAF as the only control." if detected else "Consider deploying a WAF or reverse proxy with managed rules and monitoring.",
                    evidence={"detected": detected, "firewall": firewall, "raw": record},
                )
            )
        return out


class Httpx(JSONLAdapter):
    name = "httpx"
    category = "web"
    binary_key = "httpx"
    display = "httpx"
    output_name = "httpx.jsonl"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        return [
            self.binary() or "httpx", "-u", ctx.target.target, "-json", "-o", str(output_path),
            "-silent", "-no-color", "-status-code", "-title", "-tech-detect", "-web-server", "-tls-grab",
        ]

    def parse(self, ctx: JobContext, data):
        out = []
        for record in data[:30]:
            if not isinstance(record, dict):
                continue
            url = record.get("url") or ctx.target.target
            status = record.get("status_code")
            title = record.get("title") or ""
            tech = record.get("tech") or []
            webserver = record.get("webserver") or ""
            tls = record.get("tls") or {}
            description = f"HTTP probe returned {status}" + (f" with title '{title}'" if title else "")
            if webserver:
                description += f". Server: {webserver}"
            if tech:
                description += f". Technologies: {', '.join(str(item) for item in tech)}"
            description += "."
            out.append(
                NormalizedResult(
                    title=f"HTTP probe: {url}",
                    severity="info",
                    confidence="firm",
                    endpoint=url,
                    cwe="CWE-200",
                    description=description,
                    remediation="Remove unnecessary server and technology banners and keep the stack patched.",
                    evidence={"status": status, "title": title, "tech": tech, "webserver": webserver, "tls": tls},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"hosts": len(data)}


class Subfinder(JSONLAdapter):
    name = "subfinder"
    category = "web"
    binary_key = "subfinder"
    display = "Subfinder"
    output_name = "subfinder.jsonl"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        host = extract_host(ctx.target.target)
        try:
            import ipaddress

            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise AdapterError("Subfinder requires a domain target, not an IP address")
        args = [self.binary() or "subfinder", "-d", host, "-json", "-o", str(output_path), "-silent"]
        if bool(ctx.config.get("all_sources", True)):
            args.append("-all")
        return args

    def parse(self, ctx: JobContext, data):
        out = []
        for record in data[:50]:
            if not isinstance(record, dict):
                continue
            host = record.get("host") or ""
            if not host:
                continue
            out.append(
                NormalizedResult(
                    title=f"Subdomain discovered: {host}",
                    severity="info",
                    confidence="firm",
                    endpoint=f"https://{host}",
                    cwe="CWE-200",
                    description=f"Passive enumeration discovered the subdomain {host}. Confirm it is expected, owned and in scope before assessing it.",
                    remediation="Remove stale DNS records, keep an inventory of public hostnames and restrict non-production subdomains.",
                    evidence={"host": host, "source": record.get("source", ""), "raw": record},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"subdomains": len(data)}


class Sslyze(JSONAdapter):
    name = "sslyze"
    category = "network"
    binary_key = "sslyze"
    display = "SSLyze"
    output_name = "sslyze.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        host, port = extract_host_port(ctx.target.target)
        return [self.binary() or "sslyze", f"--json_out={output_path}", f"{host}:{port}"]

    def parse(self, ctx: JobContext, data):
        results = data.get("server_scan_results") if isinstance(data, dict) else None
        if not results:
            return [
                NormalizedResult(
                    title="TLS assessment completed",
                    severity="info",
                    confidence="firm",
                    endpoint=ctx.target.target,
                    cwe="CWE-326",
                    description="SSLyze completed a TLS assessment. Review the evidence for protocol, cipher and certificate details.",
                    remediation="Disable legacy protocols and weak ciphers, and keep certificates current.",
                    evidence={"raw": data},
                )
            ]
        out = []
        for result in results:
            location = result.get("server_location") or {}
            host = location.get("hostname") or ctx.target.target
            port = location.get("port") or 443
            scan = result.get("scan_result") or {}
            endpoint = f"{host}:{port}"
            for version, label in (("tls_1_0", "TLS 1.0"), ("tls_1_1", "TLS 1.1")):
                detail = scan.get(version) or {}
                if detail.get("is_tls_version_supported"):
                    out.append(
                        NormalizedResult(
                            title=f"Legacy {label} supported",
                            severity="medium",
                            confidence="certain",
                            endpoint=endpoint,
                            cwe="CWE-326",
                            description=f"The server accepted {label}, which is deprecated and weak.",
                            remediation=f"Disable {label} and require TLS 1.2 or newer.",
                            evidence={"version": label, "supported": True},
                        )
                    )
            if not out:
                out.append(
                    NormalizedResult(
                        title="TLS assessment completed",
                        severity="info",
                        confidence="firm",
                        endpoint=endpoint,
                        cwe="CWE-326",
                        description="SSLyze completed a TLS assessment. Review the evidence for protocol, cipher and certificate details.",
                        remediation="Disable legacy protocols and weak ciphers, and keep certificates current.",
                        evidence={"server_scan_result": scan},
                    )
                )
        return out


class Grype(JSONAdapter):
    name = "grype"
    category = "infrastructure"
    binary_key = "grype"
    display = "Grype"
    output_name = "grype.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        return [self.binary() or "grype", ctx.target.target, "-o", "json", "--file", str(output_path), "--fail-on", "never"]

    def parse(self, ctx: JobContext, data):
        selected = {str(item).lower() for item in (ctx.config.get("severity") or [])}
        out = []
        for match in (data.get("matches") or [])[:300]:
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            severity = map_severity(vulnerability.get("severity"), "medium")
            if selected and severity not in selected:
                continue
            identifier = vulnerability.get("id") or "Vulnerability"
            package = artifact.get("name") or "package"
            version = artifact.get("version") or ""
            fix_versions = (vulnerability.get("fix") or {}).get("versions") or []
            remediation = f"Upgrade {package} to a patched version" + (f" ({', '.join(str(v) for v in fix_versions)})" if fix_versions else "") + "."
            out.append(
                NormalizedResult(
                    title=f"{identifier} in {package}"[:240],
                    severity=severity,
                    confidence="firm",
                    endpoint=f"{package}@{version}" if version else package,
                    cve=identifier if str(identifier).upper().startswith("CVE-") else "",
                    cwe="CWE-1104",
                    description=(vulnerability.get("description") or "A vulnerable package version was detected.")[:5000],
                    remediation=remediation,
                    evidence={"vulnerability": identifier, "package": package, "version": version, "fix_versions": fix_versions, "severity": severity},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"matches": len(data.get("matches", []) if isinstance(data, dict) else [])}


class Semgrep(JSONAdapter):
    name = "semgrep"
    category = "infrastructure"
    binary_key = "semgrep"
    display = "Semgrep"
    output_name = "semgrep.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        path = allowed_path(str(ctx.config.get("scan_path") or ctx.target.target))
        ruleset = str(ctx.config.get("ruleset", "auto") or "auto")
        config_arg = "auto" if ruleset == "auto" else ("p/owasp-top-ten" if ruleset == "owasp-top-ten" else "p/security-audit")
        return [self.binary() or "semgrep", "--json", "--config", config_arg, "--output", str(output_path), "--quiet", str(path)]

    def parse(self, ctx: JobContext, data):
        out = []
        for result in (data.get("results") or [])[:300]:
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            cwe = ""
            cwe_value = metadata.get("cwe")
            if isinstance(cwe_value, list) and cwe_value:
                cwe = str(cwe_value[0])
            elif cwe_value:
                cwe = str(cwe_value)
            line = (result.get("start") or {}).get("line") or ""
            out.append(
                NormalizedResult(
                    title=f"Semgrep: {result.get('check_id') or 'finding'}"[:240],
                    severity=map_severity(extra.get("severity"), "medium"),
                    confidence="firm",
                    endpoint=f"{result.get('path') or ctx.target.target}:{line}",
                    cwe=cwe,
                    description=(extra.get("message") or "A Semgrep rule matched the source code.")[:5000],
                    remediation="Review the Semgrep rule and apply the recommended code change. Add a regression test for the affected path.",
                    evidence={"check_id": result.get("check_id"), "path": result.get("path"), "line": line, "metadata": metadata},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"results": len(data.get("results", []) if isinstance(data, dict) else [])}


class Gitleaks(JSONAdapter):
    name = "gitleaks"
    category = "infrastructure"
    binary_key = "gitleaks"
    display = "Gitleaks"
    output_name = "gitleaks.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        path = allowed_path(str(ctx.config.get("scan_path") or ctx.target.target))
        return [self.binary() or "gitleaks", "detect", "--source", str(path), "--report-format", "json", "--report-path", str(output_path), "--no-git", "--exit-code", "0"]

    def parse(self, ctx: JobContext, data):
        records = data if isinstance(data, list) else []
        out = []
        for leak in records[:300]:
            if not isinstance(leak, dict):
                continue
            rule = leak.get("RuleID") or "secret"
            file = leak.get("File") or ""
            line = leak.get("StartLine") or ""
            out.append(
                NormalizedResult(
                    title=f"Secret detected: {rule}"[:240],
                    severity="high",
                    confidence="firm",
                    endpoint=f"{file}:{line}",
                    cwe="CWE-798",
                    description=(leak.get("Description") or "A secret was detected in the repository.")[:5000],
                    remediation="Rotate the exposed secret immediately, remove it from version history and use a secret manager or environment variables.",
                    evidence={"rule": rule, "file": file, "line": line, "raw": leak},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"leaks": len(data if isinstance(data, list) else [])}


class Tfsec(JSONAdapter):
    name = "tfsec"
    category = "infrastructure"
    binary_key = "tfsec"
    display = "tfsec"
    output_name = "tfsec.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        path = allowed_path(str(ctx.config.get("scan_path") or ctx.target.target))
        return [self.binary() or "tfsec", str(path), "--format", "json", "--out", str(output_path), "--no-color"]

    def parse(self, ctx: JobContext, data):
        out = []
        for result in (data.get("results") or [])[:300]:
            location = result.get("location") or {}
            out.append(
                NormalizedResult(
                    title=f"tfsec: {result.get('long_id') or result.get('rule_id') or 'misconfiguration'}"[:240],
                    severity=map_severity(result.get("severity"), "medium"),
                    confidence="firm",
                    endpoint=f"{location.get('filename') or ctx.target.target}:{location.get('start_line') or ''}",
                    cwe="CWE-693",
                    description=(result.get("description") or "A Terraform misconfiguration was detected.")[:5000],
                    remediation=(result.get("resolution") or "Review the tfsec guidance and update the Terraform definition.")[:5000],
                    evidence={"rule_id": result.get("rule_id"), "long_id": result.get("long_id"), "location": location},
                )
            )
        return out

    def summary(self, ctx: JobContext, data) -> dict:
        return {"results": len(data.get("results", []) if isinstance(data, dict) else [])}


class Syft(JSONAdapter):
    name = "syft"
    category = "infrastructure"
    binary_key = "syft"
    display = "Syft"
    output_name = "syft.json"

    def build_args(self, ctx: JobContext, output_path: Path) -> list[str]:
        return [self.binary() or "syft", ctx.target.target, "-o", "json", "--file", str(output_path)]

    def parse(self, ctx: JobContext, data):
        artifacts = (data.get("artifacts") or []) if isinstance(data, dict) else []
        if not artifacts:
            return []
        return [
            NormalizedResult(
                title=f"SBOM generated: {len(artifacts)} packages",
                severity="info",
                confidence="firm",
                endpoint=ctx.target.target,
                cwe="CWE-1104",
                description=f"Syft inventoried {len(artifacts)} packages. Use this inventory with a vulnerability scanner such as Grype.",
                remediation="Review the SBOM and scan the image with Grype or Trivy. Track and patch vulnerable dependencies.",
                evidence={"count": len(artifacts), "packages": [a.get("name") for a in artifacts[:50]]},
            )
        ]

    def summary(self, ctx: JobContext, data) -> dict:
        return {"packages": len(data.get("artifacts", []) if isinstance(data, dict) else [])}


class Schemathesis(Adapter):
    name = "schemathesis"
    category = "web"
    binary_key = "schemathesis"
    display = "Schemathesis"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "schemathesis"
        target = ctx.target.target.rstrip("/")
        schema_url = target if target.endswith(".json") or target.endswith(".yaml") else target + "/openapi.json"
        report_dir = ctx.workdir / "schemathesis"
        report_dir.mkdir(parents=True, exist_ok=True)
        max_examples = max(5, min(100, int(ctx.config.get("max_examples", 10) or 10)))
        args = [
            binary, "run", schema_url, "--base-url", target, "--checks", "all",
            "--max-examples", str(max_examples), "--report", "junit", "--report-dir", str(report_dir),
        ]
        ctx.progress(10, "schemathesis", "Property-based API testing")
        execution_id = ctx.start_execution("schemathesis run <schema> --base-url <target>")
        result = ctx.run_command(args, timeout=min(600, max(120, int(ctx.deadline - time.monotonic()))), label="schemathesis")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "schemathesis is unavailable")
        xml_files = list(report_dir.rglob("*.xml"))
        if not xml_files:
            raise AdapterError(f"Schemathesis produced no JUnit report (exit {result.exit_code}): {result.stderr[-700:]}")
        failures = 0
        for xml_file in xml_files:
            try:
                root = ET.fromstring(xml_file.read_text(errors="ignore"))
            except ET.ParseError:
                continue
            for testcase in root.iter("testcase"):
                node = testcase.find("failure")
                if node is None:
                    node = testcase.find("error")
                if node is None:
                    continue
                name = testcase.get("name") or "API property failure"
                message = (node.get("message") or node.text or "The API did not satisfy the schema property.")[:4000]
                ctx.add_result(
                    NormalizedResult(
                        title=f"Schemathesis: {name}"[:240],
                        severity="medium",
                        confidence="firm",
                        endpoint=target,
                        cwe="CWE-20",
                        description=message,
                        remediation="Fix the API contract violation, validate input and add a regression test for this operation.",
                        evidence={"test": name, "message": message},
                    )
                )
                failures += 1
        return {"failures": failures, "findings": len(ctx.results), "schema": schema_url, "max_examples": max_examples}


class Burp(Adapter):
    name = "burp"
    category = "web"
    binary_key = None
    display = "Burp Suite"

    @classmethod
    def probe(cls) -> dict:
        if not config.BURP_URL:
            return {"available": False, "version": "", "path": "BURP_URL", "error": "BURP_URL is not configured"}
        try:
            headers = {"Authorization": f"Bearer {config.BURP_API_KEY}"} if config.BURP_API_KEY else {}
            response = httpx.get(config.BURP_URL + "/v0.1/scan", headers=headers, timeout=5, trust_env=False)
            if response.status_code < 400:
                return {"available": True, "version": "Burp REST API", "path": config.BURP_URL, "error": ""}
            return {"available": False, "version": "", "path": config.BURP_URL, "error": f"Burp REST API returned {response.status_code}"}
        except Exception as exc:
            return {"available": False, "version": "", "path": config.BURP_URL, "error": f"Burp unreachable: {exc}"}

    def run(self, ctx: JobContext) -> dict:
        if not config.BURP_URL:
            raise AdapterError("BURP_URL is not configured")
        mode = str(ctx.config.get("mode", "crawl") or "crawl")
        max_minutes = max(1, min(30, int(ctx.config.get("max_duration_minutes", 5) or 5)))
        headers = {"Content-Type": "application/json"}
        if config.BURP_API_KEY:
            headers["Authorization"] = f"Bearer {config.BURP_API_KEY}"
        body = {"urls": [ctx.target.target], "scan_configurations": [{"name": "Audit" if mode == "audit" else "Crawl", "type": "NamedConfiguration"}]}
        ctx.progress(10, "burp", f"Submitting {mode} scan to Burp Suite")
        try:
            with httpx.Client(base_url=config.BURP_URL, headers=headers, timeout=30, trust_env=False) as client:
                response = client.post("/v0.1/scan", json=body)
                response.raise_for_status()
                payload = response.json()
                scan_id = payload.get("id") or payload.get("scan_id") or payload.get("task_id")
                if not scan_id:
                    raise AdapterError(f"Burp did not return a scan id: {payload}")
                deadline = time.monotonic() + max_minutes * 60
                status = ""
                detail = {}
                while time.monotonic() < deadline:
                    ctx.raise_if_cancelled()
                    detail_response = client.get(f"/v0.1/scan/{scan_id}")
                    detail_response.raise_for_status()
                    detail = detail_response.json()
                    status = str(detail.get("status") or detail.get("scan_status") or "").lower()
                    ctx.progress(min(90, 20 + int((1 - max(0.0, deadline - time.monotonic()) / (max_minutes * 60)) * 70)), "burp", f"Burp status: {status or 'running'}")
                    if status in {"succeeded", "finished", "complete", "completed", "failed", "error"}:
                        break
                    time.sleep(5)
                if status in {"failed", "error"}:
                    raise AdapterError(f"Burp scan {scan_id} failed: {detail}")
                report = {}
                for path in (f"/v0.1/scan/{scan_id}/report", f"/v0.1/scan/{scan_id}/issues"):
                    try:
                        report_response = client.get(path, params={"report_type": "json"})
                        if report_response.status_code < 400:
                            report = report_response.json()
                            break
                    except Exception:
                        continue
                issues = report.get("issues") or report.get("issue_events") or []
                for issue in issues[:200]:
                    name = issue.get("name") or issue.get("issue_type") or "Burp issue"
                    ctx.add_result(
                        NormalizedResult(
                            title=f"Burp: {name}"[:240],
                            severity=map_severity(issue.get("severity"), "medium"),
                            confidence="firm",
                            endpoint=issue.get("url") or ctx.target.target,
                            description=(issue.get("description") or issue.get("detail") or "Burp Suite reported an issue.")[:5000],
                            remediation=(issue.get("remediation") or "Review the Burp issue and apply the vendor guidance.")[:5000],
                            evidence=issue,
                        )
                    )
                return {"scan_id": scan_id, "mode": mode, "status": status, "issues": len(issues), "findings": len(ctx.results)}
        except httpx.HTTPError as exc:
            raise AdapterError(f"Burp REST API error: {exc}") from exc
