from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from km_worker.registry import ADAPTERS
from km_worker.scanners import extra


class FakeContext:
    def __init__(self, target: str = "http://example.com", config: dict | None = None):
        self.target = SimpleNamespace(target=target)
        self.config = config or {}
        self.workdir = Path(tempfile.mkdtemp(prefix="km-extra-test-"))
        self.results = []

    def add_result(self, result):
        self.results.append(result)


def test_new_adapters_are_registered():
    expected = {
        "burp", "ffuf", "whatweb", "wafw00f", "httpx", "subfinder",
        "sslyze", "grype", "semgrep", "gitleaks", "tfsec", "syft", "schemathesis",
    }
    assert expected <= set(ADAPTERS)


def test_severity_mapping():
    assert extra.map_severity("CRITICAL") == "critical"
    assert extra.map_severity("warning") == "medium"
    assert extra.map_severity("ERROR") == "high"
    assert extra.map_severity("unknown", "low") == "low"


def test_host_and_port_extraction():
    assert extra.extract_host("https://example.com/path") == "example.com"
    assert extra.extract_host_port("https://example.com:8443/path") == ("example.com", 8443)
    assert extra.extract_host_port("example.com") == ("example.com", 443)


def test_ffuf_parses_exposed_paths():
    ctx = FakeContext()
    findings = extra.Ffuf().parse(ctx, {"results": [{"input": {"FUZZ": ".env"}, "url": "http://example.com/.env", "status": 200, "length": 42}]})
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "Exposed environment file" in findings[0].title


def test_whatweb_parses_technologies():
    ctx = FakeContext()
    findings = extra.WhatWeb().parse(ctx, [{"target": "http://example.com", "plugins": {"Apache": {"version": ["2.4.58"]}}}])
    assert len(findings) == 1
    assert "Apache" in findings[0].title
    assert findings[0].severity == "info"


def test_wafw00f_parses_detection():
    ctx = FakeContext()
    findings = extra.WafW00f().parse(ctx, [{"url": "http://example.com", "detected": True, "firewall": "Cloudflare"}])
    assert len(findings) == 1
    assert "Cloudflare" in findings[0].title


def test_httpx_parses_probe():
    ctx = FakeContext()
    findings = extra.Httpx().parse(ctx, [{"url": "http://example.com", "status_code": 200, "title": "Home", "tech": ["nginx"], "webserver": "nginx"}])
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "nginx" in findings[0].description


def test_subfinder_parses_hosts():
    ctx = FakeContext()
    findings = extra.Subfinder().parse(ctx, [{"host": "api.example.com", "source": "crtsh"}])
    assert len(findings) == 1
    assert findings[0].endpoint == "https://api.example.com"


def test_grype_parses_vulnerabilities():
    ctx = FakeContext()
    data = {"matches": [{"vulnerability": {"id": "CVE-2026-0001", "severity": "High", "description": "A vulnerable package.", "fix": {"versions": ["1.2.4"]}}, "artifact": {"name": "openssl", "version": "1.2.3"}}]}
    findings = extra.Grype().parse(ctx, data)
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2026-0001"
    assert "Upgrade openssl" in findings[0].remediation


def test_semgrep_parses_results():
    ctx = FakeContext()
    data = {"results": [{"check_id": "python.lang.security.audit.eval", "path": "app.py", "start": {"line": 12}, "extra": {"message": "Avoid eval.", "severity": "ERROR", "metadata": {"cwe": ["CWE-95"]}}}]}
    findings = extra.Semgrep().parse(ctx, data)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].cwe == "CWE-95"


def test_gitleaks_parses_leaks():
    ctx = FakeContext()
    findings = extra.Gitleaks().parse(ctx, [{"RuleID": "aws-access-token", "File": "config.py", "StartLine": 4, "Description": "AWS key"}])
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Rotate the exposed secret" in findings[0].remediation


def test_tfsec_parses_results():
    ctx = FakeContext()
    findings = extra.Tfsec().parse(ctx, {"results": [{"rule_id": "AVD-AWS-0086", "long_id": "aws-s3-enable-bucket-encryption", "severity": "HIGH", "description": "S3 bucket is not encrypted.", "resolution": "Enable encryption.", "location": {"filename": "main.tf", "start_line": 3}}]})
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Enable encryption" in findings[0].remediation


def test_syft_reports_inventory():
    ctx = FakeContext()
    findings = extra.Syft().parse(ctx, {"artifacts": [{"name": "openssl"}, {"name": "python"}]})
    assert len(findings) == 1
    assert "2 packages" in findings[0].title


def test_allowed_path_requires_root(monkeypatch):
    monkeypatch.setattr(extra.config, "CHECKOV_ALLOWED_ROOT", "")
    with pytest.raises(extra.AdapterError, match="disabled"):
        extra.allowed_path("/tmp")


def test_burp_probe_is_unavailable_without_configuration(monkeypatch):
    monkeypatch.setattr(extra.config, "BURP_URL", "")
    result = extra.Burp.probe()
    assert result["available"] is False
    assert "BURP_URL" in result["error"]
