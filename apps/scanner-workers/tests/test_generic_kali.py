from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from km_worker.kali_tools import KALI_TOOLS
from km_worker.registry import ADAPTERS
from km_worker.scanners.generic import GenericKaliAdapter


class FakeContext:
    def __init__(self, target: str = "http://example.com:8443/path", intrusive: bool = False):
        self.target = SimpleNamespace(target=target)
        self.config = {}
        self.scope = {"intrusive_allowed": intrusive}
        self.workdir = Path(tempfile.mkdtemp(prefix="km-generic-test-"))
        self.results = []
        self.deadline = 9999999999

    def progress(self, *args, **kwargs):
        return None

    def start_execution(self, command: str) -> str:
        return "exec-1"

    def finish_execution(self, *args, **kwargs):
        return None

    def run_command(self, args, timeout=None, env=None, label="", line_callback=None):
        return SimpleNamespace(status="completed", exit_code=0, stdout="demo output", stderr="")

    def add_result(self, result):
        self.results.append(result)

    def raise_if_cancelled(self):
        return None


class DemoAdapter(GenericKaliAdapter):
    name = "demo"
    category = "web"
    binary_key = "demo"
    display = "Demo"
    command = ["demo", "{host}", "{port}", "{output}", "{wordlist}"]
    output_name = "demo.json"
    parser = "raw"


def test_kali_tools_are_registered():
    for tool in KALI_TOOLS:
        assert tool["name"] in ADAPTERS, tool["name"]


def test_generic_adapter_builds_argument_vector():
    adapter = DemoAdapter()
    ctx = FakeContext()
    args = adapter._args(ctx)
    assert args[0] == "demo"
    assert args[1] == "example.com"
    assert args[2] == "8443"
    assert args[3].endswith("demo.json")
    assert args[4].endswith("common.txt")


def test_generic_adapter_maps_json_record():
    adapter = DemoAdapter()
    ctx = FakeContext()
    finding = adapter._finding_from_record(
        ctx,
        {
            "title": "Exposed admin panel",
            "severity": "HIGH",
            "url": "http://example.com/admin",
            "cve": "CVE-2026-0001",
            "cwe": "CWE-284",
            "description": "An administrative panel is reachable.",
            "remediation": "Restrict the panel to trusted networks.",
        },
    )
    assert finding.title == "Exposed admin panel"
    assert finding.severity == "high"
    assert finding.cve == "CVE-2026-0001"
    assert finding.cwe == "CWE-284"
    assert "Restrict the panel" in finding.remediation


def test_generic_adapter_raw_finding_contains_real_output():
    adapter = DemoAdapter()
    ctx = FakeContext()
    finding = adapter._raw_finding(ctx, "found something real", "", 0, None)
    assert finding.severity == "info"
    assert "found something real" in finding.evidence["stdout"]
    assert finding.evidence["tool"] == "demo"


def test_generic_adapter_probe_reports_missing_binary():
    class MissingAdapter(GenericKaliAdapter):
        name = "definitely-not-installed"
        binary_key = "definitely-not-installed"
        display = "Missing"
        command = ["definitely-not-installed", "{target}"]

    result = MissingAdapter.probe()
    assert result["available"] is False
    assert "not installed" in result["error"]


def test_generic_adapter_intrusive_gate():
    class IntrusiveDemo(GenericKaliAdapter):
        name = "demo-intrusive"
        binary_key = "demo"
        display = "Demo intrusive"
        command = ["demo", "{target}"]
        intrusive = True

    with pytest.raises(Exception, match="intrusive"):
        IntrusiveDemo().run(FakeContext(intrusive=False))
