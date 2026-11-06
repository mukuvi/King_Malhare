from __future__ import annotations

from km_worker.redact import redact, register_secrets
from km_worker.runner import NormalizedResult
from km_worker.scanners.base import Adapter
from km_worker.scanners.gobuster import RESULT_RE
from km_worker.scanners.http_baseline import EXPOSURE_PATHS
from km_worker.scanners.nmap import RISKY_PORTS


def test_fingerprint_is_stable_and_scoped_to_scanner():
    one = NormalizedResult(title="Exposed .env", severity="high", endpoint="https://x/.env", description="d")
    two = NormalizedResult(title="Exposed .env", severity="high", endpoint="https://x/.env", description="other")
    one.finalize("nuclei")
    two.finalize("nuclei")
    assert one.fingerprint == two.fingerprint
    three = NormalizedResult(title="Exposed .env", severity="high", endpoint="https://x/.env", description="d")
    three.finalize("nikto")
    assert three.fingerprint != one.fingerprint
    assert len(one.to_dict()["fingerprint"]) == 64


def test_redaction_removes_common_secrets():
    register_secrets(["super-secret-value"])
    text = "Authorization: Bearer abcdefghijklmnop password=hunter2 https://user:pass@example.com super-secret-value"
    out = redact(text)
    assert "hunter2" not in out
    assert "abcdefghijklmnop" not in out
    assert "user:pass" not in out
    assert "super-secret-value" not in out


def test_gobuster_result_regex():
    match = RESULT_RE.search("/admin (Status: 200) [Size: 1234]")
    assert match
    assert match.group(1) == "/admin"
    assert match.group(2) == "200"
    assert match.group(3) == "1234"


def test_exposure_signatures_match_realistic_content():
    def signature(path: str):
        for candidate, _, regex, _, _ in EXPOSURE_PATHS:
            if candidate == path:
                return regex
        raise AssertionError(path)

    assert signature("/.env").search("DB_PASSWORD=secret\nAPI_KEY=abcd")
    assert not signature("/.env").search("<html>not found</html>")
    assert signature("/.git/config").search("[core]\n\trepositoryformatversion = 0")
    assert signature("/actuator/env").search('{"activeProfiles":[],"propertySources":[]}')


def test_risky_ports_are_conservative():
    assert 6379 in RISKY_PORTS
    assert 22 not in RISKY_PORTS  # SSH exposure alone is not a vulnerability
    assert 445 in RISKY_PORTS
    assert RISKY_PORTS[2375][0] == "critical"


def test_builtin_adapters_report_availability():
    from km_worker.scanners.http_baseline import HTTPBaseline
    from km_worker.scanners.auth_baseline import AuthBaseline

    assert HTTPBaseline.probe()["available"] is True
    assert AuthBaseline.probe()["available"] is True


def test_adapter_binary_requirement():
    from km_worker.scanners.nmap import Nmap

    probe = Nmap.probe()
    assert "available" in probe
    assert "path" in probe
    assert Adapter.name == ""
