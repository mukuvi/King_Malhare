from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from km_worker.scope import ScopeError, validate_target


def job(target: str, target_type: str = "web_app", *, allow_private: bool = False, expires_in: int = 24) -> dict:
    expires = (datetime.now(timezone.utc) + timedelta(hours=expires_in)).isoformat()
    return {
        "scan_id": "00000000-0000-0000-0000-000000000001",
        "org_id": "00000000-0000-0000-0000-000000000002",
        "target": target,
        "target_type": target_type,
        "scope": {
            "allow_private": allow_private,
            "intrusive_allowed": False,
            "expires_at": expires,
            "authorized_host": target,
            "approved_targets": [target],
        },
    }


def test_private_target_rejected_without_permission():
    with pytest.raises(ScopeError, match="private"):
        validate_target(job("127.0.0.1", "ip"))


def test_private_target_allowed_with_permission():
    result = validate_target(job("127.0.0.1", "ip", allow_private=True))
    assert result.ips == ["127.0.0.1"]


def test_metadata_always_rejected():
    with pytest.raises(ScopeError, match="metadata"):
        validate_target(job("169.254.169.254", "ip", allow_private=True))
    with pytest.raises(ScopeError):
        validate_target(job("http://metadata.google.internal/latest/meta-data", "web_app", allow_private=True))


def test_expired_authorization_rejected():
    with pytest.raises(ScopeError, match="expired"):
        validate_target(job("127.0.0.1", "ip", allow_private=True, expires_in=-1))


def test_url_credentials_rejected():
    with pytest.raises(ScopeError, match="Credentials"):
        validate_target(job("http://user:pass@127.0.0.1/", allow_private=True))


def test_network_range_limits():
    with pytest.raises(ScopeError, match="too large"):
        validate_target(job("10.0.0.0/8", "network", allow_private=True))
    with pytest.raises(ScopeError, match="metadata"):
        validate_target(job("169.254.0.0/16", "network", allow_private=True))
    with pytest.raises(ScopeError, match="private"):
        validate_target(job("10.0.0.0/24", "network", allow_private=False))
    result = validate_target(job("10.0.0.0/24", "network", allow_private=True))
    assert result.target == "10.0.0.0/24"


def test_cloud_job_requires_provider_credentials():
    data = job("123456789012", "cloud")
    with pytest.raises(ScopeError, match="provider"):
        validate_target(data)
    data["credentials"] = {"provider": "aws", "fields": {"access_key_id": "x"}}
    assert validate_target(data).target == "123456789012"


def test_container_reference_validation():
    with pytest.raises(ScopeError):
        validate_target(job("bad image with spaces", "container"))
    assert validate_target(job("ghcr.io/example/app:1.2.3", "container")).target.startswith("ghcr.io")


def test_private_target_requires_deployment_opt_in(monkeypatch):
    from km_worker.config import config

    monkeypatch.setattr(config, "ALLOW_PRIVATE", False)
    with pytest.raises(ScopeError, match="deployment"):
        validate_target(job("127.0.0.1", "ip", allow_private=True))


def test_authorized_host_mismatch_rejected():
    data = job("http://127.0.0.1:9", "web_app", allow_private=True)
    data["scope"]["authorized_host"] = "other.example.com"
    data["scope"]["approved_targets"] = ["other.example.com"]
    with pytest.raises(ScopeError, match="authorized scope"):
        validate_target(data, allow_private=True)
