from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .config import config

METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,251}[A-Za-z0-9])?$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{1,300}$")


class ScopeError(Exception):
    pass


@dataclass
class ValidatedTarget:
    target: str
    host: str | None
    ips: list[str]
    is_url: bool


def _is_private(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
    )


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"Target host could not be resolved: {host}") from exc
    ips = []
    for info in infos:
        raw = info[4][0]
        try:
            ips.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    if not ips:
        raise ScopeError(f"Target host resolved to no usable addresses: {host}")
    return sorted(set(ips), key=str)


def _host_from_target(target_type: str, target: str) -> tuple[str | None, bool]:
    if target_type in {"website", "web_app", "api", "graphql_api"}:
        parsed = urlparse(target if "://" in target else "https://" + target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("Target is not a valid HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ScopeError("Credentials embedded in target URLs are not permitted")
        return parsed.hostname.lower(), True
    if target_type in {"ip", "network"}:
        return target, False
    if target_type in {"server", "internal"}:
        host = target
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        elif ":" in target and not target.startswith("["):
            host = target.rsplit(":", 1)[0]
        return host.strip("[]").lower(), False
    return None, False


def validate_target(job: dict, allow_private: bool | None = None) -> ValidatedTarget:
    """Re-validate the job target against the API authorization snapshot.

    The API validated the target at queue time; the worker repeats the checks so a
    compromised queue or stale job cannot bypass scope. Metadata addresses are
    always rejected, and private addresses require explicit authorization.
    """
    target_type = job.get("target_type", "")
    target = (job.get("target") or "").strip()
    scope = job.get("scope") or {}
    if not target:
        raise ScopeError("Job has no target")

    expires_raw = scope.get("expires_at", "")
    try:
        expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            raise ScopeError("Authorization has expired")
    except ValueError as exc:
        raise ScopeError("Authorization expiry is missing or invalid") from exc

    if allow_private is None:
        allow_private = bool(scope.get("allow_private"))

    if target_type == "cloud":
        provider = (job.get("credentials") or {}).get("provider", "")
        if provider not in {"aws", "azure", "gcp"}:
            raise ScopeError("Cloud job is missing a supported provider credential")
        return ValidatedTarget(target=target, host=None, ips=[], is_url=False)

    if target_type == "container":
        if not IMAGE_RE.match(target):
            raise ScopeError("Container image reference is invalid")
        return ValidatedTarget(target=target, host=None, ips=[], is_url=False)

    if target_type == "network":
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            try:
                ip = ipaddress.ip_address(target)
            except ValueError as exc:
                raise ScopeError("Network target is not a valid IP or CIDR") from exc
            network = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
        if network.prefixlen < (16 if network.version == 4 else 112):
            raise ScopeError("Network range is too large; the maximum is /16 (IPv4) or /112 (IPv6)")
        authorized = (scope.get("authorized_host") or "").strip()
        if authorized:
            try:
                if ipaddress.ip_network(authorized, strict=False) != network:
                    raise ScopeError("Target network does not match the authorized scope snapshot")
            except ValueError:
                raise ScopeError("Authorized scope snapshot is invalid")
        for meta in METADATA_IPS:
            if meta.version == network.version and meta in network:
                raise ScopeError("Network range includes a cloud metadata address and is blocked")
        for blocked in ("169.254.0.0/16", "fe80::/10"):
            bnet = ipaddress.ip_network(blocked)
            if bnet.version == network.version and (network.overlaps(bnet) or bnet.overlaps(network)):
                raise ScopeError("Link-local and metadata ranges are always blocked")
        first = network.network_address
        if _is_private(first):
            if not allow_private:
                raise ScopeError("Private network requires an authorization with allow_private")
            if not config.ALLOW_PRIVATE:
                raise ScopeError("This deployment is not configured to assess private targets")
        return ValidatedTarget(target=str(network), host=str(first), ips=[str(first)], is_url=False)

    host, is_url = _host_from_target(target_type, target)
    if not host:
        raise ScopeError("Target does not contain a host")
    if host in METADATA_HOSTS:
        raise ScopeError("Cloud metadata hostnames are always blocked")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal and literal in METADATA_IPS:
        raise ScopeError("Cloud metadata addresses are always blocked")

    if target_type == "ip":
        ips = [literal] if literal else []
        if not ips:
            raise ScopeError("IP target is invalid")
    else:
        if literal:
            ips = [literal]
        else:
            if not HOST_RE.match(host):
                raise ScopeError("Target hostname is invalid")
            ips = _resolve(host)

    approved = [h.lower() for h in scope.get("approved_targets") or []]
    authorized = (scope.get("authorized_host") or "").lower()
    if authorized and host != authorized and host not in approved:
        # The API snapshots the same host; a mismatch means the job was tampered with.
        raise ScopeError("Target host does not match the authorized scope snapshot")

    for ip in ips:
        if ip in METADATA_IPS or ip.is_link_local:
            raise ScopeError("Cloud metadata and link-local addresses are always blocked")
        if _is_private(ip):
            if not allow_private:
                raise ScopeError("Target resolves to a private address but the authorization does not allow internal systems")
            if not config.ALLOW_PRIVATE:
                raise ScopeError("This deployment is not configured to assess private targets")
    return ValidatedTarget(target=target, host=host, ips=[str(ip) for ip in ips], is_url=is_url)
