from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import httpx

from ..runner import JobContext, NormalizedResult
from .base import AdapterError, HTTPBaselineAdapter

USER_AGENT = "KingMalhare/1.0 (+authorized security assessment)"

HEADER_CHECKS = [
    (
        "Content-Security-Policy",
        "medium",
        "CWE-693",
        "Content-Security-Policy is not set. The browser has no policy restricting script, style or frame sources, which increases the impact of injection flaws.",
        "Define a Content-Security-Policy with explicit script-src, object-src 'none', base-uri 'self' and frame-ancestors 'none'. Roll it out in report-only mode first.",
    ),
    (
        "X-Content-Type-Options",
        "low",
        "CWE-693",
        "X-Content-Type-Options is missing. Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
        "Send X-Content-Type-Options: nosniff on all responses.",
    ),
    (
        "Referrer-Policy",
        "low",
        "CWE-200",
        "Referrer-Policy is missing. Sensitive path or query information may leak to third parties through the Referer header.",
        "Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    ),
    (
        "Permissions-Policy",
        "info",
        "CWE-693",
        "Permissions-Policy is missing. Browser features are not explicitly restricted for the origin.",
        "Send a Permissions-Policy that disables capabilities the application does not use (camera, microphone, geolocation).",
    ),
]

EXPOSURE_PATHS = [
    ("/.git/config", "high", re.compile(r"\[core\]|repositoryformatversion"), "Exposed Git repository configuration", "Remove .git from the web root and redeploy from a clean artifact."),
    ("/.git/HEAD", "high", re.compile(r"^ref:\s+refs/"), "Exposed Git repository metadata", "Block access to .git at the web server and redeploy without repository metadata."),
    ("/.env", "critical", re.compile(r"(?m)^[A-Z0-9_]{2,}=[^\n]{1,}"), "Exposed environment file", "Remove the file from the web root immediately, rotate every exposed secret, and add deployment checks."),
    ("/.env.local", "critical", re.compile(r"(?m)^[A-Z0-9_]{2,}=[^\n]{1,}"), "Exposed environment file (.env.local)", "Remove the file from the web root immediately and rotate every exposed secret."),
    ("/.env.production", "critical", re.compile(r"(?m)^[A-Z0-9_]{2,}=[^\n]{1,}"), "Exposed production environment file", "Remove the file, rotate credentials, and restrict static file serving to build artifacts."),
    ("/server-status", "medium", re.compile(r"Apache Server Status"), "Apache server-status endpoint exposed", "Restrict /server-status to localhost using Require local or disable mod_status."),
    ("/actuator/env", "high", re.compile(r"propertySources|activeProfiles"), "Spring Boot actuator environment exposed", "Restrict actuator endpoints to the management network and disable env exposure."),
    ("/actuator/health", "low", re.compile(r'"?status"?\s*:\s*"?UP"?'), "Spring Boot actuator health endpoint exposed", "Limit actuator access to internal monitoring and remove detailed component information."),
    ("/swagger-ui.html", "medium", re.compile(r"swagger-ui|Swagger UI"), "Interactive API documentation exposed", "Require authentication for API documentation in production or disable it."),
    ("/openapi.json", "medium", re.compile(r'"(openapi|swagger)"\s*:'), "OpenAPI specification exposed", "Restrict API specification endpoints to authenticated developers."),
    ("/api-docs", "medium", re.compile(r'"(openapi|swagger)"\s*:'), "API documentation exposed", "Restrict documentation endpoints in production."),
    ("/phpinfo.php", "high", re.compile(r"PHP Version|phpinfo\(\)"), "PHP information page exposed", "Remove phpinfo scripts from production."),
    ("/backup.zip", "critical", re.compile(r"."), "Backup archive exposed", "Remove backup archives from the web root and rotate any contained secrets."),
    ("/config.json", "high", re.compile(r'"[A-Za-z_]*(key|secret|token|password)[A-Za-z_]*"\s*:'), "Configuration file with secrets exposed", "Remove the configuration file from public storage and rotate exposed credentials."),
    ("/docker-compose.yml", "medium", re.compile(r"(?m)^services:"), "Docker Compose configuration exposed", "Remove infrastructure files from the web root."),
    ("/.DS_Store", "low", re.compile(r"Bud1|DS_Store"), "macOS metadata file exposed", "Exclude .DS_Store files from deployment."),
]


class HTTPBaseline(HTTPBaselineAdapter):
    def run(self, ctx: JobContext) -> dict:
        parsed = urlparse(ctx.target.target if "://" in ctx.target.target else "https://" + ctx.target.target)
        scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
        host = parsed.hostname
        if not host:
            raise AdapterError("HTTP baseline requires a host")
        port = parsed.port or (443 if scheme == "https" else 80)
        origin = urlunparse((scheme, parsed.netloc, "", "", "", ""))
        max_requests = int(ctx.config.get("max_requests", 120) or 120)
        budget = {"used": 0}
        ctx.progress(6, "http-baseline", f"Connecting to {host}:{port}")

        client = httpx.Client(
            verify=True,
            follow_redirects=False,
            timeout=httpx.Timeout(12.0, connect=8.0),
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            trust_env=False,
        )
        try:
            response = self._safe_get(client, ctx.target.target, budget, max_requests)
            if response is None:
                raise AdapterError("Target did not return an HTTP response")
            ctx.progress(18, "http-baseline", f"HTTP {response.status_code} received")
            self._header_findings(ctx, response, scheme, host)
            self._cookie_findings(ctx, response, host)
            self._disclosure_findings(ctx, response, host)
            if scheme == "http":
                ctx.add_result(
                    NormalizedResult(
                        title="Unencrypted HTTP transport in use",
                        severity="medium",
                        confidence="certain",
                        endpoint=origin,
                        cwe="CWE-319",
                        description="The assessed endpoint responds over plain HTTP. Credentials, session cookies and sensitive data can be intercepted or modified by a network attacker.",
                        remediation="Redirect all HTTP traffic to HTTPS, enable HSTS, and mark cookies Secure.",
                        evidence={"url": ctx.target.target, "status": response.status_code, "server": response.headers.get("server", "")},
                    )
                )
            if bool(ctx.config.get("cors_check", True)):
                self._cors_findings(ctx, client, origin, budget, max_requests)
            if bool(ctx.config.get("exposure_check", True)):
                self._exposure_findings(ctx, client, origin, budget, max_requests)
            if bool(ctx.config.get("tls_check", True)) and scheme == "https":
                self._tls_findings(ctx, host, port)
            ctx.progress(88, "http-baseline", f"{len(ctx.results)} findings from baseline checks")
            return {
                "requests": budget["used"],
                "base_status": response.status_code,
                "tls_checked": scheme == "https",
                "findings": len(ctx.results),
            }
        finally:
            client.close()

    def _safe_get(self, client: httpx.Client, url: str, budget: dict, max_requests: int) -> httpx.Response | None:
        if budget["used"] >= max_requests:
            return None
        budget["used"] += 1
        try:
            response = client.get(url)
        except httpx.HTTPError as exc:
            raise AdapterError(f"Request failed: {exc}") from exc
        # Follow only same-origin redirects, and never leave the authorized host.
        parsed = urlparse(url)
        for _ in range(3):
            if not response.is_redirect:
                break
            location = response.headers.get("location", "")
            if not location:
                break
            target = httpx.URL(url).join(location)
            if target.host != parsed.host or target.scheme not in {"http", "https"}:
                break
            if budget["used"] >= max_requests:
                break
            budget["used"] += 1
            try:
                response = client.get(str(target))
            except httpx.HTTPError:
                break
        return response

    def _header_findings(self, ctx: JobContext, response: httpx.Response, scheme: str, host: str) -> None:
        headers = {k.lower(): v for k, v in response.headers.items()}
        endpoint = str(response.url)
        if scheme == "https" and "strict-transport-security" not in headers:
            ctx.add_result(
                NormalizedResult(
                    title="HTTP Strict Transport Security is not enabled",
                    severity="medium",
                    confidence="certain",
                    endpoint=endpoint,
                    cwe="CWE-319",
                    description="The HTTPS response does not include a Strict-Transport-Security header. A user who reaches the site over HTTP remains vulnerable to SSL-stripping and downgrade attacks until the browser receives this header.",
                    remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload only after verifying all subdomains support HTTPS).",
                    evidence={"header": "Strict-Transport-Security", "observed": None, "status": response.status_code},
                )
            )
        for header, severity, cwe, description, remediation in HEADER_CHECKS:
            if header.lower() in headers:
                continue
            ctx.add_result(
                NormalizedResult(
                    title=f"Security header missing: {header}",
                    severity=severity,
                    confidence="certain",
                    endpoint=endpoint,
                    cwe=cwe,
                    description=description,
                    remediation=remediation,
                    evidence={"header": header, "observed": None, "status": response.status_code, "response_headers": {k: headers.get(k) for k in ("server", "content-type", "x-powered-by")}},
                )
            )
        xfo = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()
        if not xfo and "frame-ancestors" not in csp:
            ctx.add_result(
                NormalizedResult(
                    title="Clickjacking protection is not configured",
                    severity="low",
                    confidence="certain",
                    endpoint=endpoint,
                    cwe="CWE-1021",
                    description="Neither X-Frame-Options nor a CSP frame-ancestors directive restricts framing. An attacker can overlay the application in an iframe and capture user interactions.",
                    remediation="Send X-Frame-Options: DENY or CSP frame-ancestors 'none' for application pages.",
                    evidence={"x_frame_options": headers.get("x-frame-options"), "csp": headers.get("content-security-policy"), "status": response.status_code},
                )
            )
        if "content-security-policy" in headers and "unsafe-inline" in csp and "nonce-" not in csp and "sha256-" not in csp:
            ctx.add_result(
                NormalizedResult(
                    title="Content-Security-Policy permits inline script or style",
                    severity="low",
                    confidence="firm",
                    endpoint=endpoint,
                    cwe="CWE-693",
                    description="The CSP contains 'unsafe-inline' without a nonce or hash, weakening its protection against script injection.",
                    remediation="Move inline scripts and styles to external files or use nonces/hashes and remove 'unsafe-inline'.",
                    evidence={"csp": response.headers.get("content-security-policy", "")[:1000]},
                )
            )

    def _cookie_findings(self, ctx: JobContext, response: httpx.Response, host: str) -> None:
        set_cookies = response.headers.get_list("set-cookie")
        for cookie_header in set_cookies:
            parts = [p.strip() for p in cookie_header.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()[:80]
            flags = {p.split("=", 1)[0].strip().lower(): p for p in parts[1:]}
            sensitive = bool(re.search(r"(sess|auth|token|jwt|sid|login|remember)", name, re.I))
            if "httponly" not in flags:
                ctx.add_result(
                    NormalizedResult(
                        title=f"Cookie without HttpOnly flag: {name}",
                        severity="medium" if sensitive else "low",
                        confidence="certain",
                        endpoint=str(response.url),
                        cwe="CWE-1004",
                        description="A cookie is set without HttpOnly. Client-side script can read it, so any cross-site scripting flaw can steal the value.",
                        remediation="Set HttpOnly on session and authentication cookies. Never store session identifiers in JavaScript-readable storage.",
                        evidence={"cookie": name, "attributes": list(flags.keys()), "sensitive": sensitive},
                    )
                )
            if "secure" not in flags and urlparse(str(response.url)).scheme == "https":
                ctx.add_result(
                    NormalizedResult(
                        title=f"Cookie without Secure flag: {name}",
                        severity="medium" if sensitive else "low",
                        confidence="certain",
                        endpoint=str(response.url),
                        cwe="CWE-614",
                        description="A cookie is set without the Secure attribute. The browser may transmit it over an unencrypted connection.",
                        remediation="Set Secure on all cookies served over HTTPS.",
                        evidence={"cookie": name, "attributes": list(flags.keys())},
                    )
                )
            if sensitive and "samesite" not in flags:
                ctx.add_result(
                    NormalizedResult(
                        title=f"Session cookie without SameSite attribute: {name}",
                        severity="low",
                        confidence="firm",
                        endpoint=str(response.url),
                        cwe="CWE-1275",
                        description="A session-like cookie has no explicit SameSite policy, which may allow it to be sent on cross-site requests depending on the browser default.",
                        remediation="Set SameSite=Lax or SameSite=Strict on session cookies unless a documented cross-site flow requires None with Secure.",
                        evidence={"cookie": name},
                    )
                )
            if flags.get("samesite", "").lower().endswith("none") and "secure" not in flags:
                ctx.add_result(
                    NormalizedResult(
                        title=f"SameSite=None cookie without Secure: {name}",
                        severity="medium",
                        confidence="certain",
                        endpoint=str(response.url),
                        cwe="CWE-614",
                        description="A cookie declares SameSite=None but lacks Secure. Modern browsers reject the cookie, and older behaviour exposes it to network attackers.",
                        remediation="Add Secure whenever SameSite=None is required.",
                        evidence={"cookie": name},
                    )
                )

    def _disclosure_findings(self, ctx: JobContext, response: httpx.Response, host: str) -> None:
        server = response.headers.get("server", "")
        powered = response.headers.get("x-powered-by", "")
        for header, value in (("Server", server), ("X-Powered-By", powered)):
            if value:
                ctx.add_result(
                    NormalizedResult(
                        title=f"Technology disclosure through {header} header",
                        severity="info",
                        confidence="certain",
                        endpoint=str(response.url),
                        cwe="CWE-200",
                        description="The response advertises server or framework details that help an attacker select targeted exploits. This is an observation, not a vulnerability on its own.",
                        remediation="Remove or generalise version banners at the reverse proxy where practical.",
                        evidence={"header": header, "value": value[:300]},
                    )
                )
        if re.search(r"(?i)stack trace|exception|at [a-z0-9_.]+\([a-zA-Z0-9_.]+\.java:\d+\)", response.text[:8000]):
            ctx.add_result(
                NormalizedResult(
                    title="Application error details exposed in response",
                    severity="low",
                    confidence="firm",
                    endpoint=str(response.url),
                    cwe="CWE-209",
                    description="The response contains exception or stack trace details that reveal internal file paths or implementation details.",
                    remediation="Return generic error pages in production and log details server-side only.",
                    evidence={"status": response.status_code, "excerpt": response.text[:600]},
                )
            )

    def _cors_findings(self, ctx: JobContext, client: httpx.Client, origin_url: str, budget: dict, max_requests: int) -> None:
        probe_origin = "https://king-malhare.invalid"
        for method in ("GET", "OPTIONS"):
            if budget["used"] >= max_requests:
                return
            budget["used"] += 1
            try:
                headers = {"Origin": probe_origin, "User-Agent": USER_AGENT}
                if method == "OPTIONS":
                    headers.update({"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
                response = client.request(method, origin_url, headers=headers)
            except httpx.HTTPError:
                continue
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao in {"*", probe_origin}:
                severity = "high" if (acao == probe_origin and acac) else "medium"
                ctx.add_result(
                    NormalizedResult(
                        title="Permissive Cross-Origin Resource Sharing policy",
                        severity=severity,
                        confidence="certain",
                        endpoint=origin_url,
                        cwe="CWE-942",
                        description=f"The server reflects an arbitrary Origin ({probe_origin}) in Access-Control-Allow-Origin"
                        + (" and allows credentials. A malicious site can read authenticated responses." if acac else ". A malicious site can read responses that should be restricted."),
                        remediation="Replace dynamic origin reflection with an explicit allowlist of trusted origins. Do not combine wildcard origins with credentials.",
                        evidence={"method": method, "origin_sent": probe_origin, "access_control_allow_origin": acao, "allow_credentials": acac},
                    )
                )
                return

    def _exposure_findings(self, ctx: JobContext, client: httpx.Client, origin: str, budget: dict, max_requests: int) -> None:
        for index, (path, severity, signature, title, remediation) in enumerate(EXPOSURE_PATHS):
            if budget["used"] >= max_requests:
                break
            if ctx.check_cancel():
                return
            budget["used"] += 1
            url = origin + path
            try:
                response = client.get(url)
            except httpx.HTTPError:
                continue
            if response.status_code != 200:
                continue
            sample = response.content[:25000]
            text = sample.decode("utf-8", errors="ignore")
            if not signature.search(text):
                continue
            ctx.add_result(
                NormalizedResult(
                    title=title,
                    severity=severity,
                    confidence="certain",
                    endpoint=url,
                    cwe="CWE-538",
                    description=f"{path} returned HTTP 200 with content matching the expected signature for this file. Publicly served configuration and repository files can expose credentials, source code or internal topology.",
                    remediation=remediation,
                    evidence={"path": path, "status": 200, "content_type": response.headers.get("content-type", ""), "excerpt": text[:500]},
                )
            )
            ctx.progress(30 + int((index / max(1, len(EXPOSURE_PATHS))) * 50), "http-baseline", f"Exposed path confirmed: {path}")

    def _tls_findings(self, ctx: JobContext, host: str, port: int) -> None:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    version = tls.version() or ""
                    cipher = tls.cipher()
                    cert = tls.getpeercert()
                    if version in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
                        ctx.add_result(
                            NormalizedResult(
                                title=f"Deprecated TLS protocol negotiated ({version})",
                                severity="high",
                                endpoint=f"{host}:{port}",
                                cwe="CWE-327",
                                description="The server negotiated an obsolete TLS protocol with known cryptographic weaknesses.",
                                remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2 or newer with modern cipher suites.",
                                evidence={"version": version, "cipher": cipher[0] if cipher else ""},
                            )
                        )
                    not_after = cert.get("notAfter") if cert else None
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            days = (expiry - datetime.now(timezone.utc)).days
                            if days < 21:
                                ctx.add_result(
                                    NormalizedResult(
                                        title=f"TLS certificate expires in {days} days",
                                        severity="high" if days < 7 else "medium",
                                        endpoint=f"{host}:{port}",
                                        cwe="CWE-298",
                                        description="The certificate presented by the target expires imminently. Renewal failures cause outages and train users to ignore warnings.",
                                        remediation="Renew the certificate and automate renewal with monitoring for expiry.",
                                        evidence={"not_after": not_after, "days_remaining": days, "subject": cert.get("subject")},
                                    )
                                )
                        except ValueError:
                            pass
        except ssl.SSLCertVerificationError as exc:
            ctx.add_result(
                NormalizedResult(
                    title="TLS certificate validation failed",
                    severity="high",
                    confidence="certain",
                    endpoint=f"{host}:{port}",
                    cwe="CWE-295",
                    description="The certificate chain presented by the target failed validation. Clients cannot verify they are communicating with the intended service.",
                    remediation="Install a certificate from a trusted CA with a complete intermediate chain and a hostname that matches the service.",
                    evidence={"error": str(exc)[:500]},
                )
            )
        except (socket.timeout, ssl.SSLError, OSError) as exc:
            ctx.add_result(
                NormalizedResult(
                    title="TLS handshake could not be completed",
                    severity="medium",
                    confidence="tentative",
                    endpoint=f"{host}:{port}",
                    cwe="CWE-295",
                    description="The TLS handshake failed during the assessment. The service may be misconfigured, or port 443 may not serve TLS.",
                    remediation="Verify the TLS listener, certificate chain and protocol configuration.",
                    evidence={"error": str(exc)[:500]},
                )
            )
