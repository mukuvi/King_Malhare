from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

LOCKOUT_WORDS = ("locked", "lockout", "too many", "rate limit", "try again", "temporarily blocked", "captcha")
SESSION_COOKIE_WORDS = ("sess", "sid", "auth", "token", "jwt", "login", "remember")


class AuthBaseline(Adapter):
    name = "auth-baseline"
    category = "authentication"
    binary_key = None
    display = "Authentication baseline"

    def run(self, ctx: JobContext) -> dict:
        scope = ctx.job.get("scope") or {}
        if not scope.get("intrusive_allowed"):
            raise AdapterError("Authentication testing requires an authorization that permits intrusive testing")
        creds = (ctx.job.get("credentials") or {}).get("fields") or {}
        username = str(creds.get("username") or ctx.config.get("test_username") or "").strip()
        password = str(creds.get("password") or "")
        if not username or not password:
            raise AdapterError("Authentication testing requires an explicitly authorized test account and password.")
        login_path = str(ctx.config.get("login_path", "/login") or "/login")
        if not login_path.startswith("/"):
            login_path = "/" + login_path
        user_field = str(ctx.config.get("username_field", "username") or "username")
        pass_field = str(ctx.config.get("password_field", "password") or "password")
        request_format = str(ctx.config.get("request_format", "json") or "json")
        attempts = max(1, min(10, int(ctx.config.get("attempts", 5) or 5)))
        delay_ms = max(100, min(5000, int(ctx.config.get("delay_ms", 500) or 500)))
        base = ctx.target.target
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        login_url = origin + login_path
        if parsed.hostname != ctx.target.host:
            raise AdapterError("Login endpoint left the authorized host")

        client = httpx.Client(
            verify=True, follow_redirects=False, timeout=httpx.Timeout(12, connect=8), trust_env=False,
            headers={"User-Agent": "KingMalhare/1.0 (authorized authentication test)", "Accept": "application/json, text/html"},
        )
        try:
            ctx.progress(12, "auth-baseline", "Validating the authorized test account")
            pre_response = None
            try:
                pre_response = client.get(login_url)
            except httpx.HTTPError:
                pass
            pre_cookies = dict(pre_response.cookies) if pre_response is not None else {}
            baseline = self._probe(client, login_url, user_field, pass_field, username, password, request_format)
            if baseline is None:
                raise AdapterError("The login endpoint could not be reached")
            if baseline.status_code >= 500:
                raise AdapterError(f"Login endpoint returned HTTP {baseline.status_code}")
            valid_login = baseline.status_code < 400 and not self._contains_failure(baseline.text)
            if not valid_login:
                raise AdapterError(
                    "The supplied test-account credentials were rejected by the login endpoint. Verify the authorized test account before running this assessment."
                )
            self._cookie_findings(ctx, baseline)
            self._rotation_findings(ctx, pre_cookies, dict(client.cookies), login_url)
            ctx.progress(30, "auth-baseline", f"Testing throttling with {attempts} bounded attempts")
            statuses: list[int] = []
            lockout_detected = False
            rate_limited = False
            bypass = False
            for index in range(attempts):
                ctx.raise_if_cancelled()
                wrong = f"Km-invalid-{index}-{int(time.time())}"
                response = self._probe(client, login_url, user_field, pass_field, username, wrong, request_format)
                if response is None:
                    break
                statuses.append(response.status_code)
                body = response.text.lower()[:4000]
                if response.status_code == 429 or any(word in body for word in LOCKOUT_WORDS):
                    rate_limited = True
                    if "lock" in body:
                        lockout_detected = True
                    break
                if response.status_code < 400 and not self._contains_failure(response.text):
                    bypass = True
                    break
                time.sleep(delay_ms / 1000.0)
            if bypass:
                ctx.add_result(
                    NormalizedResult(
                        title="Authentication bypass: invalid password accepted",
                        severity="critical",
                        confidence="certain",
                        endpoint=login_url,
                        cwe="CWE-287",
                        description="The login endpoint returned a success response for an incorrect password during the bounded test. This indicates broken authentication.",
                        remediation="Fix the credential verification path, reject invalid passwords uniformly, and add regression tests for failed authentication.",
                        evidence={"attempts": len(statuses), "statuses": statuses, "account": username},
                    )
                )
            elif not rate_limited:
                ctx.add_result(
                    NormalizedResult(
                        title="No login throttling or lockout observed",
                        severity="medium",
                        confidence="firm",
                        endpoint=login_url,
                        cwe="CWE-307",
                        description=f"{len(statuses)} consecutive failed authentication attempts produced no rate-limit response, lockout or CAPTCHA. This permits online password guessing at the rate the server can process.",
                        remediation="Add per-account and per-IP rate limiting, exponential backoff, alerting and temporary lockout after a defined threshold. Do not reveal whether the username exists.",
                        evidence={"attempts": len(statuses), "statuses": statuses, "delay_ms": delay_ms, "account": username},
                    )
                )
            else:
                ctx.summary["throttling"] = "observed"
            ctx.progress(90, "auth-baseline", "Authentication checks complete")
            return {
                "attempts": len(statuses),
                "statuses": statuses,
                "rate_limited": rate_limited,
                "lockout_detected": lockout_detected,
                "bypass": bypass,
                "account": username,
                "findings": len(ctx.results),
            }
        finally:
            client.close()

    def _probe(self, client, url, user_field, pass_field, username, password, request_format):
        payload = {user_field: username, pass_field: password}
        try:
            if request_format == "form":
                return client.post(url, data=payload)
            return client.post(url, json=payload)
        except httpx.HTTPError:
            return None

    @staticmethod
    def _contains_failure(body: str) -> bool:
        lowered = body.lower()[:6000]
        return any(word in lowered for word in ("invalid", "incorrect", "failed", "unauthorized", "bad credentials", "wrong"))

    def _rotation_findings(self, ctx: JobContext, pre_cookies: dict, post_cookies: dict, login_url: str) -> None:
        for name, value in post_cookies.items():
            if not any(word in name.lower() for word in SESSION_COOKIE_WORDS):
                continue
            if pre_cookies.get(name) == value:
                ctx.add_result(
                    NormalizedResult(
                        title=f"Session identifier was not rotated at login: {name}",
                        severity="medium",
                        confidence="firm",
                        endpoint=login_url,
                        cwe="CWE-384",
                        description="A session-like cookie had the same value before and after authentication. If an attacker can plant a known session identifier, they may inherit the authenticated session.",
                        remediation="Issue a new session identifier on successful authentication and invalidate the pre-authentication session.",
                        evidence={"cookie": name, "same_before_and_after": True},
                    )
                )

    def _cookie_findings(self, ctx: JobContext, response: httpx.Response) -> None:
        for header in response.headers.get_list("set-cookie"):
            parts = [p.strip() for p in header.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()
            if not any(word in name.lower() for word in SESSION_COOKIE_WORDS):
                continue
            flags = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
            missing = []
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if "secure" not in flags:
                missing.append("Secure")
            if "samesite" not in flags:
                missing.append("SameSite")
            if missing:
                ctx.add_result(
                    NormalizedResult(
                        title=f"Authentication cookie missing attributes: {', '.join(missing)}",
                        severity="medium" if "HttpOnly" in missing or "Secure" in missing else "low",
                        confidence="certain",
                        endpoint=str(response.url),
                        cwe="CWE-1004",
                        description=f"The session cookie '{name}' is missing: {', '.join(missing)}. This weakens protection against script access, network interception and cross-site requests.",
                        remediation="Set HttpOnly, Secure and SameSite=Lax (or Strict) on authentication cookies.",
                        evidence={"cookie": name, "missing": missing},
                    )
                )
