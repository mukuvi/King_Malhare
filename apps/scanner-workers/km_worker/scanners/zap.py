from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from ..config import config
from ..runner import JobContext, NormalizedResult
from .base import AdapterError, ZAPAdapter

RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class ZAP(ZAPAdapter):
    def _api(self, path: str, params: dict | None = None) -> dict:
        url = config.ZAP_URL.rstrip("/") + path
        query = dict(params or {})
        if config.ZAP_API_KEY:
            query["apikey"] = config.ZAP_API_KEY
        try:
            response = httpx.get(url, params=query, timeout=30, trust_env=False)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise AdapterError(f"ZAP API request failed: {exc}") from exc
        except ValueError as exc:
            raise AdapterError("ZAP returned a non-JSON response") from exc

    def run(self, ctx: JobContext) -> dict:
        if not config.ZAP_URL:
            raise AdapterError("ZAP_URL is not configured")
        target = ctx.target.target
        host = urlparse(target).hostname
        mode = str(ctx.config.get("mode", "spider"))
        max_minutes = max(1, min(30, int(ctx.config.get("max_duration_minutes", 5))))
        deadline = time.monotonic() + max_minutes * 60
        ctx.progress(8, "zap", "Starting ZAP spider")
        spider = self._api("/JSON/spider/action/scan/", {
            "url": target, "recurse": "true", "subtreeonly": "true",
        })
        spider_id = spider.get("scan")
        if spider_id is None:
            raise AdapterError(f"ZAP refused to start the spider: {spider}")
        while time.monotonic() < deadline:
            ctx.raise_if_cancelled()
            status = self._api("/JSON/spider/view/status/", {"scanId": spider_id}).get("status", "0")
            points = int(float(status or 0))
            ctx.progress(10 + int(points * 0.25), "zap", f"Spider progress {points}%")
            if points >= 100:
                break
            time.sleep(2)
        # Passive scan queue
        for _ in range(60):
            ctx.raise_if_cancelled()
            remaining = self._api("/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")
            try:
                value = int(remaining)
            except (TypeError, ValueError):
                value = 0
            if value <= 0:
                break
            ctx.progress(38, "zap", f"Passive analysis, {value} responses queued")
            time.sleep(2)
        passive_note = ""
        if mode == "active":
            ctx.progress(45, "zap", "Starting active scan")
            active = self._api("/JSON/ascan/action/scan/", {
                "url": target, "recurse": "true", "inScopeOnly": "true",
            })
            active_id = active.get("scan")
            if active_id is None:
                raise AdapterError(f"ZAP refused to start the active scan: {active}")
            while time.monotonic() < deadline:
                ctx.raise_if_cancelled()
                status = int(float(self._api("/JSON/ascan/view/status/", {"scanId": active_id}).get("status", "0") or 0))
                ctx.progress(45 + int(status * 0.4), "zap", f"Active scan progress {status}%")
                if status >= 100:
                    break
                time.sleep(3)
            else:
                passive_note = "The active scan reached the time budget before completing."
        ctx.progress(88, "zap", "Collecting alerts")
        alerts = self._api("/JSON/core/view/alerts/", {"baseurl": target, "start": "0", "count": "500"}).get("alerts", [])
        count = 0
        for alert in alerts:
            alert_host = urlparse(alert.get("url", "")).hostname
            if host and alert_host and alert_host != host:
                continue
            risk = (alert.get("risk") or "Informational").lower()
            severity = RISK_TO_SEVERITY.get(risk, "info")
            if severity == "info" and alert.get("confidence", "").lower() == "low":
                severity = "low"
            cwe = alert.get("cweid")
            if cwe and str(cwe) != "-1":
                cwe = f"CWE-{cwe}"
            else:
                cwe = ""
            evidence = {
                "alert": alert.get("alert"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "param": alert.get("param"),
                "attack": (alert.get("attack") or "")[:1000],
                "evidence": (alert.get("evidence") or "")[:2000],
                "description": (alert.get("description") or "")[:3000],
                "other_info": (alert.get("other") or "")[:2000],
                "solution": (alert.get("solution") or "")[:2000],
                "reference": (alert.get("reference") or "")[:2000],
                "cwe": cwe,
            }
            ctx.add_result(
                NormalizedResult(
                    title=alert.get("alert") or alert.get("name") or "ZAP alert",
                    severity=severity,
                    confidence="firm" if (alert.get("confidence") or "").lower() in {"high", "medium"} else "tentative",
                    endpoint=alert.get("url") or target,
                    cwe=cwe,
                    description=alert.get("description") or "ZAP reported a weakness. Review the alert evidence and confirm exploitability.",
                    remediation=alert.get("solution") or "Apply the remediation in the ZAP alert reference and retest.",
                    evidence=evidence,
                    raw={k: alert.get(k) for k in ("pluginId", "alertRef", "alert", "riskcode", "confidence", "cweid", "wascid")},
                )
            )
            count += 1
        summary = {
            "mode": mode,
            "alerts": len(alerts),
            "findings": count,
            "time_budget_minutes": max_minutes,
            "note": passive_note,
        }
        if passive_note:
            ctx.summary["note"] = passive_note
        return summary
