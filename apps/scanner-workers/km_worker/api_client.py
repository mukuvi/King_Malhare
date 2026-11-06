from __future__ import annotations

import logging

import httpx

from .config import config

log = logging.getLogger("km_worker.api")


class WorkerAPIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ClaimRejected(WorkerAPIError):
    pass


class WorkerAPI:
    def __init__(self) -> None:
        if not config.SERVICE_TOKEN:
            raise RuntimeError("WORKER_SERVICE_TOKEN is required")
        self.client = httpx.Client(
            base_url=config.API_INTERNAL_URL + "/internal/worker",
            headers={
                "X-Service-Token": config.SERVICE_TOKEN,
                "X-Worker-Id": config.WORKER_ID,
                "Content-Type": "application/json",
                "User-Agent": f"king-malhare-worker/{config.WORKER_ID}",
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
            trust_env=False,
        )

    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            response = self.client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise WorkerAPIError(0, f"API unreachable: {exc}") from exc
        if response.status_code >= 400:
            detail = response.text[:500]
            if response.status_code == 409:
                raise ClaimRejected(response.status_code, detail)
            raise WorkerAPIError(response.status_code, detail)
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    def claim(self, scan_id: str) -> dict:
        return self._request("POST", f"/jobs/{scan_id}/claim")

    def progress(self, scan_id: str, phase: str, percent: int, message: str = "") -> dict:
        return self._request(
            "POST",
            f"/jobs/{scan_id}/progress",
            json={"phase": phase, "progress": max(0, min(100, int(percent))), "message": message[:1000]},
        )

    def execution_start(self, scan_id: str, scanner: str, command: str) -> str:
        data = self._request(
            "POST",
            f"/jobs/{scan_id}/executions",
            json={"scanner": scanner, "command": command[:2000], "status": "running"},
        )
        return data.get("id", "")

    def execution_finish(
        self,
        scan_id: str,
        execution_id: str,
        status: str,
        exit_code: int | None,
        output: str,
        error: str = "",
    ) -> None:
        if not execution_id:
            return
        self._request(
            "POST",
            f"/jobs/{scan_id}/executions",
            json={
                "execution_id": execution_id,
                "status": status,
                "exit_code": exit_code,
                "output_excerpt": output[:20000],
                "error": error[:2000],
            },
        )

    def results(self, scan_id: str, results: list[dict]) -> dict:
        return self._request("POST", f"/jobs/{scan_id}/results", json={"results": results})

    def complete(self, scan_id: str, status: str, summary: dict, error: str = "") -> None:
        self._request(
            "POST",
            f"/jobs/{scan_id}/complete",
            json={"status": status, "summary": summary, "error": error[:2000]},
        )

    def cancel_state(self, scan_id: str) -> dict:
        return self._request("GET", f"/jobs/{scan_id}/cancel-state")

    def org_config(self, org_id: str) -> dict:
        return self._request("GET", f"/config/{org_id}")

    def close(self) -> None:
        self.client.close()
