from __future__ import annotations

import importlib.util
import logging
import shutil
import subprocess

import httpx

from ..config import config
from ..runner import JobContext

log = logging.getLogger("km_worker.adapters")

VERSION_ARGS = {
    "nuclei": ["-version"],
    "nikto": ["-Version"],
    "sqlmap": ["--version"],
    "testssl": ["--version"],
    "trivy": ["--version"],
    "prowler": ["--version"],
    "scoutsuite": ["--version"],
    "checkov": ["--version"],
    "gobuster": ["version"],
}


class AdapterError(Exception):
    """Raised when an adapter cannot complete meaningfully (missing tool, unreachable service)."""


class Adapter:
    name = ""
    category = ""
    binary_key: str | None = None
    display = ""

    @classmethod
    def binary(cls) -> str | None:
        if not cls.binary_key:
            return None
        return config.BINARIES.get(cls.binary_key)

    @classmethod
    def probe(cls) -> dict:
        binary = cls.binary()
        if not binary:
            return {"available": True, "version": "built-in", "path": "internal", "error": ""}
        path = shutil.which(binary)
        if not path:
            return {"available": False, "version": "", "path": binary, "error": f"{binary} is not installed in the worker image"}
        args = VERSION_ARGS.get(cls.binary_key or "", ["--version"])
        version = ""
        error = ""
        try:
            proc = subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                timeout=10,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"},
            )
            raw = (proc.stdout or "") + (proc.stderr or "")
            version = next((line.strip() for line in raw.splitlines() if line.strip()), "")
            if len(version) > 160:
                version = version[:160]
            if proc.returncode != 0 and not version:
                error = f"{path} returned exit code {proc.returncode}"
        except (subprocess.TimeoutExpired, OSError) as exc:
            error = f"version check failed: {exc}"
        return {"available": not error, "version": version, "path": path, "error": error}

    def run(self, ctx: JobContext) -> dict:
        raise NotImplementedError


class ZAPAdapter(Adapter):
    name = "zap"
    category = "web"
    binary_key = None
    display = "OWASP ZAP"

    @classmethod
    def probe(cls) -> dict:
        if not config.ZAP_URL:
            return {"available": False, "version": "", "path": "ZAP_URL", "error": "ZAP_URL is not configured"}
        try:
            response = httpx.get(
                config.ZAP_URL.rstrip("/") + "/JSON/core/view/version/",
                params={"apikey": config.ZAP_API_KEY} if config.ZAP_API_KEY else {},
                timeout=4,
                trust_env=False,
            )
            if response.status_code == 200:
                version = response.json().get("version", "")
                return {"available": True, "version": f"ZAP {version}", "path": config.ZAP_URL, "error": ""}
            return {"available": False, "version": "", "path": config.ZAP_URL, "error": f"ZAP returned {response.status_code}"}
        except Exception as exc:
            return {"available": False, "version": "", "path": config.ZAP_URL, "error": f"ZAP unreachable: {exc}"}


class AWSPostureAdapter(Adapter):
    name = "aws-posture"
    category = "cloud"
    binary_key = None
    display = "AWS posture (boto3)"

    @classmethod
    def probe(cls) -> dict:
        if importlib.util.find_spec("boto3") is None:
            return {"available": False, "version": "", "path": "boto3", "error": "boto3 is not installed"}
        import boto3

        return {"available": True, "version": f"boto3 {boto3.__version__}", "path": "boto3", "error": ""}


class AuthBaselineAdapter(Adapter):
    name = "auth-baseline"
    category = "authentication"
    binary_key = None
    display = "Authentication baseline"

    @classmethod
    def probe(cls) -> dict:
        return {"available": True, "version": "built-in", "path": "internal", "error": ""}


class HTTPBaselineAdapter(Adapter):
    name = "http-baseline"
    category = "web"
    binary_key = None
    display = "HTTP baseline"

    @classmethod
    def probe(cls) -> dict:
        return {"available": True, "version": "built-in", "path": "internal", "error": ""}
