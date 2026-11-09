from __future__ import annotations

import logging

from .scanners.auth_baseline import AuthBaseline
from .scanners.aws_posture import AWSPosture
from .scanners.base import Adapter
from .scanners.checkov import Checkov
from .scanners.extra import Burp, Ffuf, Gitleaks, Grype, Httpx, Schemathesis, Semgrep, Sslyze, Subfinder, Syft, Tfsec, WafW00f, WhatWeb
from .scanners.gobuster import Gobuster
from .scanners.http_baseline import HTTPBaseline
from .scanners.nikto import Nikto
from .scanners.nmap import Nmap
from .scanners.nuclei import Nuclei
from .scanners.prowler import Prowler
from .scanners.scoutsuite import ScoutSuite
from .scanners.sqlmap import SQLMap
from .scanners.testssl import TestSSL
from .scanners.trivy import Trivy
from .scanners.zap import ZAP
from .scanners.generic import GenericKaliAdapter
from .kali_tools import KALI_TOOLS

log = logging.getLogger("km_worker.registry")

ADAPTERS: dict[str, type[Adapter]] = {
    "http-baseline": HTTPBaseline,
    "nmap": Nmap,
    "nuclei": Nuclei,
    "zap": ZAP,
    "nikto": Nikto,
    "gobuster": Gobuster,
    "testssl": TestSSL,
    "sqlmap": SQLMap,
    "trivy": Trivy,
    "prowler": Prowler,
    "scoutsuite": ScoutSuite,
    "checkov": Checkov,
    "aws-posture": AWSPosture,
    "auth-baseline": AuthBaseline,
    "burp": Burp,
    "ffuf": Ffuf,
    "whatweb": WhatWeb,
    "wafw00f": WafW00f,
    "httpx": Httpx,
    "subfinder": Subfinder,
    "sslyze": Sslyze,
    "grype": Grype,
    "semgrep": Semgrep,
    "gitleaks": Gitleaks,
    "tfsec": Tfsec,
    "syft": Syft,
    "schemathesis": Schemathesis,
}

# Real Kali CLI tools are registered from the shared catalog. The generic
# adapter uses argument vectors, scope checks and honest availability probes.
for _spec in KALI_TOOLS:
    _name = _spec["name"]
    if _name in ADAPTERS:
        continue
    ADAPTERS[_name] = type(
        f"Kali_{_name.replace('-', '_')}",
        (GenericKaliAdapter,),
        {
            "name": _name,
            "category": _spec["category"],
            "binary_key": _name,
            "display": _spec["label"],
            "command": _spec["command"],
            "output_mode": _spec.get("output", "text"),
            "output_name": _spec.get("output_name", f"{_name}.out"),
            "parser": _spec.get("parser", "raw"),
            "intrusive": bool(_spec.get("intrusive", False)),
            "timeout": int(_spec.get("timeout", 600)),
        },
    )


def detect_all() -> dict:
    out = {}
    for name, adapter in ADAPTERS.items():
        try:
            out[name] = adapter.probe()
        except Exception as exc:  # defensive: a broken probe must not stop the worker
            log.warning("probe failed for %s: %s", name, exc)
            out[name] = {"available": False, "version": "", "path": "", "error": str(exc)[:300]}
    return out
