from __future__ import annotations

import logging

from .scanners.auth_baseline import AuthBaseline
from .scanners.aws_posture import AWSPosture
from .scanners.base import Adapter
from .scanners.checkov import Checkov
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
}


def detect_all() -> dict:
    out = {}
    for name, adapter in ADAPTERS.items():
        try:
            out[name] = adapter.probe()
        except Exception as exc:  # defensive: a broken probe must not stop the worker
            log.warning("probe failed for %s: %s", name, exc)
            out[name] = {"available": False, "version": "", "path": "", "error": str(exc)[:300]}
    return out
