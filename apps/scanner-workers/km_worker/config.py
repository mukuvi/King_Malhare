import os
import socket
import uuid
from pathlib import Path


def _find_dotenv() -> Path | None:
    here = Path(__file__).resolve()
    for base in (Path.cwd(), here.parent, here.parent.parent, here.parent.parent.parent, here.parent.parent.parent.parent):
        candidate = base / ".env"
        if candidate.is_file():
            return candidate
    return None


def _load_dotenv() -> None:
    path = _find_dotenv()
    if not path:
        return
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        pass


_load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    redis_url = _env("REDIS_URL", "redis://localhost:6379/0")
    queue_key = _env("SCAN_QUEUE", "km:scan:jobs")
    API_INTERNAL_URL = _env("API_INTERNAL_URL", "http://localhost:8081").rstrip("/")
    SERVICE_TOKEN = _env("WORKER_SERVICE_TOKEN")
    WORKER_ID = _env("WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    CONCURRENCY = max(1, min(4, _env_int("WORKER_CONCURRENCY", 1)))
    HEARTBEAT_SECONDS = max(5, _env_int("WORKER_HEARTBEAT_SECONDS", 20))
    JOB_TIMEOUT = max(30, _env_int("SCANNER_JOB_TIMEOUT_SECONDS", 900))
    MAX_OUTPUT = max(65536, _env_int("SCANNER_MAX_OUTPUT_BYTES", 8_000_000))
    WORK_DIR = Path(_env("SCANNER_WORK_DIR", "/tmp/king-malhare-work"))
    ALLOW_PRIVATE = _env_bool("ALLOW_PRIVATE_TARGETS", False)
    DIR_WORDLIST = Path(_env("DIR_WORDLIST", str(Path(__file__).parent / "wordlists" / "common.txt")))
    NUCLEI_TEMPLATES = _env("NUCLEI_TEMPLATES")
    ZAP_URL = _env("ZAP_URL").rstrip("/")
    ZAP_API_KEY = _env("ZAP_API_KEY")
    CHECKOV_ALLOWED_ROOT = _env("CHECKOV_ALLOWED_ROOT")
    LOG_LEVEL = _env("LOG_LEVEL", "info")

    BINARIES = {
        "nmap": _env("NMAP_PATH", "nmap"),
        "nuclei": _env("NUCLEI_PATH", "nuclei"),
        "nikto": _env("NIKTO_PATH", "nikto"),
        "gobuster": _env("GOBUSTER_PATH", "gobuster"),
        "sqlmap": _env("SQLMAP_PATH", "sqlmap"),
        "testssl": _env("TESTSSL_PATH", "testssl.sh"),
        "trivy": _env("TRIVY_PATH", "trivy"),
        "prowler": _env("PROWLER_PATH", "prowler"),
        "scoutsuite": _env("SCOUTSUITE_PATH", "scoutsuite"),
        "checkov": _env("CHECKOV_PATH", "checkov"),
    }
    NMAP_PATH = _env("NMAP_PATH", "nmap")
    NUCLEI_PATH = _env("NUCLEI_PATH", "nuclei")
    NIKTO_PATH = _env("NIKTO_PATH", "nikto")
    GOBUSTER_PATH = _env("GOBUSTER_PATH", "gobuster")
    SQLMAP_PATH = _env("SQLMAP_PATH", "sqlmap")
    TESTSSL_PATH = _env("TESTSSL_PATH", "testssl.sh")
    TRIVY_PATH = _env("TRIVY_PATH", "trivy")
    PROWLER_PATH = _env("PROWLER_PATH", "prowler")
    SCOUTSUITE_PATH = _env("SCOUTSUITE_PATH", "scoutsuite")
    CHECKOV_PATH = _env("CHECKOV_PATH", "checkov")

    @classmethod
    def ensure_dirs(cls) -> None:
        cls.WORK_DIR.mkdir(parents=True, exist_ok=True)


config = Config()
