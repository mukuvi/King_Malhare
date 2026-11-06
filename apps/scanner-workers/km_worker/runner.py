from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field

import redis

from .api_client import WorkerAPI, WorkerAPIError
from .config import config
from .redact import redact
from .scope import ValidatedTarget

log = logging.getLogger("km_worker.runner")

_active_processes: set[subprocess.Popen] = set()
_active_lock = threading.Lock()


def terminate_active_processes() -> None:
    with _active_lock:
        procs = list(_active_processes)
    for proc in procs:
        _kill_process_group(proc, signal.SIGTERM)


def _kill_process_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


class JobCancelled(Exception):
    pass


@dataclass
class NormalizedResult:
    title: str
    severity: str
    endpoint: str
    description: str
    remediation: str = ""
    confidence: str = "firm"
    cve: str = ""
    cwe: str = ""
    cvss: float | None = None
    evidence: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    fingerprint: str = ""

    def finalize(self, scanner_name: str) -> None:
        if not self.fingerprint:
            key = "|".join(
                [
                    scanner_name,
                    self.title.strip().lower(),
                    self.endpoint.strip().lower(),
                    self.cve.upper(),
                    self.cwe.upper(),
                ]
            )
            self.fingerprint = hashlib.sha256(key.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title[:240],
            "severity": self.severity,
            "confidence": self.confidence,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "endpoint": self.endpoint[:2000],
            "description": self.description[:5000],
            "remediation": self.remediation[:5000],
            "evidence": redact_dict(self.evidence),
            "raw": redact_dict(self.raw),
        }


@dataclass
class CommandResult:
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.status == "completed" and (self.exit_code == 0 or self.exit_code is None)


def redact_dict(value, depth: int = 0):
    if depth > 6:
        return "[depth limit]"
    if isinstance(value, dict):
        out = {}
        for k, v in list(value.items())[:80]:
            if re.search(r"(password|secret|token|api[_-]?key|credential|authorization)", str(k), re.I):
                out[str(k)] = "[redacted]"
            else:
                out[str(k)] = redact_dict(v, depth + 1)
        return out
    if isinstance(value, list):
        return [redact_dict(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return redact(value)[:8000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def _clean_env(extra: dict | None = None) -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": str(config.WORK_DIR),
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    for key in ("SSL_CERT_FILE", "SSL_CERT_DIR", "TZ"):
        if key in os.environ:
            env[key] = os.environ[key]
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


class JobContext:
    def __init__(self, job: dict, api: WorkerAPI, rdb: redis.Redis, target: ValidatedTarget):
        self.job = job
        self.api = api
        self.rdb = rdb
        self.target = target
        self.scan_id = job["scan_id"]
        self.org_id = job["org_id"]
        self.scanner_name = job.get("scanner", "")
        self.config = job.get("config") or {}
        self.scope = job.get("scope") or {}
        self.deadline = time.monotonic() + config.JOB_TIMEOUT
        self.workdir = config.WORK_DIR / self.scan_id
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.results: list[NormalizedResult] = []
        self._seen: set[str] = set()
        self.cancelled = False
        self.progress_percent = 0
        self.summary: dict = {}

    # -- cancellation -----------------------------------------------------
    def check_cancel(self) -> bool:
        if self.cancelled:
            return True
        try:
            scan_cancel = self.rdb.exists(f"km:scan:cancel:{self.scan_id}")
            org_stop = self.rdb.exists(f"km:org:emergency-stop:{self.org_id}")
            if scan_cancel or org_stop:
                self.cancelled = True
        except redis.RedisError:
            pass
        return self.cancelled

    def raise_if_cancelled(self) -> None:
        if self.check_cancel():
            raise JobCancelled("Assessment cancelled by operator")

    # -- progress ---------------------------------------------------------
    def progress(self, percent: int, phase: str, message: str = "") -> None:
        self.progress_percent = max(self.progress_percent, max(0, min(100, int(percent))))
        try:
            data = self.api.progress(self.scan_id, phase, self.progress_percent, message)
            if data.get("cancel"):
                self.cancelled = True
                raise JobCancelled("Cancellation requested")
        except JobCancelled:
            raise
        except WorkerAPIError as exc:
            log.warning("progress update failed: %s", exc)

    def note(self, phase: str, message: str = "") -> None:
        self.progress(self.progress_percent, phase, message)

    # -- results ----------------------------------------------------------
    def add_result(self, result: NormalizedResult) -> None:
        result.finalize(self.scanner_name)
        if result.fingerprint in self._seen:
            return
        self._seen.add(result.fingerprint)
        self.results.append(result)

    def flush_results(self) -> None:
        if not self.results:
            return
        batch: list[dict] = []
        for result in self.results:
            if len(batch) >= 40:
                self.api.results(self.scan_id, batch)
                batch = []
            batch.append(result.to_dict())
        if batch:
            self.api.results(self.scan_id, batch)
        log.info("submitted %d normalized results for %s", len(self.results), self.scan_id)

    # -- execution --------------------------------------------------------
    def start_execution(self, command: str) -> str:
        try:
            return self.api.execution_start(self.scan_id, self.scanner_name, redact(command))
        except WorkerAPIError as exc:
            log.warning("could not record execution start: %s", exc)
            return ""

    def finish_execution(self, execution_id: str, result: CommandResult) -> None:
        self.api.execution_finish(
            self.scan_id,
            execution_id,
            result.status,
            result.exit_code,
            redact(result.stdout[-20000:]),
            redact(result.stderr[-2000:]),
        )

    def run_command(
        self,
        args: list[str],
        timeout: int | None = None,
        env: dict | None = None,
        label: str = "",
        line_callback=None,
    ) -> CommandResult:
        self.raise_if_cancelled()
        started = time.monotonic()
        remaining = max(1, int(self.deadline - started))
        limit = min(timeout, remaining) if timeout else remaining
        log.info("running %s: %s", label or args[0], redact(" ".join(args)))
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.workdir),
                env=_clean_env(env),
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except FileNotFoundError:
            return CommandResult("unavailable", None, "", f"{args[0]} not found", 0.0)
        except OSError as exc:
            return CommandResult("failed", None, "", str(exc), 0.0)

        with _active_lock:
            _active_processes.add(proc)

        out_chunks: list[str] = []
        err_chunks: list[str] = []
        out_size = [0]
        err_size = [0]

        def reader(stream, chunks, size, callback=None):
            try:
                for line in iter(stream.readline, ""):
                    if size[0] < config.MAX_OUTPUT:
                        chunk = line[: max(0, config.MAX_OUTPUT - size[0])]
                        chunks.append(chunk)
                        size[0] += len(chunk)
                    if callback:
                        try:
                            callback(line.rstrip("\n"))
                        except Exception:
                            log.debug("line callback failed", exc_info=True)
            except (ValueError, OSError):
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        out_thread = threading.Thread(target=reader, args=(proc.stdout, out_chunks, out_size, line_callback), daemon=True)
        err_thread = threading.Thread(target=reader, args=(proc.stderr, err_chunks, err_size), daemon=True)
        out_thread.start()
        err_thread.start()

        status = "completed"
        deadline = time.monotonic() + limit
        while proc.poll() is None:
            if self.check_cancel():
                status = "cancelled"
                _kill_process_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    _kill_process_group(proc, signal.SIGKILL)
                break
            if time.monotonic() >= deadline:
                status = "timed_out"
                _kill_process_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    _kill_process_group(proc, signal.SIGKILL)
                break
            time.sleep(0.35)

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc, signal.SIGKILL)
            proc.wait(timeout=3)
        out_thread.join(timeout=3)
        err_thread.join(timeout=3)
        with _active_lock:
            _active_processes.discard(proc)

        stdout = "".join(out_chunks)
        stderr = "".join(err_chunks)
        if status == "cancelled":
            self.cancelled = True
            raise JobCancelled("Assessment cancelled while a scanner was running")
        if status == "timed_out":
            return CommandResult("failed", proc.returncode, stdout, (stderr + "\nCommand timed out").strip(), time.monotonic() - started)
        return CommandResult(
            "completed" if proc.returncode == 0 else "failed",
            proc.returncode,
            stdout,
            stderr,
            time.monotonic() - started,
        )

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)
