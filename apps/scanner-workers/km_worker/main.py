from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import redis
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .api_client import ClaimRejected, WorkerAPI, WorkerAPIError
from .config import config
from .redact import redact, register_secrets
from .registry import ADAPTERS, detect_all
from .runner import JobCancelled, JobContext, terminate_active_processes
from .scope import ScopeError, validate_target

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("km_worker")

_stop = threading.Event()
_detected: dict = {}
_detected_at = 0.0
_detected_lock = threading.Lock()
_worker_api: WorkerAPI | None = None
_rdb: redis.Redis | None = None
_current_jobs: set[str] = set()
_current_lock = threading.Lock()


def get_detection(force: bool = False) -> dict:
    global _detected, _detected_at
    with _detected_lock:
        if force or not _detected or time.time() - _detected_at > 300:
            _detected = detect_all()
            _detected_at = time.time()
        return _detected


def heartbeat_loop() -> None:
    try:
        rdb = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=5)
    except Exception as exc:
        log.error("heartbeat redis connection failed: %s", exc)
        return
    while not _stop.is_set():
        try:
            payload = {
                "worker_id": config.WORKER_ID,
                "hostname": os.uname().nodename,
                "pid": os.getpid(),
                "at": datetime.now(timezone.utc).isoformat(),
                "concurrency": config.CONCURRENCY,
                "active_jobs": len(_current_jobs),
                "scanners": get_detection(),
            }
            key = f"km:worker:heartbeat:{config.WORKER_ID}"
            pipe = rdb.pipeline()
            pipe.set(key, json.dumps(payload), ex=max(60, config.HEARTBEAT_SECONDS * 4))
            pipe.execute()
        except redis.RedisError as exc:
            log.warning("heartbeat failed: %s", exc)
        _stop.wait(config.HEARTBEAT_SECONDS)
    try:
        rdb.delete(f"km:worker:heartbeat:{config.WORKER_ID}")
    except redis.RedisError:
        pass


def process_job(raw_job: str) -> None:
    global _worker_api, _rdb
    assert _worker_api is not None and _rdb is not None
    try:
        job = json.loads(raw_job)
    except json.JSONDecodeError:
        log.error("discarding malformed job payload")
        return
    scan_id = str(job.get("scan_id") or "")
    if not scan_id:
        log.error("discarding job without scan_id")
        return
    adapter_cls = ADAPTERS.get(job.get("scanner", ""))
    if not adapter_cls:
        log.error("unknown scanner in job: %s", job.get("scanner"))
        try:
            _worker_api.complete(scan_id, "failed", {}, f"Unknown scanner {job.get('scanner')}")
        except WorkerAPIError:
            pass
        return

    credentials = (job.get("credentials") or {}).get("fields") or {}
    register_secrets(credentials.values())
    with _current_lock:
        _current_jobs.add(scan_id)
    ctx = None
    try:
        log.info("claimed scan %s (%s)", scan_id, job.get("scanner"))
        try:
            _worker_api.claim(scan_id)
        except ClaimRejected as exc:
            log.info("job %s not claimable: %s", scan_id, exc)
            return
        target = validate_target(job)
        ctx = JobContext(job, _worker_api, _rdb, target)
        if bool(ctx.scope.get("intrusive_allowed")) is False and adapter_cls.name in {"sqlmap", "auth-baseline"}:
            raise ScopeError("Intrusive scanner requires explicit authorization")
        probe = adapter_cls.probe()
        if not probe.get("available"):
            raise RuntimeError(probe.get("error") or f"{adapter_cls.display} is unavailable")
        ctx.progress(6, "initializing", f"{adapter_cls.display} starting against {job.get('target')}")
        adapter = adapter_cls()
        summary = adapter.run(ctx) or {}
        summary.setdefault("findings", len(ctx.results))
        ctx.flush_results()
        ctx.progress(99, "finalizing", "Persisting findings")
        _worker_api.complete(scan_id, "completed", summary)
        log.info("scan %s completed with %d findings", scan_id, len(ctx.results))
    except JobCancelled as exc:
        log.info("scan %s cancelled: %s", scan_id, exc)
        if ctx is not None:
            try:
                ctx.flush_results()
            except WorkerAPIError:
                pass
            try:
                _worker_api.complete(scan_id, "cancelled", ctx.summary, str(exc))
            except WorkerAPIError:
                log.warning("could not report cancellation for %s", scan_id)
    except (ScopeError, Exception) as exc:
        message = redact(str(exc))[:2000]
        log.warning("scan %s failed: %s", scan_id, message)
        if ctx is not None:
            try:
                ctx.flush_results()
            except WorkerAPIError:
                pass
            try:
                ctx.api.complete(scan_id, "failed", {**ctx.summary, "error": message}, message)
            except WorkerAPIError as api_exc:
                log.error("could not report failure for %s: %s", scan_id, api_exc)
        else:
            try:
                _worker_api.complete(scan_id, "failed", {}, message)
            except WorkerAPIError:
                pass
    finally:
        if ctx is not None:
            ctx.cleanup()
        with _current_lock:
            _current_jobs.discard(scan_id)


def consumer_loop(worker_index: int) -> None:
    assert _rdb is not None
    while not _stop.is_set():
        try:
            item = _rdb.brpop(config.queue_key, timeout=5)
        except redis.RedisError as exc:
            log.warning("queue read failed: %s", exc)
            _stop.wait(3)
            continue
        if item is None:
            continue
        _, raw = item
        try:
            process_job(raw)
        except Exception:
            log.exception("unhandled job failure")
    log.info("consumer %d stopped", worker_index)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker_api, _rdb
    if not config.SERVICE_TOKEN:
        log.error("WORKER_SERVICE_TOKEN is not set; refusing to start")
        raise RuntimeError("WORKER_SERVICE_TOKEN is required")
    config.ensure_dirs()
    _worker_api = WorkerAPI()
    _rdb = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=10)
    _rdb.ping()
    get_detection(force=True)
    log.info("worker %s ready with %d consumers", config.WORKER_ID, config.CONCURRENCY)
    threads = [threading.Thread(target=heartbeat_loop, name="heartbeat", daemon=True)]
    for index in range(config.CONCURRENCY):
        threads.append(threading.Thread(target=consumer_loop, args=(index,), name=f"consumer-{index}", daemon=True))
    for thread in threads:
        thread.start()
    yield
    _stop.set()
    terminate_active_processes()
    for thread in threads:
        thread.join(timeout=5)
    if _worker_api:
        _worker_api.close()
    if _rdb:
        _rdb.close()
    log.info("worker shutdown complete")


app = FastAPI(title="King Malhare Scanner Worker", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.get("/health")
def health():
    detection = get_detection()
    available = [name for name, status in detection.items() if status.get("available")]
    return {
        "status": "ok",
        "worker_id": config.WORKER_ID,
        "active_jobs": len(_current_jobs),
        "available_scanners": available,
        "unavailable_scanners": [name for name in detection if name not in available],
        "at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/ready")
def ready():
    try:
        assert _rdb is not None
        _rdb.ping()
        assert _worker_api is not None
        return {"status": "ready"}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "not_ready", "error": str(exc)})


def main() -> None:
    port = int(os.environ.get("WORKER_HTTP_PORT", "8090"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=config.LOG_LEVEL, access_log=False)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    main()
