from __future__ import annotations

import re
import threading

_lock = threading.Lock()
_secret_values: set[str] = set()

_PATTERNS = [
    (re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}"), "[redacted-aws-key]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[A-Za-z0-9._\-+/=]{8,}"), r"\1[redacted]"),
    (re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*)('[^']*'|\"[^\"]*\"|[^\s&,;]+)"), r"\1[redacted]"),
    (re.compile(r"(?i)([?&](?:token|key|api_key|apikey|password|secret|access_token|sig|signature)=)[^&\s]+"), r"\1[redacted]"),
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[redacted]@"),
]


def register_secrets(values) -> None:
    with _lock:
        for value in values or []:
            text = str(value or "").strip()
            if len(text) >= 6:
                _secret_values.add(text)


def redact(text: str) -> str:
    if not text:
        return text
    out = str(text)
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    with _lock:
        secrets = sorted(_secret_values, key=len, reverse=True)
    for value in secrets:
        out = out.replace(value, "[redacted]")
    return out
