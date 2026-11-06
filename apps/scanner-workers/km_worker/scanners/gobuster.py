from __future__ import annotations

import re

from ..config import config
from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

RESULT_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
HOT_PATTERNS = [
    (re.compile(r"(?i)(^|/)\.env"), "critical", "Exposed environment file discovered", "Remove the file, rotate secrets and restrict static file serving."),
    (re.compile(r"(?i)(^|/)\.git"), "high", "Exposed Git metadata discovered", "Block access to .git and redeploy from a clean artifact."),
    (re.compile(r"(?i)(backup|dump|\.sql$|\.bak$|\.old$|\.tar\.gz$|\.zip$)"), "high", "Potential backup or database dump discovered", "Remove backup artifacts from the web root and rotate contained credentials."),
    (re.compile(r"(?i)(admin|phpmyadmin|pma|console|manager)"), "medium", "Administrative interface discovered", "Restrict administrative interfaces to trusted networks and require strong authentication."),
    (re.compile(r"(?i)(debug|actuator|metrics|prometheus|server-status|phpinfo)"), "medium", "Diagnostic interface discovered", "Disable diagnostic endpoints in production or restrict them to the management network."),
    (re.compile(r"(?i)(swagger|openapi|api/docs|graphiql)"), "low", "API documentation discovered", "Require authentication for documentation endpoints in production."),
]


class Gobuster(Adapter):
    name = "gobuster"
    category = "web"
    binary_key = "gobuster"
    display = "Gobuster"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "gobuster"
        wordlist = config.DIR_WORDLIST
        if not wordlist.exists():
            raise AdapterError(f"Wordlist not found: {wordlist}")
        preset = str(ctx.config.get("wordlist", "common"))
        if preset == "small":
            words = wordlist.read_text(errors="ignore").splitlines()[:30]
            custom = ctx.workdir / "wordlist.txt"
            custom.write_text("\n".join(words))
            wordlist = custom
        threads = max(1, min(20, int(ctx.config.get("threads", 10) or 10)))
        extensions = ctx.config.get("extensions") or []
        args = [
            binary, "dir", "-u", ctx.target.target, "-w", str(wordlist),
            "-t", str(threads), "--no-progress", "--no-error", "-q",
            "-s", "200,204,301,302,401,403", "--timeout", "10s",
        ]
        if extensions:
            args += ["-x", ",".join(str(e) for e in extensions)]
        ctx.progress(10, "gobuster", "Content discovery running")
        execution_id = ctx.start_execution(f"gobuster dir -u <target> -w {preset} -t {threads}")
        result = ctx.run_command(args, timeout=min(600, max(120, ctx.config.get("timeout", 300) or 300)), label="gobuster")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "gobuster is unavailable")
        matches = []
        for line in (result.stdout + "\n" + result.stderr).splitlines():
            match = RESULT_RE.search(line)
            if match:
                matches.append((match.group(1), int(match.group(2)), int(match.group(3) or 0)))
        ctx.progress(85, "gobuster", f"{len(matches)} paths returned")
        reported = 0
        for path, status, size in matches[:300]:
            if ctx.check_cancel():
                break
            path_lower = path.lower()
            category = None
            for pattern, severity, title, remediation in HOT_PATTERNS:
                if pattern.search(path_lower):
                    category = (severity, title, remediation)
                    break
            if not category:
                continue
            if status in (401, 403) and category[0] in {"critical", "high"}:
                # A protected file is still worth noting, but is not an exposure.
                severity = "info"
            else:
                severity = category[0]
            ctx.add_result(
                NormalizedResult(
                    title=f"{category[1]}: {path}",
                    severity=severity,
                    confidence="firm" if status in (200, 204, 301, 302) else "tentative",
                    endpoint=ctx.target.target.rstrip("/") + path,
                    cwe="CWE-538",
                    description=f"Content discovery found {path} returning HTTP {status} (size {size} bytes). Confirm the content and whether the path should be publicly reachable.",
                    remediation=category[2],
                    evidence={"path": path, "status": status, "size": size, "wordlist": preset},
                )
            )
            reported += 1
        return {"paths_found": len(matches), "findings": reported, "wordlist": preset, "threads": threads}
