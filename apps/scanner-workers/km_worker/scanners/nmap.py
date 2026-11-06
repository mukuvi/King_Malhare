from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from ..runner import JobContext, NormalizedResult
from .base import Adapter, AdapterError

RISKY_PORTS = {
    21: ("medium", "FTP service exposed", "FTP transmits credentials and data in clear text and is frequently misconfigured with anonymous access.", "Disable FTP, or replace it with SFTP/FTPS and restrict access by network policy.", "CWE-319"),
    23: ("high", "Telnet service exposed", "Telnet transmits credentials and session data without encryption.", "Disable Telnet and use SSH with key-based authentication.", "CWE-319"),
    139: ("medium", "NetBIOS session service exposed", "NetBIOS session service exposure expands the SMB attack surface and can leak host information.", "Block port 139 at the network boundary and require VPN access for administrative protocols.", "CWE-284"),
    445: ("high", "SMB service exposed", "SMB is reachable from the tested network. Exposed SMB is a common ransomware entry point and has a history of critical remote code execution flaws.", "Restrict SMB to trusted management networks, disable SMBv1, require signing and patch promptly.", "CWE-284"),
    1433: ("high", "Microsoft SQL Server exposed", "A database service is reachable directly from the tested network.", "Restrict database ports to application hosts, require strong authentication and encrypt connections.", "CWE-284"),
    1521: ("high", "Oracle database listener exposed", "A database listener is reachable directly from the tested network.", "Restrict the listener to application hosts and enforce authentication and network ACLs.", "CWE-284"),
    2375: ("critical", "Docker daemon API exposed without TLS", "An unauthenticated Docker API grants host control equivalent to root. This is a critical exposure.", "Close port 2375 immediately, use a protected TLS socket, and never expose the daemon beyond localhost.", "CWE-306"),
    2379: ("high", "etcd client API exposed", "etcd may contain cluster secrets and configuration. Unauthenticated access can compromise the control plane.", "Restrict etcd to the control plane, enable mutual TLS and authentication.", "CWE-306"),
    3306: ("high", "MySQL service exposed", "A database service is reachable directly from the tested network.", "Restrict database ports to application hosts, require TLS and strong authentication.", "CWE-284"),
    3389: ("medium", "Remote Desktop service exposed", "RDP is reachable from the tested network and is a frequent target for credential attacks and remote code execution.", "Place RDP behind a VPN or zero-trust gateway, enable NLA and MFA.", "CWE-284"),
    5432: ("high", "PostgreSQL service exposed", "A database service is reachable directly from the tested network.", "Restrict PostgreSQL to application hosts, enforce scram-sha-256 and TLS.", "CWE-284"),
    5601: ("medium", "Kibana exposed", "Kibana can expose indexed data and administrative functionality.", "Restrict Kibana to trusted networks and require authentication.", "CWE-284"),
    5900: ("high", "VNC service exposed", "VNC commonly lacks strong authentication and provides interactive desktop access.", "Disable VNC or tunnel it through a VPN with strong authentication.", "CWE-306"),
    6379: ("high", "Redis service exposed", "Redis is reachable directly. Unauthenticated Redis permits data access and can be abused for remote code execution through module loading or scheduled jobs.", "Bind Redis to private interfaces, require authentication and TLS, and restrict with firewall rules.", "CWE-306"),
    9042: ("high", "Cassandra service exposed", "A distributed database service is reachable directly from the tested network.", "Restrict the native transport port to application hosts and enable authentication.", "CWE-284"),
    9200: ("high", "Elasticsearch HTTP API exposed", "The Elasticsearch API may allow unauthenticated data access and cluster administration.", "Enable security features, require authentication and restrict the HTTP interface to trusted networks.", "CWE-306"),
    11211: ("high", "Memcached exposed", "Memcached has no authentication by default and is abused for data exposure and amplification attacks.", "Bind Memcached to localhost/private interfaces and block UDP/11211 at the network edge.", "CWE-306"),
    27017: ("high", "MongoDB service exposed", "MongoDB is reachable directly. Misconfigured instances frequently allow unauthenticated reads and writes.", "Enable authorization, bind to private interfaces and restrict access with network policy.", "CWE-306"),
    9090: ("medium", "Prometheus server exposed", "Prometheus may disclose internal metrics, targets and labels.", "Restrict the Prometheus UI to the monitoring network and require authentication.", "CWE-200"),
}


class Nmap(Adapter):
    name = "nmap"
    category = "network"
    binary_key = "nmap"
    display = "Nmap"

    def run(self, ctx: JobContext) -> dict:
        binary = self.binary() or "nmap"
        target = ctx.target.target
        if "://" in target:
            parsed = urlparse(target)
            target = parsed.hostname or target
        ports = str(ctx.config.get("ports", "top-1000"))
        args = [binary, "-oX", "-", "-T4", "--max-retries", "2", "--host-timeout", "15m"]
        if ports == "top-100":
            args += ["--top-ports", "100"]
        elif ports == "all":
            args += ["-p-"]
        else:
            args += ["--top-ports", "1000"]
        if bool(ctx.config.get("service_detection", True)):
            args += ["-sV", "--version-light"]
        if not bool(ctx.config.get("host_discovery", True)):
            args += ["-Pn"]
        if bool(ctx.config.get("os_detection", False)):
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                args += ["-O", "--osscan-limit"]
            else:
                ctx.summary["os_detection_skipped"] = "OS detection requires root in the worker container."
        args.append(target)

        ctx.progress(10, "nmap", f"Port scan started against {target}")
        execution_id = ctx.start_execution("nmap " + " ".join(args[1:-1]) + " <target>")
        result = ctx.run_command(args, timeout=min(840, max(120, int(ctx.deadline - __import__("time").monotonic()))), label="nmap")
        ctx.finish_execution(execution_id, result)
        if result.status == "unavailable":
            raise AdapterError(result.stderr or "nmap is unavailable")
        if not result.stdout.strip():
            raise AdapterError(f"nmap produced no XML output (exit {result.exit_code}): {result.stderr[-500:]}")
        ctx.progress(78, "nmap", "Parsing scan output")
        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError as exc:
            raise AdapterError(f"nmap XML could not be parsed: {exc}") from exc

        hosts_up = 0
        open_ports = 0
        os_matches: list[str] = []
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            hosts_up += 1
            addresses = [a.get("addr", "") for a in host.findall("address")]
            addr = next((a for a in addresses if a), "unknown")
            hostnames = [h.get("name", "") for h in host.findall("./hostnames/hostname")]
            hostname = hostnames[0] if hostnames else ""
            for osmatch in host.findall("./os/osmatch"):
                name = osmatch.get("name", "")
                if name and name not in os_matches:
                    os_matches.append(name)
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                open_ports += 1
                portid = int(port.get("portid", "0") or 0)
                proto = port.get("protocol", "tcp")
                service = port.find("service")
                service_name = service.get("name", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                cpes = [c.text or "" for c in service.findall("cpe")] if service is not None else []
                endpoint = f"{addr}:{portid}"
                if hostname:
                    endpoint = f"{hostname}:{portid}"
                if portid in RISKY_PORTS:
                    severity, title, description, remediation, cwe = RISKY_PORTS[portid]
                    ctx.add_result(
                        NormalizedResult(
                            title=title,
                            severity=severity,
                            confidence="certain",
                            endpoint=endpoint,
                            cwe=cwe,
                            description=description + f" The service was observed as {service_name or 'unknown'}"
                            + (f" ({product} {version})".strip() if product or version else "")
                            + ". Reachability was confirmed; authentication and patch level were not bypassed by this check.",
                            remediation=remediation,
                            evidence={
                                "host": addr,
                                "hostname": hostname,
                                "port": portid,
                                "protocol": proto,
                                "state": "open",
                                "service": service_name,
                                "product": product,
                                "version": version,
                                "cpe": cpes,
                            },
                            raw={"nmap_port": ET.tostring(port, encoding="unicode")[:2000]},
                        )
                    )
                elif product or version:
                    ctx.summary.setdefault("disclosed_services", []).append(
                        {"endpoint": endpoint, "service": service_name, "product": product, "version": version}
                    )
        ctx.progress(94, "nmap", f"{hosts_up} hosts up, {open_ports} open ports")
        return {
            "hosts_up": hosts_up,
            "open_ports": open_ports,
            "os_matches": os_matches[:8],
            "exit_code": result.exit_code,
            "findings": len(ctx.results),
            "stderr": result.stderr[-500:],
        }
