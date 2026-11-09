import { Link } from "react-router-dom";
import { Cloud, Plug } from "lucide-react";
import { useCloudConnections } from "@/hooks/queries";
import { CategoryPage } from "@/components/domain/category-page";
import { Badge, Button, Card, CardContent } from "@/components/ui";

export function WebSecurityPage() {
  return (
    <CategoryPage
      category="web"
      eyebrow="Web application security"
      title="Web application assessments"
      description="Header, cookie, CORS, TLS and exposure checks run first. Template and active scanners provide deeper coverage against the same authorized target."
      capabilities={[
        { title: "Security headers, cookies and TLS", text: "CSP, HSTS, framing, referrer policy, cookie flags, certificate validity and protocol version.", scanner: "http-baseline" },
        { title: "Exposure discovery", text: "Confirms .git, .env, actuator, Swagger, backups and diagnostic pages with content signatures.", scanner: "http-baseline" },
        { title: "CVE and misconfiguration templates", text: "Nuclei templates are parsed from JSONL into the normalized finding schema.", scanner: "nuclei" },
        { title: "Passive and active web scanning", text: "ZAP spider and passive alerts; active scan requires intrusive authorization and consent.", scanner: "zap" },
        { title: "Server misconfiguration", text: "Nikto observations are recorded as tentative until verified.", scanner: "nikto" },
        { title: "Content discovery", text: "Bounded directory discovery against a curated wordlist with status and size evidence.", scanner: "gobuster" },
        { title: "SQL injection verification", text: "Guarded, single-parameter boolean/error testing. Requires intrusive approval; no shell or data dump.", scanner: "sqlmap" },
        { title: "Burp Suite integration", text: "Crawl and audit scans through a Burp REST API endpoint. Audit mode requires intrusive approval.", scanner: "burp" },
        { title: "Discovery and fingerprinting", text: "ffuf, WhatWeb, WAFW00F, httpx and Subfinder expand content, technology and hostname discovery with JSON evidence.", scanner: "ffuf" },
        { title: "API contract testing", text: "Schemathesis exercises an OpenAPI schema with generated requests and reports contract failures.", scanner: "schemathesis" },
      ]}
      warning="Active web scanning and SQLMap send attack traffic. Only run them with an authorization that permits intrusive testing and within an agreed window."
    />
  );
}

export function NetworkSecurityPage() {
  return (
    <CategoryPage
      category="network"
      eyebrow="Network security"
      title="Network assessments"
      description="Host discovery, service enumeration and TLS analysis from an isolated worker. Network targets are limited to /16 or smaller and revalidated before execution."
      capabilities={[
        { title: "Host and port discovery", text: "Nmap top-port and full TCP scans with bounded retries and host timeouts.", scanner: "nmap" },
        { title: "Service and version detection", text: "Service banners and CPE data are recorded as evidence; exposure findings are created for risky services.", scanner: "nmap" },
        { title: "Risky service exposure", text: "Telnet, SMB, RDP, Redis, MongoDB, Elasticsearch, exposed databases and Docker API are flagged.", scanner: "nmap" },
        { title: "OS fingerprint hints", text: "OS detection runs only when the worker has the required privilege; otherwise the summary says it was skipped.", scanner: "nmap" },
        { title: "TLS protocol and certificate", text: "testssl.sh findings include protocol, cipher and certificate weaknesses.", scanner: "testssl" },
        { title: "TLS analysis with SSLyze", text: "SSLyze adds protocol, cipher and certificate checks with structured JSON evidence.", scanner: "sslyze" },
      ]}
      warning="Private ranges are reachable only when the asset authorization explicitly allows internal targets. Scope the worker deployment to an isolated assessment network."
    />
  );
}

export function AuthenticationPage() {
  return (
    <CategoryPage
      category="authentication"
      eyebrow="Authentication security"
      title="Authentication testing"
      description="Bounded verification of login throttling, lockout behaviour, session cookie flags and session rotation using one explicitly supplied test account."
      capabilities={[
        { title: "Rate limiting and lockout", text: "A small number of failed attempts establishes whether the login endpoint throttles or locks accounts. Stops immediately on 429 or lockout.", scanner: "auth-baseline" },
        { title: "Authentication bypass", text: "If an invalid password produces a success response, a critical finding is recorded with the response evidence.", scanner: "auth-baseline" },
        { title: "Session cookie attributes", text: "HttpOnly, Secure and SameSite flags are checked on the authentication cookie.", scanner: "auth-baseline" },
        { title: "Session rotation", text: "The pre-authentication and post-authentication cookie values are compared for fixation.", scanner: "auth-baseline" },
      ]}
      warning="This module is intrusive and can lock the test account. Use a dedicated account you control, never a real user, and never run credential stuffing or password spraying against third-party accounts."
    />
  );
}

export function CloudSecurityPage() {
  const connections = useCloudConnections();
  return (
    <CategoryPage
      category="cloud"
      eyebrow="Cloud security"
      title="Cloud posture assessments"
      description="Read-only posture checks against cloud accounts using encrypted credentials. Credentials are decrypted only at dispatch and never returned to the browser."
      capabilities={[
        { title: "AWS native posture", text: "Root MFA, root access keys, CloudTrail logging, S3 public access, password policy, open security groups and stale IAM keys.", scanner: "aws-posture" },
        { title: "Prowler controls", text: "Prowler runs read-only checks and its failed controls are normalized into findings.", scanner: "prowler" },
        { title: "ScoutSuite configuration", text: "ScoutSuite results are parsed into per-control findings when the tool is installed.", scanner: "scoutsuite" },
        { title: "Checkov IaC", text: "Static analysis of an allowlisted infrastructure path mounted into the worker.", scanner: "checkov" },
        { title: "Container and supply chain", text: "Grype and Syft scan container images and generate an SBOM for vulnerability review.", scanner: "grype" },
        { title: "Code and IaC", text: "Semgrep, Gitleaks and tfsec add SAST, secret scanning and Terraform misconfiguration checks.", scanner: "semgrep" },
      ]}
      warning="Use read-only credentials scoped to the minimum required permissions. The platform does not validate that the credential itself is read-only; review it before saving."
      extra={
        <Card>
          <CardContent className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-ink-600 bg-ink-800 text-ink-300"><Cloud className="h-4 w-4" /></div>
              <div>
                <p className="text-[12px] font-medium text-ink-100">Cloud connections</p>
                <p className="mt-0.5 text-[10.5px] text-ink-400">
                  {connections.isLoading ? "Loading…" : connections.data?.items.length ? `${connections.data.items.length} stored connection${connections.data.items.length === 1 ? "" : "s"}` : "No cloud connection stored"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {connections.data?.items.slice(0, 3).map((connection) => (
                <Badge key={connection.id}>{connection.provider.toUpperCase()} · {connection.name}</Badge>
              ))}
              <Link to="/integrations"><Button variant="secondary" size="sm"><Plug className="h-3.5 w-3.5" /> Manage connections</Button></Link>
            </div>
          </CardContent>
        </Card>
      }
    />
  );
}
