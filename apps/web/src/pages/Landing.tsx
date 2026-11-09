import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ArrowRight,
  BadgeCheck,
  Boxes,
  CheckCircle2,
  ChevronRight,
  Cloud,
  Code2,
  FileSearch,
  FileText,
  Fingerprint,
  Globe2,
  KeyRound,
  LockKeyhole,
  Network,
  Radar,
  ShieldCheck,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { Logo } from "@/components/layout/Logo";
import { buttonStyles, SeverityBadge } from "@/components/ui";

const toolGroups = [
  {
    label: "Information gathering",
    tools: ["Amass", "theHarvester", "DNSRecon", "DNSEnum", "Fierce", "Sublist3r", "Assetfinder", "Whois", "Subfinder", "httpx"],
  },
  {
    label: "Web and API",
    tools: ["Burp Suite", "OWASP ZAP", "Nikto", "SQLMap", "ffuf", "Gobuster", "WhatWeb", "WAFW00F", "DIRB", "dirsearch", "feroxbuster", "Wfuzz", "Arjun", "ParamSpider", "Commix", "Dalfox", "XSStrike", "WPScan", "JoomScan", "Droopescan", "Skipfish", "Wapiti", "Schemathesis"],
  },
  {
    label: "Network and TLS",
    tools: ["Nmap", "Masscan", "Netdiscover", "arp-scan", "NBTscan", "Enum4linux", "SMBMap", "onesixtyone", "SNMPWalk", "LDAPSearch", "testssl.sh", "SSLyze", "SSLScan", "Kube-hunter"],
  },
  {
    label: "Cloud, container and code",
    tools: ["Trivy", "Grype", "Syft", "Prowler", "ScoutSuite", "Checkov", "tfsec", "Semgrep", "Gitleaks", "Bandit", "TruffleHog", "SearchSploit"],
  },
];

const capabilities = [
  { icon: Boxes, title: "Asset inventory", text: "Domains, APIs, IPs, ranges, cloud accounts and containers with ownership, environment and authorization records." },
  { icon: Radar, title: "Scan orchestration", text: "A Redis-backed queue, isolated workers, live progress, cancellation and an organization-wide emergency stop." },
  { icon: Globe2, title: "Web assessment", text: "Nuclei, OWASP ZAP, Nikto, Gobuster and a first-party HTTP engine for headers, cookies, CORS, TLS and exposure." },
  { icon: Network, title: "Network assessment", text: "Nmap discovery, service enumeration and risky exposure detection with scope checks before every packet." },
  { icon: Cloud, title: "Cloud posture", text: "AWS read-only checks, Prowler, ScoutSuite and Checkov adapters with encrypted credentials that never reach the browser." },
  { icon: KeyRound, title: "Authentication testing", text: "Bounded rate-limit and lockout verification against explicit test accounts. No credential stuffing." },
  { icon: FileSearch, title: "Finding lifecycle", text: "Deduplicated findings with CVSS, CVE/CWE, evidence, ownership, status, remediation and retest history." },
  { icon: FileText, title: "Client-ready reports", text: "Fourteen-section HTML and PDF reports with scope, methodology, evidence, risk analysis and remediation guidance." },
  { icon: BadgeCheck, title: "Guided remediation", text: "Every finding carries technical impact, business impact and a concrete recommendation. Track actions, owners and deadlines." },
  { icon: Code2, title: "API automation", text: "Scoped bearer keys and an OpenAPI 3.1 document let CI, scripts and external platforms run the same authorized workflow." },
];

const steps = [
  { number: "01", title: "Register the asset", text: "Describe what it is, where it runs and who owns it. Targets are parsed and validated, and cloud metadata addresses are rejected outright." },
  { number: "02", title: "Record authorization", text: "Attach a written approval reference, approver, expiry and whether intrusive testing or private ranges are permitted. Nothing runs without it." },
  { number: "03", title: "Choose the assessment", text: "Pick a scanner and profile. Review the exact scope snapshot, parameters and approval chain before anything is queued." },
  { number: "04", title: "Triage, retest, report", text: "Findings are normalized, deduplicated and assigned. Fix, retest, compare against the baseline, then export a professional report." },
];

export function LandingPage() {
  return (
    <div className="min-h-screen bg-ink-950">
      <header className="surface-blur sticky top-0 z-40 border-b border-ink-700/70">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5 lg:px-8">
          <Link to="/" aria-label="King Malhare home"><Logo /></Link>
          <nav className="hidden items-center gap-7 text-[12.5px] text-ink-300 md:flex">
            <a href="#platform" className="transition-colors hover:text-ink-50">Platform</a>
            <a href="#workflow" className="transition-colors hover:text-ink-50">Workflow</a>
            <a href="#security" className="transition-colors hover:text-ink-50">Security model</a>
            <Link to="/api-docs" className="transition-colors hover:text-ink-50">API</Link>
          </nav>
          <div className="flex items-center gap-2">
            <Link to="/login" className={buttonStyles("ghost", "sm")}>Sign in</Link>
            <Link to="/register" className={buttonStyles("primary", "sm")}>Start assessing</Link>
          </div>
        </div>
      </header>

      <main>
        <section className="relative overflow-hidden border-b border-ink-700/70">
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute -left-28 top-6 h-80 w-80 rounded-full bg-amber-200/50 blur-3xl" />
            <div className="absolute -right-24 top-0 h-96 w-96 rounded-full bg-mint-200/45 blur-3xl" />
            <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-lilac-200/40 blur-3xl" />
          </div>
          <div className="pointer-events-none absolute inset-0 dot-grid opacity-40 [mask-image:radial-gradient(ellipse_at_center,black_10%,transparent_70%)]" />
          <div className="relative mx-auto grid max-w-6xl gap-14 px-5 pb-20 pt-16 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:px-8 lg:pb-28 lg:pt-24">
            <div className="min-w-0">
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
                <h1 className="max-w-[620px] break-words text-[38px] font-semibold leading-[1.02] tracking-[-0.045em] text-ink-50 sm:text-[58px] lg:text-[64px]">
                  Know your weaknesses <span className="text-gradient-teal">before attackers do.</span>
                </h1>
                <p className="mt-6 max-w-[520px] text-[15px] leading-relaxed text-ink-300">
                  King Malhare brings asset inventory, authorization, scanner orchestration, findings and client-ready reporting into one self-hosted security workstation.
                </p>
                <p className="mt-3 max-w-[520px] text-[12.5px] leading-relaxed text-ink-400">
                  Built for penetration testers and security engineers who need to prove what was tested, when, and against whose permission.
                </p>
                <div className="mt-8 flex flex-wrap items-center gap-3">
                  <Link to="/register" className={buttonStyles("primary", "lg")}>
                    Open the console <ArrowRight className="h-4 w-4" />
                  </Link>
                  <a href="#platform" className={buttonStyles("secondary", "lg")}>
                    See the platform
                  </a>
                </div>
                <div className="mt-8 flex flex-wrap items-center gap-x-5 gap-y-2 text-[11px] text-ink-400">
                  <span className="flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-lime-600/80" /> Self-hosted</span>
                  <span className="flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-lime-600/80" /> Real scanners, no demo data</span>
                  <span className="flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-lime-600/80" /> Scope enforced twice</span>
                </div>
              </motion.div>
            </div>

            <motion.div
              initial={{ opacity: 0, y: 24, rotate: -0.6 }}
              animate={{ opacity: 1, y: 0, rotate: 0 }}
              transition={{ duration: 0.7, delay: 0.12, ease: [0.22, 1, 0.36, 1] }}
              className="relative min-w-0"
            >
              <div className="absolute -inset-6 rounded-3xl bg-amber-500/[0.05] blur-2xl" />
              <div className="relative overflow-hidden rounded-xl border border-ink-600 bg-ink-950 shadow-lift">
                <div className="flex h-9 items-center gap-1.5 border-b border-ink-700 bg-ink-900 px-3">
                  <span className="h-2 w-2 rounded-full bg-ink-600" />
                  <span className="h-2 w-2 rounded-full bg-ink-600" />
                  <span className="h-2 w-2 rounded-full bg-ink-600" />
                  <span className="ml-3 font-mono text-[9px] text-ink-400">king-malhare / operations</span>
                  <span className="ml-auto rounded border border-ink-700 px-1.5 py-0.5 font-mono text-[8px] text-ink-400">interface preview</span>
                </div>
                <div className="grid grid-cols-[118px_1fr]">
                  <div className="border-r border-ink-800 p-2.5">
                    <div className="mb-3 flex items-center gap-1.5">
                      <span className="flex h-5 w-5 items-center justify-center rounded bg-amber-400 text-[10px] font-bold text-ink-50">K</span>
                      <span className="text-[8px] font-semibold text-ink-200">King Malhare</span>
                    </div>
                    {["Overview", "Assets", "Scans", "Web", "Network", "Cloud", "Findings", "Reports"].map((item, index) => (
                      <div key={item} className={`mb-0.5 flex items-center gap-1.5 rounded px-1.5 py-1 text-[8px] ${index === 0 ? "bg-ink-800 text-ink-100" : "text-ink-400"}`}>
                        <span className={`h-1 w-1 rounded-full ${index === 0 ? "bg-amber-400" : "bg-ink-600"}`} />
                        {item}
                      </div>
                    ))}
                  </div>
                  <div className="p-3.5">
                    <div className="mb-3 flex items-center justify-between">
                      <div>
                        <p className="text-[8px] uppercase tracking-[0.14em] text-ink-400">Security overview</p>
                        <p className="mt-1 text-[13px] font-medium text-ink-100">Posture at a glance</p>
                      </div>
                      <span className="rounded bg-amber-400/15 px-2 py-1 text-[8px] font-medium text-amber-700">Live data</span>
                    </div>
                    <div className="mb-3 grid grid-cols-3 gap-1.5">
                      {["Assets", "Active scans", "Critical"].map((label) => (
                        <div key={label} className="rounded border border-ink-700 bg-ink-900 p-2">
                          <p className="text-[7px] text-ink-400">{label}</p>
                          <div className="mt-2 h-1.5 w-8 rounded bg-ink-700" />
                        </div>
                      ))}
                    </div>
                    <div className="rounded border border-ink-700 bg-ink-900 p-2.5">
                      <div className="mb-2 flex items-center justify-between">
                        <p className="text-[8px] text-ink-400">Recent findings</p>
                        <span className="text-[7px] text-ink-400">normalized</span>
                      </div>
                      <div className="space-y-1.5">
                        {[
                          ["Missing security header", "medium"],
                          ["Exposed service", "high"],
                          ["TLS configuration", "low"],
                        ].map(([title, sev]) => (
                          <div key={title} className="flex items-center gap-2 rounded border border-ink-800 bg-ink-850 px-2 py-1.5">
                            <SeverityBadge severity={sev as "medium" | "high" | "low"} />
                            <span className="flex-1 truncate text-[8px] text-ink-300">{title}</span>
                            <span className="font-mono text-[7px] text-ink-400">open</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="mt-2.5 rounded border border-amber-500/20 bg-amber-500/[0.04] p-2 font-mono text-[7px] leading-relaxed text-amber-700/80">
                      <div className="flex items-center gap-1.5"><Terminal className="h-2.5 w-2.5" /> worker → nmap · nuclei · http-baseline</div>
                      <div className="mt-1 text-ink-400">scope revalidated · authorization active</div>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        <section className="border-b border-ink-700/70 bg-ink-850/70">
          <div className="mx-auto max-w-6xl px-5 py-10 lg:px-8">
            <div className="mb-6 flex items-end justify-between gap-4">
              <div>
                <div className="eyebrow">The Kali toolbelt</div>
                <h2 className="mt-2 text-[24px] font-semibold tracking-[-0.03em] sm:text-[30px]">Real tools across every assessment layer.</h2>
              </div>
              <span className="hidden rounded-full border border-ink-700 bg-ink-850 px-3 py-1 text-[10px] text-ink-400 sm:inline-flex">Availability is detected, never faked</span>
            </div>
            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
              {toolGroups.map((group) => (
                <div key={group.label}>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-teal-700">{group.label}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {group.tools.map((tool) => (
                      <span key={tool} className="rounded-full border border-ink-700 bg-ink-850 px-2.5 py-1 text-[10px] text-ink-300">{tool}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="platform" className="mx-auto max-w-6xl px-5 py-20 lg:px-8 lg:py-28">
          <div className="max-w-2xl">
            <div className="eyebrow">The platform</div>
            <h2 className="mt-3 text-[34px] font-semibold leading-[1.05] tracking-[-0.035em] sm:text-[42px]">One workstation. The whole assessment.</h2>
            <p className="mt-4 text-[14px] leading-relaxed text-ink-300">Not another dashboard layered over a script runner. King Malhare models authorization, execution, evidence and remediation as first-class data.</p>
          </div>
          <div className="mt-12 grid gap-px overflow-hidden rounded-2xl border border-ink-650 bg-ink-650 shadow-soft sm:grid-cols-2 lg:grid-cols-4">
            {capabilities.map((capability, index) => {
              const Icon = capability.icon;
              return (
                <motion.div
                  key={capability.title}
                  initial={{ opacity: 0, y: 16 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.15 }}
                  transition={{ duration: 0.4, delay: (index % 4) * 0.05 }}
                  className="group bg-ink-850 p-5 transition-colors hover:bg-ink-800"
                >
                  <div className="mb-4 flex h-8 w-8 items-center justify-center rounded-xl border border-ink-600 bg-ink-900 text-amber-700 transition-colors group-hover:border-amber-500/30">
                    <Icon className="h-4 w-4" strokeWidth={1.8} />
                  </div>
                  <h3 className="text-[13px] font-semibold text-ink-50">{capability.title}</h3>
                  <p className="mt-2 text-[11.5px] leading-relaxed text-ink-400">{capability.text}</p>
                </motion.div>
              );
            })}
          </div>
        </section>

        <section id="workflow" className="border-y border-ink-700/70 bg-ink-900/60">
          <div className="mx-auto max-w-6xl px-5 py-20 lg:px-8 lg:py-28">
            <div className="grid gap-12 lg:grid-cols-[0.8fr_1.2fr]">
              <div>
                <div className="eyebrow">The workflow</div>
                <h2 className="mt-3 text-[34px] font-semibold leading-[1.05] tracking-[-0.035em] sm:text-[42px]">Intake to evidence, without gaps.</h2>
                <p className="mt-4 max-w-md text-[14px] leading-relaxed text-ink-300">Every assessment is traceable from the written authorization to the exact scanner execution and the generated report.</p>
                <Link to="/register" className={buttonStyles("outline", "md", "mt-7")}>Start with an authorized asset <ArrowRight className="h-3.5 w-3.5" /></Link>
              </div>
              <div className="divide-y divide-ink-700/70 border-y border-ink-700/70">
                {steps.map((step, index) => (
                  <motion.div
                    key={step.number}
                    initial={{ opacity: 0, x: 18 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true, amount: 0.2 }}
                    transition={{ duration: 0.4, delay: index * 0.06 }}
                    className="grid gap-3 py-6 sm:grid-cols-[48px_1fr]"
                  >
                    <span className="font-mono text-[11px] text-amber-700/80">{step.number}</span>
                    <div>
                      <h3 className="text-[14px] font-semibold text-ink-50">{step.title}</h3>
                      <p className="mt-1.5 max-w-xl text-[12.5px] leading-relaxed text-ink-400">{step.text}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section id="security" className="mx-auto max-w-6xl px-5 py-20 lg:px-8 lg:py-28">
          <div className="grid gap-12 lg:grid-cols-2 lg:items-center">
            <div>
              <div className="eyebrow">Security model</div>
              <h2 className="mt-3 text-[34px] font-semibold leading-[1.05] tracking-[-0.035em] sm:text-[42px]">The platform is part of the attack surface.</h2>
              <p className="mt-4 text-[14px] leading-relaxed text-ink-300">King Malhare applies the same discipline to itself: Argon2id authentication, opaque sessions, CSRF protection, encrypted cloud credentials, strict RBAC and an append-only audit trail.</p>
              <div className="mt-7 grid gap-3 sm:grid-cols-2">
                {[
                  [ShieldCheck, "Scope enforced twice", "API validation and worker re-validation before a single packet leaves the sandbox."],
                  [LockKeyhole, "Credentials stay server-side", "AES-256-GCM at rest. Cloud keys are never serialized to the browser."],
                  [Terminal, "No shell execution", "Scanners run from allowlisted argument vectors with timeouts and output caps."],
                  [Fingerprint, "Evidence integrity", "SHA-256 hashes on evidence files and generated report artefacts."],
                ].map(([Icon, title, text], index) => {
                  const Component = Icon as typeof ShieldCheck;
                  return (
                    <motion.div
                      key={String(title)}
                      initial={{ opacity: 0, y: 14 }}
                      whileInView={{ opacity: 1, y: 0 }}
                      viewport={{ once: true, amount: 0.2 }}
                      transition={{ duration: 0.4, delay: index * 0.06 }}
                      className="rounded-lg border border-ink-700 bg-ink-850/70 p-3.5"
                    >
                      <Component className="mb-2 h-4 w-4 text-amber-700" />
                      <p className="text-[12px] font-medium text-ink-100">{String(title)}</p>
                      <p className="mt-1 text-[11px] leading-relaxed text-ink-400">{String(text)}</p>
                    </motion.div>
                  );
                })}
              </div>
            </div>
            <div className="overflow-hidden rounded-xl border border-ink-650 bg-ink-950 shadow-lift">
              <div className="flex items-center gap-2 border-b border-ink-700 bg-ink-900 px-4 py-2.5">
                <Code2 className="h-3.5 w-3.5 text-ink-400" />
                <span className="font-mono text-[10px] text-ink-400">authorization policy</span>
              </div>
              <pre className="overflow-x-auto p-5 font-mono text-[10.5px] leading-[1.8] text-ink-300">
{`assert asset.org_id == actor.org_id
assert authorization.status == "active"
assert authorization.expires_at > now()
assert job.target in authorization.target_scope

if scanner.is_intrusive:
    assert actor.can("scans:intrusive")
    assert authorization.intrusive_allowed
    assert request.confirm_intrusive

if target.is_private():
    assert authorization.allow_private
    assert not target.is_metadata_endpoint()

queue.enqueue(job)  # worker repeats every check`}
              </pre>
              <div className="flex items-center gap-2 border-t border-ink-700 bg-ink-900 px-4 py-3 text-[10.5px] text-ink-400">
                <BadgeCheck className="h-3.5 w-3.5 text-lime-600/80" />
                Any failed condition stops the assessment before execution.
              </div>
            </div>
          </div>
        </section>

        <section className="border-t border-ink-700/70">
          <div className="mx-auto max-w-6xl px-5 py-16 lg:px-8">
            <motion.div
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.5 }}
              className="grid gap-6 rounded-3xl border border-ink-650 bg-gradient-to-br from-amber-100/80 via-ink-850 to-mint-100/70 p-7 shadow-soft sm:p-10 lg:grid-cols-[1.3fr_0.7fr] lg:items-center"
            >
              <div>
                <div className="mb-3 flex items-center gap-2">
                  <TriangleAlert className="h-4 w-4 text-amber-700" />
                  <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-700">Operator's tool</span>
                </div>
                <h2 className="max-w-2xl text-[28px] font-semibold leading-[1.1] tracking-[-0.03em] sm:text-[34px]">Built for the person holding the keyboard.</h2>
                <p className="mt-3 max-w-xl text-[13px] leading-relaxed text-ink-300">No simulated scans. No decorative metrics. When a tool is missing, the platform says so. When a target is out of scope, it refuses. When a scan runs, you see the real output.</p>
              </div>
              <div className="flex flex-col gap-2 sm:flex-row lg:flex-col">
                <Link to="/register" className={buttonStyles("primary", "lg", "w-full")}>Create your workspace <ChevronRight className="h-4 w-4" /></Link>
                <Link to="/login" className={buttonStyles("secondary", "lg", "w-full")}>Sign in</Link>
              </div>
            </motion.div>
          </div>
        </section>
      </main>

      <footer className="border-t border-ink-700/70">
        <div className="mx-auto flex max-w-6xl flex-col gap-5 px-5 py-8 sm:flex-row sm:items-center sm:justify-between lg:px-8">
          <div className="flex items-center gap-3">
            <Logo compact />
            <span className="text-[11px] text-ink-400">Security testing, under control.</span>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-2 text-[11px] text-ink-400">
            <Link to="/privacy" className="hover:text-ink-200">Privacy Policy</Link>
            <Link to="/terms" className="hover:text-ink-200">Terms of Service</Link>
            <Link to="/api-docs" className="hover:text-ink-200">API</Link>
            <Link to="/login" className="hover:text-ink-200">Sign in</Link>
            <span>Authorized testing only</span>
            <span className="font-mono">v1.0.0</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
