import { Link } from "react-router-dom";
import { Logo } from "@/components/layout/Logo";
import { PageTransition } from "@/components/ui";

function LegalLayout({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-ink-950">
      <header className="surface-blur sticky top-0 z-40 border-b border-ink-700/70">
        <div className="mx-auto flex h-16 max-w-4xl items-center justify-between px-5 lg:px-8">
          <Link to="/" aria-label="King Malhare home"><Logo /></Link>
          <nav className="flex items-center gap-4 text-[11.5px] text-ink-400">
            <Link to="/privacy" className="hover:text-ink-100">Privacy</Link>
            <Link to="/terms" className="hover:text-ink-100">Terms</Link>
            <Link to="/login" className="hover:text-ink-100">Sign in</Link>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-4xl px-5 py-12 lg:px-8 lg:py-16">
        <PageTransition>
          <div className="eyebrow">Legal</div>
          <h1 className="mt-3 text-[38px] font-semibold tracking-[-0.04em] text-ink-50 sm:text-[48px]">{title}</h1>
          <p className="mt-3 text-[12px] text-ink-400">Last updated 9 November 2026</p>
          <article className="mt-8 space-y-7 rounded-3xl border border-ink-700 bg-ink-850 p-6 shadow-card sm:p-9">
            {children}
          </article>
          <p className="mt-8 text-[11.5px] leading-relaxed text-ink-400">
            This page applies to this self-hosted King Malhare instance. Questions about data or terms should be directed to the operator of this deployment.
          </p>
        </PageTransition>
      </main>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-[15px] font-semibold tracking-[-0.01em] text-ink-50">{title}</h2>
      <div className="mt-2 space-y-2.5 text-[13px] leading-relaxed text-ink-300">{children}</div>
    </section>
  );
}

export function PrivacyPage() {
  return (
    <LegalLayout title="Privacy Policy">
      <Section title="Who controls the data">
        <p>King Malhare is self-hosted software. The organization operating this instance is the data controller for accounts, assessments, evidence and reports created here. This page explains what the platform stores and why.</p>
      </Section>
      <Section title="What we collect">
        <p>Account details include your name, email address, organization, role and session metadata. Assessment data includes the assets and targets you register, authorization records, scan configuration, scanner output, findings, evidence you upload, reports and audit events.</p>
        <p>Authentication uses opaque session cookies and, for automation, scoped bearer API keys. Passwords are stored as Argon2id hashes. Cloud credentials are encrypted at rest with AES-256-GCM.</p>
      </Section>
      <Section title="How the data is used">
        <p>Data is used to provide the assessment service, enforce written authorization and scope, run scanner jobs, display findings, record remediation and produce reports. Audit events provide accountability for security-relevant actions.</p>
        <p>This deployment does not include third-party advertising or analytics trackers. External vulnerability intelligence lookups are limited to the CVE or CWE identifiers you request.</p>
      </Section>
      <Section title="Retention and deletion">
        <p>Retention follows the policy configured by the organization that operates this instance. Findings are retained so that triage and accepted-risk decisions survive re-assessment. Evidence, report artefacts and audit events may be deleted according to the organization retention policy or an operator request.</p>
      </Section>
      <Section title="Your choices">
        <p>You can request access, correction or deletion of your account data from the operator of this instance. Organization owners can manage members, roles and workspace settings from the console.</p>
      </Section>
      <Section title="Security">
        <p>Access is scoped to the authenticated organization. Mutating browser requests require a CSRF token, API keys are hashed at rest, scanner workers have no public ports and every scan requires an active authorization record.</p>
      </Section>
    </LegalLayout>
  );
}

export function TermsPage() {
  return (
    <LegalLayout title="Terms of Service">
      <Section title="Authorized testing only">
        <p>You may use King Malhare only against systems you own or have explicit, documented permission to test. Every assessment requires a recorded authorization with a named approver and a validity window. You are responsible for complying with applicable law, contracts and the rules of any target environment.</p>
      </Section>
      <Section title="Acceptable use">
        <p>Do not use this platform for unauthorized access, credential stuffing, password spraying, denial of service, data exfiltration or any activity that is unlawful or outside the recorded scope. Intrusive tools require explicit approval and can disrupt services. Run them only in an agreed window against a system you are authorized to test.</p>
      </Section>
      <Section title="Your data and responsibilities">
        <p>You retain ownership of the assets, evidence, findings and reports you create. You are responsible for the accuracy of authorization records and for protecting any credentials or evidence you upload. The operator may suspend access for abuse, legal reasons or violation of these terms.</p>
      </Section>
      <Section title="Availability and warranties">
        <p>This self-hosted software is provided as-is. The operator does not warrant uninterrupted availability, completeness of scanner coverage or that every finding is exploitable in your context. Missing tools are reported as unavailable and are never simulated.</p>
      </Section>
      <Section title="Limitation of liability">
        <p>To the maximum extent permitted by law, the operator is not liable for indirect, incidental or consequential loss, service disruption, data loss or damage arising from use of the platform. You are responsible for backups and for validating findings before acting on them.</p>
      </Section>
      <Section title="Changes">
        <p>The operator may update these terms as the platform or applicable law changes. The current version is always published on this page with the date shown above.</p>
      </Section>
    </LegalLayout>
  );
}
