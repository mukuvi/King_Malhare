import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowLeft, ArrowRight, Check, Eye, EyeOff, ShieldCheck } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { Me } from "@/types";
import { Button, Field, Input } from "@/components/ui";
import { Logo, LogoMark } from "@/components/layout/Logo";

function AuthPanel({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_0.9fr]">
      <div className="flex flex-col px-5 py-6 sm:px-10 lg:px-16">
        <div className="flex items-center justify-between">
          <Link to="/"><Logo /></Link>
          <Link to="/" className="flex items-center gap-1.5 text-[11.5px] text-ink-400 hover:text-ink-100">
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </Link>
        </div>
        <div className="flex flex-1 items-center justify-center py-12">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }} className="w-full max-w-[420px]">
            {children}
          </motion.div>
        </div>
        <p className="text-center text-[10px] text-ink-400">Authorized security testing only. You are responsible for having permission for every target.</p>
      </div>

      <div className="relative hidden overflow-hidden border-l border-ink-700/70 bg-gradient-to-br from-amber-100 via-ink-850 to-mint-100 lg:block">
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -right-16 -top-16 h-72 w-72 rounded-full bg-amber-200/60 blur-3xl" />
          <div className="absolute -bottom-20 -left-10 h-80 w-80 rounded-full bg-mint-200/60 blur-3xl" />
          <div className="absolute right-1/4 top-1/3 h-48 w-48 rounded-full bg-lilac-200/50 blur-3xl" />
        </div>
        <div className="absolute inset-0 dot-grid opacity-30 [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)]" />
        <div className="relative flex h-full flex-col p-12">
          <div>
            <div className="mb-8 inline-flex items-center gap-3 rounded-2xl border border-ink-700/80 bg-ink-850/80 px-4 py-3 shadow-soft">
              <LogoMark className="h-10 w-10" />
              <div>
                <div className="text-[13px] font-semibold text-ink-50">King Malhare</div>
                <div className="text-[9px] font-semibold uppercase tracking-[0.18em] text-teal-700">Security assessment</div>
              </div>
            </div>
            <div className="eyebrow">Security assessment workstation</div>
            <h2 className="mt-4 max-w-md text-[40px] font-semibold leading-[1.02] tracking-[-0.04em] text-ink-50">
              Evidence, not intuition.
            </h2>
            <p className="mt-5 max-w-sm text-[13px] leading-relaxed text-ink-300">
              Every finding carries its scanner, endpoint, evidence, authorization and timestamp. Every scan is bounded by a written approval you recorded.
            </p>
          </div>
          <div className="mt-10 space-y-3">
            {[
              "Argon2id password hashing and opaque server-side sessions",
              "Explicit authorization required before any scan is queued",
              "Isolated scanner workers with no public network exposure",
              "Report artefacts and evidence hashed with SHA-256",
            ].map((item) => (
              <div key={item} className="flex items-start gap-2.5 text-[12px] text-ink-300">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-lime-600/30 bg-lime-500/10">
                  <Check className="h-2.5 w-2.5 text-lime-700" />
                </span>
                {item}
              </div>
            ))}
          </div>
          <div className="mt-auto rounded-2xl border border-ink-700 bg-ink-850/80 p-4 shadow-soft backdrop-blur">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.14em] text-ink-400">
              <ShieldCheck className="h-3.5 w-3.5 text-amber-700" /> Scope gate
            </div>
            <p className="mt-2 font-mono text-[10.5px] leading-relaxed text-ink-400">
              authorization.status = active<br />
              target ∈ approved_scope<br />
              intrusive ⇒ explicit_consent
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const client = useQueryClient();
  const from = (location.state as { from?: string } | null)?.from ?? "/dashboard";

  const mutation = useMutation({
    mutationFn: () => api.post<Me>("/auth/login", { email: email.trim(), password }),
    onSuccess: (data) => {
      client.setQueryData(["me"], data);
      navigate(from, { replace: true });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Sign-in failed. Try again."),
  });

  return (
    <AuthPanel>
      <div className="mb-8">
        <h1 className="text-[28px] font-semibold tracking-[-0.03em] text-ink-50">Sign in</h1>
        <p className="mt-2 text-[13px] text-ink-300">Access your security workspace.</p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <Field label="Email address">
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" placeholder="you@example.com" required autoFocus />
        </Field>
        <Field label="Password">
          <div className="relative">
            <Input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required className="pr-10" />
            <button type="button" onClick={() => setShowPassword((value) => !value)} className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-ink-400 hover:text-ink-100" aria-label={showPassword ? "Hide password" : "Show password"}>
              {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </Field>
        {error ? <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-700">{error}</div> : null}
        <Button type="submit" size="lg" className="w-full" loading={mutation.isPending} disabled={!email || !password}>
          Sign in <ArrowRight className="h-4 w-4" />
        </Button>
      </form>
      <p className="mt-6 text-center text-[12px] text-ink-400">
        Need a workspace? <Link to="/register" className="font-medium text-amber-700 hover:text-amber-800">Create one</Link>
      </p>
    </AuthPanel>
  );
}

export function RegisterPage() {
  const [orgName, setOrgName] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const client = useQueryClient();

  const checks = {
    length: password.length >= 12,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    digit: /\d/.test(password),
  };
  const valid = Object.values(checks).every(Boolean) && password === confirm && authorized;

  const mutation = useMutation({
    mutationFn: () => api.post<Me>("/auth/register", { org_name: orgName.trim(), name: name.trim(), email: email.trim(), password }),
    onSuccess: (data) => {
      client.setQueryData(["me"], data);
      navigate("/dashboard", { replace: true });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Account creation failed."),
  });

  return (
    <AuthPanel>
      <div className="mb-7">
        <h1 className="text-[28px] font-semibold tracking-[-0.03em] text-ink-50">Create your workspace</h1>
        <p className="mt-2 text-[13px] text-ink-300">The first account becomes the organization owner.</p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          if (!valid) return;
          mutation.mutate();
        }}
        className="space-y-3.5"
      >
        <Field label="Organization">
          <Input value={orgName} onChange={(event) => setOrgName(event.target.value)} placeholder="Acme Security" required autoFocus />
        </Field>
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field label="Your name">
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Mukuvi Ngandu" autoComplete="name" required />
          </Field>
          <Field label="Email">
            <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" autoComplete="email" required />
          </Field>
        </div>
        <Field label="Password" hint="Minimum 12 characters">
          <div className="relative">
            <Input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" required className="pr-10" />
            <button type="button" onClick={() => setShowPassword((value) => !value)} className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-ink-400 hover:text-ink-100" aria-label="Toggle password visibility">
              {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </Field>
        <div className="grid grid-cols-2 gap-1.5">
          {[
            ["length", "12+ characters"],
            ["upper", "Upper case"],
            ["lower", "Lower case"],
            ["digit", "Number"],
          ].map(([key, label]) => (
            <div key={key} className={`flex items-center gap-1.5 text-[10.5px] ${checks[key as keyof typeof checks] ? "text-lime-700" : "text-ink-400"}`}>
              <span className={`h-1 w-1 rounded-full ${checks[key as keyof typeof checks] ? "bg-lime-400" : "bg-ink-600"}`} /> {label}
            </div>
          ))}
        </div>
        <Field label="Confirm password">
          <Input type={showPassword ? "text" : "password"} value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" required />
        </Field>
        {confirm && confirm !== password ? <p className="text-[11px] text-red-700">Passwords do not match.</p> : null}
        <label className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-ink-600 bg-ink-900/50 p-3">
          <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-0.5 h-3.5 w-3.5 rounded border-ink-500 bg-ink-800 accent-amber-400" />
          <span className="text-[11px] leading-relaxed text-ink-300">
            I will only register and assess systems I own or have explicit, documented permission to test. I understand that intrusive testing can disrupt services.
          </span>
        </label>
        {error ? <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-700">{error}</div> : null}
        <Button type="submit" size="lg" className="w-full" loading={mutation.isPending} disabled={!valid}>
          Create workspace <ArrowRight className="h-4 w-4" />
        </Button>
      </form>
      <p className="mt-5 text-center text-[12px] text-ink-400">
        Already have an account? <Link to="/login" className="font-medium text-amber-700 hover:text-amber-800">Sign in</Link>
      </p>
    </AuthPanel>
  );
}
