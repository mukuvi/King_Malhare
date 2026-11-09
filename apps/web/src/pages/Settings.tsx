import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowRight, Check, KeyRound, Save, ShieldCheck, UserRound } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useMe } from "@/hooks/queries";
import { formatDateTime } from "@/lib/utils";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Field, Input, PageHeader, PageTransition } from "@/components/ui";

export function SettingsPage() {
  const me = useMe();
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);

  useEffect(() => {
    if (me.data?.user.name) setName(me.data.user.name);
  }, [me.data]);

  const profile = useMutation({
    mutationFn: () => api.patch("/me", { name: name.trim() }),
    onSuccess: () => { toast.success("Profile updated"); void client.invalidateQueries({ queryKey: ["me"] }); },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Could not update the profile."),
  });

  const password = useMutation({
    mutationFn: () => api.post("/auth/change-password", { current_password: currentPassword, new_password: newPassword }),
    onSuccess: () => {
      toast.success("Password changed", { description: "Other sessions were signed out." });
      setCurrentPassword("");
      setNewPassword("");
      setConfirm("");
      setPasswordError(null);
    },
    onError: (err) => setPasswordError(err instanceof ApiError ? err.message : "Could not change the password."),
  });

  const checks = {
    length: newPassword.length >= 12,
    upper: /[A-Z]/.test(newPassword),
    lower: /[a-z]/.test(newPassword),
    digit: /\d/.test(newPassword),
  };
  const passwordValid = Object.values(checks).every(Boolean) && newPassword === confirm && currentPassword.length > 0;

  return (
    <PageTransition>
      <PageHeader eyebrow="Account" title="Settings" description="Your profile, password and role within the organization." />

      <div className="mt-6 grid gap-4 xl:grid-cols-[1.25fr_1fr]">
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="Displayed in assignments and audit events">Profile</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-full text-[16px] font-bold text-ink-50" style={{ backgroundColor: me.data?.user.avatar_color ?? "#D98B8B" }}>
                  {me.data?.user.name.slice(0, 1).toUpperCase() ?? "K"}
                </div>
                <div>
                  <p className="text-[13px] font-medium text-ink-100">{me.data?.user.name}</p>
                  <p className="mt-0.5 text-[11px] text-ink-400">{me.data?.user.email}</p>
                  <Badge className="mt-1.5">{me.data?.role}</Badge>
                </div>
              </div>
              <Field label="Full name">
                <Input value={name} onChange={(event) => setName(event.target.value)} maxLength={120} />
              </Field>
              <div className="flex justify-end">
                <Button size="sm" onClick={() => profile.mutate()} loading={profile.isPending} disabled={name.trim().length < 2 || name === me.data?.user.name}><Save className="h-3.5 w-3.5" /> Save profile</Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Argon2id hashing, all other sessions revoked">Change password</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <Field label="Current password"><Input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} autoComplete="current-password" /></Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="New password" hint="Minimum 12 characters"><Input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} autoComplete="new-password" /></Field>
                <Field label="Confirm new password"><Input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" /></Field>
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {[["length", "12+ characters"], ["upper", "Upper case"], ["lower", "Lower case"], ["digit", "Number"]].map(([key, label]) => (
                  <div key={key} className={`flex items-center gap-1.5 text-[10.5px] ${checks[key as keyof typeof checks] ? "text-lime-700" : "text-ink-400"}`}>
                    <Check className="h-3 w-3" /> {label}
                  </div>
                ))}
              </div>
              {confirm && confirm !== newPassword ? <p className="text-[11px] text-red-700">Passwords do not match.</p> : null}
              {passwordError ? <p className="rounded-lg border border-red-500/25 bg-red-500/10 px-3 py-2 text-[11.5px] text-red-700">{passwordError}</p> : null}
              <div className="flex justify-end">
                <Button size="sm" onClick={() => password.mutate()} loading={password.isPending} disabled={!passwordValid}><KeyRound className="h-3.5 w-3.5" /> Update password</Button>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="Session and membership">Account</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-[11.5px]">
              <Row label="Email" value={me.data?.user.email ?? "-"} />
              <Row label="Role" value={me.data?.role ?? "-"} />
              <Row label="Organization" value={me.data?.org.name ?? "-"} />
              <Row label="Last sign-in" value={me.data?.user.last_login_at ? formatDateTime(me.data.user.last_login_at) : "-"} />
              <Row label="Session policy" value="12 hour absolute, HttpOnly, SameSite=Lax" />
              <Link to="/organization" className="mt-2 flex items-center justify-between rounded-lg border border-ink-700 bg-ink-900/40 px-3 py-2.5 text-ink-300 hover:border-ink-500 hover:text-ink-100">
                <span className="flex items-center gap-2"><UserRound className="h-3.5 w-3.5" /> Organization settings</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="Derived from your role">Permissions</CardTitle></CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-1.5">
                {me.data?.permissions.map((permission) => <Badge key={permission} className="font-mono text-[9.5px]">{permission}</Badge>)}
              </div>
              <p className="mt-3 flex items-start gap-2 text-[10.5px] leading-relaxed text-ink-400"><ShieldCheck className="mt-0.5 h-3 w-3 shrink-0" /> Permissions are enforced server-side on every request and re-checked on object access.</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle subtitle="For automation and reports">Developer access</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              <p className="text-[11px] leading-relaxed text-ink-400">Issue scoped API keys and review the REST API contract.</p>
              <div className="flex gap-2">
                <Link to="/integrations?tab=keys" className="flex-1"><Button variant="secondary" size="sm" className="w-full">API keys</Button></Link>
                <Link to="/api-docs" className="flex-1"><Button variant="secondary" size="sm" className="w-full">API docs</Button></Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </PageTransition>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-ink-700/50 pb-2">
      <span className="text-ink-400">{label}</span>
      <span className="max-w-[65%] text-right text-ink-200">{value}</span>
    </div>
  );
}
