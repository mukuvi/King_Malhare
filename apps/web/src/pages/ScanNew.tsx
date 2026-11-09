import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  Cloud,
  Code2,
  Globe2,
  KeyRound,
  LockKeyhole,
  Network,
  Radar,
  ServerCog,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useAssets, useAuthorizations, useCloudConnections, useMe, useProfiles, useScanners } from "@/hooks/queries";
import { categoryLabel, cn, formatDateTime, scannerLabel } from "@/lib/utils";
import type { Asset, Category, ScannerInfo } from "@/types";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, EmptyState, Field, Input, PageHeader, PageTransition, Progress, QueryState, Select, Skeleton, Toggle } from "@/components/ui";
import { AuthorizationModal } from "@/components/domain/assets";

const steps = ["Scope", "Method", "Parameters", "Review"];

const categoryIcons: Record<Category, typeof Globe2> = {
  web: Globe2,
  network: Network,
  cloud: Cloud,
  authentication: KeyRound,
  infrastructure: ServerCog,
};

function scannerFitsAsset(asset: Asset | undefined, scanner: ScannerInfo): boolean {
  if (!asset) return false;
  const web = ["website", "web_app", "api", "graphql_api"].includes(asset.type);
  switch (scanner.category) {
    case "web":
    case "authentication":
      return web;
    case "network":
      return web || ["ip", "network", "server", "internal"].includes(asset.type);
    case "infrastructure":
      return ["container", "server", "internal"].includes(asset.type);
    case "cloud":
      return asset.type === "cloud";
    default:
      return false;
  }
}

function defaultCategory(asset?: Asset): Category {
  if (!asset) return "web";
  if (asset.type === "cloud") return "cloud";
  if (["ip", "network", "server", "internal"].includes(asset.type)) return "network";
  if (asset.type === "container") return "infrastructure";
  return "web";
}

export function ScanNewPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const me = useMe();
  const assets = useAssets({ status: "active", per_page: 100 });
  const scanners = useScanners();
  const profiles = useProfiles();
  const clouds = useCloudConnections();

  const [step, setStep] = useState(0);
  const initialCategory = (searchParams.get("category") as Category | null) ?? "web";
  const [assetId, setAssetId] = useState(searchParams.get("asset") ?? "");
  const [authId, setAuthId] = useState("");
  const [category, setCategory] = useState<Category>(["web", "network", "cloud", "authentication", "infrastructure"].includes(initialCategory) ? initialCategory : "web");
  const [scannerName, setScannerName] = useState("");
  const [profileId, setProfileId] = useState("");
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [cloudId, setCloudId] = useState("");
  const [testUsername, setTestUsername] = useState("");
  const [testPassword, setTestPassword] = useState("");
  const [confirmIntrusive, setConfirmIntrusive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authOpen, setAuthOpen] = useState(false);

  const asset = useMemo(() => assets.data?.items.find((item) => item.id === assetId), [assets.data, assetId]);
  const authorizations = useAuthorizations(assetId || undefined);
  const activeAuths = useMemo(() => (authorizations.data ?? []).filter((auth) => auth.effective_status === "active"), [authorizations.data]);
  const selection = useMemo(() => scanners.data?.items.find((item) => item.name === scannerName), [scanners.data, scannerName]);
  const filteredProfiles = useMemo(() => (profiles.data?.items ?? []).filter((profile) => profile.scanner === scannerName), [profiles.data, scannerName]);
  const availableScanners = useMemo(
    () => (scanners.data?.items ?? []).filter((scanner) => scannerFitsAsset(asset, scanner)),
    [scanners.data, asset],
  );
  const visibleScanners = availableScanners.filter((scanner) => scanner.category === category);

  useEffect(() => {
    if (!assetId) return;
    const preferred = initialCategory !== "web" ? initialCategory : defaultCategory(asset);
    setCategory(preferred);
    setAuthId("");
    setScannerName("");
    setProfileId("");
    setConfig({});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assetId]);

  useEffect(() => {
    if (!assetId) return;
    if (!activeAuths.some((auth) => auth.id === authId)) {
      setAuthId(activeAuths[0]?.id ?? "");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeAuths, assetId]);

  const isIntrusive = Boolean(selection?.intrusive) || (scannerName === "zap" && config.mode === "active") || (scannerName === "burp" && config.mode === "audit");
  const canIntrusive = Boolean(me.data?.permissions.includes("scans:intrusive")) && Boolean(activeAuths.find((auth) => auth.id === authId)?.intrusive_allowed);

  const chooseScanner = (scanner: ScannerInfo) => {
    setScannerName(scanner.name);
    setProfileId("");
    setConfig({ ...scanner.default_params });
    setConfirmIntrusive(false);
    setError(null);
  };

  const chooseProfile = (id: string) => {
    setProfileId(id);
    if (!id) {
      setConfig({ ...(selection?.default_params ?? {}) });
      return;
    }
    const profile = profiles.data?.items.find((item) => item.id === id);
    if (profile) setConfig({ ...profile.config });
  };

  const create = useMutation({
    mutationFn: () =>
      api.post<{ id: string; status: string }>("/scans", {
        asset_id: assetId,
        authorization_id: authId,
        scanner: scannerName,
        category,
        profile_id: profileId || null,
        params: config,
        confirm_intrusive: confirmIntrusive,
        cloud_connection_id: cloudId || undefined,
        test_account_password: scannerName === "auth-baseline" ? testPassword : undefined,
      }),
    onSuccess: (result) => {
      toast.success("Assessment queued", { description: "The worker will claim the job and report real progress." });
      navigate(`/scans/${result.id}`);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "The assessment could not be queued."),
  });

  const selectedAuth = activeAuths.find((auth) => auth.id === authId);
  const canContinue = (() => {
    if (step === 0) return Boolean(assetId && authId);
    if (step === 1) return Boolean(scannerName);
    if (step === 2) {
      if (scannerName === "auth-baseline" && (!testUsername.trim() || !testPassword)) return false;
      if (category === "cloud" && !cloudId) return false;
      return true;
    }
    if (step === 3) {
      if (isIntrusive) return canIntrusive && confirmIntrusive;
      return true;
    }
    return false;
  })();

  return (
    <PageTransition>
      <Link to="/scans" className="mb-4 inline-flex items-center gap-1.5 text-[11.5px] text-ink-400 hover:text-ink-100">
        <ArrowLeft className="h-3.5 w-3.5" /> Scan center
      </Link>
      <PageHeader eyebrow="New assessment" title="Configure an assessment" description="Scope is validated when the job is queued and again inside the worker before execution." />

      <div className="mt-7 sm:hidden">
        <div className="flex items-center justify-between text-[11px] text-ink-400">
          <span>Step {step + 1} of {steps.length}</span>
          <span className="font-medium text-ink-100">{steps[step]}</span>
        </div>
        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-700">
          <div className="h-full rounded-full bg-amber-400 transition-[width]" style={{ width: `${((step + 1) / steps.length) * 100}%` }} />
        </div>
      </div>
      <div className="mt-4 hidden items-center gap-2 overflow-x-auto pb-1 sm:flex">
        {steps.map((label, index) => (
          <div key={label} className="flex shrink-0 items-center gap-2">
            <button
              onClick={() => index < step && setStep(index)}
              className={cn(
                "flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11.5px] transition-colors",
                index === step ? "border-amber-500/40 bg-amber-500/10 text-amber-700" : index < step ? "border-lime-500/25 bg-lime-500/5 text-lime-700" : "border-ink-600 bg-ink-850 text-ink-400",
              )}
            >
              <span className={cn("flex h-4 w-4 items-center justify-center rounded-full text-[9px] font-bold", index === step ? "bg-amber-400 text-ink-50" : index < step ? "bg-lime-400 text-ink-50" : "bg-ink-700 text-ink-300")}>
                {index < step ? <Check className="h-2.5 w-2.5" /> : index + 1}
              </span>
              {label}
            </button>
            {index < steps.length - 1 ? <div className="h-px w-5 bg-ink-700" /> : null}
          </div>
        ))}
      </div>

      <div className="mt-5 grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <div>
          <QueryState loading={assets.isLoading} error={assets.error} onRetry={() => void assets.refetch()} skeleton={<Skeleton className="h-80 w-full rounded-xl" />}>
            {step === 0 ? (
              <Card>
                <CardHeader><CardTitle subtitle="Choose the authorized target for this run">Scope</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  {(assets.data?.items.length ?? 0) === 0 ? (
                    <EmptyState icon={<Radar className="h-4 w-4" />} title="No active assets" description="Register an asset and record authorization before starting an assessment." action={<Link to="/assets"><Button size="sm">Go to assets</Button></Link>} />
                  ) : (
                    <>
                      <Field label="Asset">
                        <Select value={assetId} onChange={(event) => setAssetId(event.target.value)}>
                          <option value="">Select an asset</option>
                          {assets.data?.items.map((item) => <option key={item.id} value={item.id}>{item.name} - {item.target}</option>)}
                        </Select>
                      </Field>
                      {asset ? (
                        <div className="rounded-lg border border-ink-600 bg-ink-900/50 p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="font-mono text-[11.5px] text-ink-100">{asset.target}</p>
                              <p className="mt-1 text-[10.5px] text-ink-400">{asset.type.replace(/_/g, " ")} · {asset.environment} · owner {asset.owner_name ?? "unassigned"}</p>
                            </div>
                            <Badge>{asset.type.replace(/_/g, " ")}</Badge>
                          </div>
                        </div>
                      ) : null}

                      <div>
                        <div className="mb-2 flex items-center justify-between">
                          <span className="text-[12px] font-medium text-ink-200">Authorization</span>
                          {asset ? <button onClick={() => setAuthOpen(true)} className="text-[11px] text-amber-700 hover:text-amber-700">Add authorization</button> : null}
                        </div>
                        {!assetId ? (
                          <p className="rounded-lg border border-ink-700 bg-ink-900/40 px-3 py-2.5 text-[11.5px] text-ink-400">Select an asset to load its authorization records.</p>
                        ) : authorizations.isLoading ? (
                          <Skeleton className="h-16 w-full" />
                        ) : activeAuths.length === 0 ? (
                          <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-3">
                            <p className="flex items-center gap-2 text-[12px] text-amber-700"><AlertTriangle className="h-3.5 w-3.5" /> No active authorization</p>
                            <p className="mt-1 text-[11px] leading-relaxed text-ink-300">This asset cannot be assessed. Record a written approval with a future expiry first.</p>
                            <Button size="sm" className="mt-3" onClick={() => setAuthOpen(true)}>Record authorization</Button>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {activeAuths.map((auth) => (
                              <button
                                key={auth.id}
                                onClick={() => setAuthId(auth.id)}
                                className={cn(
                                  "w-full rounded-lg border px-3 py-2.5 text-left transition-colors",
                                  authId === auth.id ? "border-amber-500/50 bg-amber-500/[0.06]" : "border-ink-600 bg-ink-900/40 hover:border-ink-500",
                                )}
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-mono text-[11.5px] text-ink-100">{auth.reference}</span>
                                  <span className={cn("flex h-4 w-4 items-center justify-center rounded-full border", authId === auth.id ? "border-amber-400 bg-amber-400 text-ink-50" : "border-ink-500")}>
                                    {authId === auth.id ? <Check className="h-2.5 w-2.5" /> : null}
                                  </span>
                                </div>
                                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-ink-400">
                                  <span>expires {formatDateTime(auth.expires_at)}</span>
                                  <span>approved by {auth.approved_by_name}</span>
                                  {auth.intrusive_allowed ? <span className="text-orange-700">intrusive allowed</span> : null}
                                  {auth.allow_private ? <span className="text-amber-700">private allowed</span> : null}
                                </div>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            ) : null}

            {step === 1 ? (
              <Card>
                <CardHeader><CardTitle subtitle="Only scanners compatible with this asset are shown">Assessment method</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex flex-wrap gap-1.5">
                    {(["web", "network", "cloud", "authentication", "infrastructure"] as Category[]).map((item) => {
                      const Icon = categoryIcons[item];
                      return (
                        <button
                          key={item}
                          onClick={() => { setCategory(item); setScannerName(""); setProfileId(""); setConfig({}); }}
                          className={cn("inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] transition-colors", category === item ? "border-amber-500/40 bg-amber-500/10 text-amber-700" : "border-ink-600 bg-ink-900/40 text-ink-400 hover:text-ink-200")}
                        >
                          <Icon className="h-3.5 w-3.5" /> {categoryLabel(item)}
                        </button>
                      );
                    })}
                  </div>
                  {scanners.isError ? (
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-700">Scanner availability could not be loaded.</div>
                  ) : scanners.isLoading ? (
                    <div className="grid gap-2 sm:grid-cols-2">{Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-24 w-full" />)}</div>
                  ) : visibleScanners.length === 0 ? (
                    <p className="rounded-lg border border-ink-700 bg-ink-900/40 px-3 py-4 text-[12px] text-ink-400">No scanner in this category is compatible with the selected asset type.</p>
                  ) : (
                    <div className="grid gap-2 sm:grid-cols-2">
                      {visibleScanners.map((scanner) => (
                        <button
                          key={scanner.name}
                          onClick={() => chooseScanner(scanner)}
                          disabled={scanner.status === "offline"}
                          className={cn(
                            "rounded-lg border p-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50",
                            scannerName === scanner.name ? "border-amber-500/50 bg-amber-500/[0.06]" : "border-ink-600 bg-ink-900/40 hover:border-ink-500",
                          )}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <span className="text-[12px] font-medium text-ink-100">{scanner.label}</span>
                          </div>
                          <p className="mt-1.5 line-clamp-2 text-[10.5px] leading-relaxed text-ink-400">{scanner.description}</p>
                          <div className="mt-2 flex items-center gap-1.5">
                            {scanner.intrusive ? <Badge className="border-orange-500/25 bg-orange-500/10 text-orange-700">intrusive</Badge> : null}
                            <span className="text-[9px] uppercase tracking-wider text-ink-400">{scanner.status}</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}

                  {scannerName ? (
                    <div className="grid gap-3 sm:grid-cols-2">
                      <Field label="Profile" hint="Optional preset">
                        <Select value={profileId} onChange={(event) => chooseProfile(event.target.value)}>
                          <option value="">Scanner defaults</option>
                          {filteredProfiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}{profile.is_system ? " (system)" : ""}</option>)}
                        </Select>
                      </Field>
                      {category === "cloud" ? (
                        <Field label="Cloud connection">
                          <Select value={cloudId} onChange={(event) => setCloudId(event.target.value)}>
                            <option value="">Select connection</option>
                            {clouds.data?.items.map((connection) => <option key={connection.id} value={connection.id}>{connection.name} - {connection.provider.toUpperCase()} {connection.account_id}</option>)}
                          </Select>
                        </Field>
                      ) : null}
                    </div>
                  ) : null}
                  {category === "cloud" && (clouds.data?.items.length ?? 0) === 0 ? (
                    <p className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-700">No cloud connection is configured. Add read-only credentials under Integrations first.</p>
                  ) : null}
                </CardContent>
              </Card>
            ) : null}

            {step === 2 ? (
              <Card>
                <CardHeader>
                  <CardTitle subtitle={selection ? `${selection.label} parameters` : "Scanner parameters"}>Parameters</CardTitle>
                  {profileId ? <Badge>profile preset</Badge> : <Badge>scanner defaults</Badge>}
                </CardHeader>
                <CardContent className="space-y-4">
                  {!selection ? (
                    <p className="text-[12px] text-ink-400">Select a scanner first.</p>
                  ) : (
                    <>
                      <div className="grid gap-4 sm:grid-cols-2">
                        {Object.entries(selection.params).map(([key, schema]) => (
                          <ParamControl key={key} name={key} schema={schema} value={config[key]} onChange={(value) => setConfig((current) => ({ ...current, [key]: value }))} />
                        ))}
                      </div>
                      {scannerName === "auth-baseline" ? (
                        <div className="space-y-3 rounded-lg border border-orange-500/25 bg-orange-500/[0.04] p-3">
                          <div className="flex items-center gap-2 text-[12px] font-medium text-orange-200"><LockKeyhole className="h-3.5 w-3.5" /> Authorized test account</div>
                          <p className="text-[10.5px] leading-relaxed text-ink-400">Use a dedicated test account. The password is sent only in the job payload to the worker, never stored in scan configuration or logs.</p>
                          <div className="grid gap-3 sm:grid-cols-2">
                            <Field label="Test username">
                              <Input value={testUsername} onChange={(event) => setTestUsername(event.target.value)} placeholder="security-test@example.com" autoComplete="off" />
                            </Field>
                            <Field label="Test password">
                              <Input type="password" value={testPassword} onChange={(event) => setTestPassword(event.target.value)} placeholder="••••••••" autoComplete="new-password" />
                            </Field>
                          </div>
                        </div>
                      ) : null}
                      <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3">
                        <div className="mb-2 flex items-center justify-between">
                          <span className="text-[10px] font-semibold uppercase tracking-[0.13em] text-ink-400">Effective configuration</span>
                          <span className="text-[9.5px] text-ink-400">server validates this</span>
                        </div>
                        <pre className="max-h-48 overflow-auto font-mono text-[10.5px] leading-relaxed text-ink-300">{JSON.stringify(config, null, 2)}</pre>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            ) : null}

            {step === 3 ? (
              <Card>
                <CardHeader><CardTitle subtitle="Confirm exactly what will be executed">Review and queue</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <ReviewItem label="Asset" value={asset?.name ?? "-"} sub={asset?.target} />
                    <ReviewItem label="Method" value={scannerLabel(scannerName)} sub={categoryLabel(category)} />
                    <ReviewItem label="Authorization" value={selectedAuth?.reference ?? "-"} sub={selectedAuth ? `expires ${formatDateTime(selectedAuth.expires_at)}` : undefined} />
                    <ReviewItem label="Approved by" value={selectedAuth?.approved_by_name ?? "-"} sub={selectedAuth?.intrusive_allowed ? "Intrusive testing permitted" : "Non-intrusive only"} />
                  </div>
                  {selectedAuth?.allow_private ? (
                    <div className="flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2.5 text-[11px] leading-relaxed text-amber-700">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      This authorization permits private and internal targets. Confirm the worker runs inside an isolated assessment environment before scanning internal infrastructure.
                    </div>
                  ) : null}
                  {isIntrusive ? (
                    <div className="rounded-lg border border-orange-500/30 bg-orange-500/[0.05] p-3">
                      <div className="flex items-center gap-2 text-[12px] font-medium text-orange-200"><AlertTriangle className="h-3.5 w-3.5" /> Intrusive assessment</div>
                      <p className="mt-1.5 text-[11px] leading-relaxed text-ink-300">
                        {scannerLabel(scannerName)} sends attack traffic that can modify data, trigger lockouts or disrupt the service. Run it only in an approved window.
                      </p>
                      {!canIntrusive ? (
                        <p className="mt-2 rounded border border-red-500/25 bg-red-500/10 px-2 py-1.5 text-[10.5px] text-red-700">
                          This requires the scans:intrusive permission and an authorization that permits intrusive testing.
                        </p>
                      ) : (
                        <label className="mt-2.5 flex cursor-pointer items-start gap-2 text-[11px] text-ink-200">
                          <input type="checkbox" checked={confirmIntrusive} onChange={(event) => setConfirmIntrusive(event.target.checked)} className="mt-0.5 h-3.5 w-3.5 accent-orange-500" />
                          I approve this intrusive run against the authorized scope and accept responsibility for its impact.
                        </label>
                      )}
                    </div>
                  ) : null}
                  <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-3">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-ink-400">Scope snapshot</p>
                    <div className="mt-2 grid gap-1.5 font-mono text-[10.5px] text-ink-300">
                      <span>target: {asset?.target ?? "-"}</span>
                      <span>scanner: {scannerName || "-"}</span>
                      <span>profile: {profiles.data?.items.find((item) => item.id === profileId)?.name ?? "scanner defaults"}</span>
                      <span>intrusive: {String(isIntrusive)}</span>
                      <span>allow_private: {String(selectedAuth?.allow_private ?? false)}</span>
                    </div>
                  </div>
                  {error ? <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-700">{error}</div> : null}
                </CardContent>
              </Card>
            ) : null}

            <div className="mt-4 flex items-center justify-between">
              <Button variant="ghost" onClick={() => (step === 0 ? navigate("/scans") : setStep(step - 1))}>
                <ArrowLeft className="h-3.5 w-3.5" /> {step === 0 ? "Cancel" : "Back"}
              </Button>
              {step < 3 ? (
                <Button onClick={() => setStep(step + 1)} disabled={!canContinue}>
                  Continue <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              ) : (
                <Button onClick={() => { setError(null); create.mutate(); }} loading={create.isPending} disabled={!canContinue}>
                  <Radar className="h-3.5 w-3.5" /> Queue assessment
                </Button>
              )}
            </div>
          </QueryState>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle subtitle="What the platform will record">Assessment summary</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <SummaryRow icon={<Radar className="h-3.5 w-3.5" />} label="Asset" value={asset?.name ?? "Not selected"} />
              <SummaryRow icon={<ShieldCheck className="h-3.5 w-3.5" />} label="Authorization" value={selectedAuth?.reference ?? "Not selected"} />
              <SummaryRow icon={<Terminal className="h-3.5 w-3.5" />} label="Scanner" value={scannerName ? scannerLabel(scannerName) : "Not selected"} />
              <SummaryRow icon={<Sparkles className="h-3.5 w-3.5" />} label="Category" value={categoryLabel(category)} />
              {isIntrusive ? (
                <div className="flex items-start gap-2 rounded-lg border border-orange-500/25 bg-orange-500/5 px-2.5 py-2 text-[10.5px] text-orange-200">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" /> Intrusive testing requires explicit consent.
                </div>
              ) : null}
              <div className="pt-1">
                <div className="mb-1.5 flex items-center justify-between text-[10px] text-ink-400"><span>Configuration progress</span><span>{Math.round(((step + 1) / 4) * 100)}%</span></div>
                <Progress value={((step + 1) / 4) * 100} />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-ink-900/40">
            <CardContent className="space-y-2.5 py-4 text-[10.5px] leading-relaxed text-ink-400">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-ink-300"><Code2 className="h-3 w-3" /> Execution notes</div>
              <p>Jobs are queued in Redis and claimed by an isolated worker. Progress is streamed from the worker, not simulated.</p>
              <p>The worker revalidates the authorization expiry, intrusive approval and target resolution before it starts a scanner.</p>
              <p>Findings are normalized, fingerprinted and deduplicated against the existing register.</p>
              <div className="pt-1 text-[10px] text-ink-400">
                <Link to="/integrations" className="text-amber-700 hover:text-amber-700">Check scanner availability</Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {asset ? <AuthorizationModal open={authOpen} onClose={() => setAuthOpen(false)} asset={asset} /> : null}
    </PageTransition>
  );
}

function SummaryRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-start gap-2.5">
      <span className="mt-0.5 text-ink-400">{icon}</span>
      <div className="min-w-0 flex-1">
        <p className="text-[9.5px] uppercase tracking-[0.12em] text-ink-400">{label}</p>
        <p className="mt-0.5 truncate text-[11.5px] text-ink-200">{value}</p>
      </div>
    </div>
  );
}

function ReviewItem({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900/40 px-3 py-2.5">
      <p className="text-[9.5px] uppercase tracking-[0.12em] text-ink-400">{label}</p>
      <p className="mt-1 truncate text-[12px] font-medium text-ink-100">{value}</p>
      {sub ? <p className="mt-0.5 truncate text-[10px] text-ink-400">{sub}</p> : null}
    </div>
  );
}

function ParamControl({
  name,
  schema,
  value,
  onChange,
}: {
  name: string;
  schema: { type: string; description: string; enum?: string[]; min?: number; max?: number };
  value: unknown;
  onChange: (value: unknown) => void;
}) {
  const label = name.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
  if (schema.type === "bool") {
    return (
      <Toggle checked={Boolean(value)} onChange={onChange} label={label} description={schema.description} />
    );
  }
  if (schema.type === "int") {
    return (
      <Field label={label} hint={schema.description}>
        <Input type="number" min={schema.min} max={schema.max} value={Number(value ?? schema.min ?? 0)} onChange={(event) => onChange(Number(event.target.value))} />
      </Field>
    );
  }
  if (schema.type === "enum") {
    return (
      <Field label={label} hint={schema.description}>
        <Select value={String(value ?? "")} onChange={(event) => onChange(event.target.value)}>
          {schema.enum?.map((option) => <option key={option} value={option}>{option}</option>)}
        </Select>
      </Field>
    );
  }
  if (schema.type === "string_list") {
    const list = Array.isArray(value) ? (value as string[]) : [];
    return (
      <div className="sm:col-span-2">
        <p className="mb-1.5 text-[12px] font-medium text-ink-200">{label}</p>
        <div className="flex flex-wrap gap-1.5">
          {(schema.enum ?? []).map((option) => {
            const active = list.includes(option);
            return (
              <button
                key={option}
                type="button"
                onClick={() => onChange(active ? list.filter((item) => item !== option) : [...list, option])}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[10.5px] transition-colors",
                  active ? "border-amber-500/40 bg-amber-500/10 text-amber-700" : "border-ink-600 bg-ink-900 text-ink-400 hover:text-ink-200",
                )}
              >
                {option}
              </button>
            );
          })}
        </div>
        <p className="mt-1 text-[10px] text-ink-400">{schema.description}</p>
      </div>
    );
  }
  return (
    <Field label={label} hint={schema.description}>
      <Input value={String(value ?? "")} onChange={(event) => onChange(event.target.value)} />
    </Field>
  );
}
