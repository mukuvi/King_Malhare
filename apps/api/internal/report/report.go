package report

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	fpdf "github.com/jung-kurt/gofpdf"
)

type EvidenceFile struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	DataURI     string `json:"-"`
}

type Finding struct {
	ID              string         `json:"id"`
	Fingerprint     string         `json:"fingerprint"`
	Title           string         `json:"title"`
	Severity        string         `json:"severity"`
	Confidence      string         `json:"confidence"`
	CVE             string         `json:"cve"`
	CWE             string         `json:"cwe"`
	CVSS            *float64       `json:"cvss"`
	Endpoint        string         `json:"endpoint"`
	Description     string         `json:"description"`
	Reproduction    string         `json:"reproduction"`
	BusinessImpact  string         `json:"business_impact"`
	TechnicalImpact string         `json:"technical_impact"`
	Remediation     string         `json:"remediation"`
	References      []string       `json:"references"`
	Evidence        any            `json:"evidence"`
	Status          string         `json:"status"`
	FirstSeen       string         `json:"first_seen"`
	LastSeen        string         `json:"last_seen"`
	EvidenceFiles   []EvidenceFile `json:"evidence_files"`
}

type ScopeItem struct {
	Name        string `json:"name"`
	Target      string `json:"target"`
	Type        string `json:"type"`
	Environment string `json:"environment"`
	AuthRef     string `json:"auth_ref"`
	Approver    string `json:"approver"`
	Expires     string `json:"expires"`
}

type ScanInfo struct {
	ID          string `json:"id"`
	Scanner     string `json:"scanner"`
	Category    string `json:"category"`
	Target      string `json:"target"`
	AssetName   string `json:"asset_name"`
	Status      string `json:"status"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	AuthRef     string `json:"auth_ref"`
	Approver    string `json:"approver"`
	AuthExpires string `json:"auth_expires"`
}

type TimelineItem struct {
	At     string `json:"at"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

type Execution struct {
	Scanner  string `json:"scanner"`
	Status   string `json:"status"`
	Command  string `json:"command"`
	Started  string `json:"started"`
	Finished string `json:"finished"`
	Output   string `json:"output"`
}

type Data struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	ClientName     string         `json:"client_name"`
	AssessorName   string         `json:"assessor_name"`
	OrgName        string         `json:"org_name"`
	GeneratedAt    string         `json:"generated_at"`
	PeriodStart    string         `json:"period_start"`
	PeriodEnd      string         `json:"period_end"`
	Scope          []ScopeItem    `json:"scope"`
	Scan           *ScanInfo      `json:"scan,omitempty"`
	Findings       []Finding      `json:"findings"`
	SeverityCounts map[string]int `json:"severity_counts"`
	Tools          []string       `json:"tools"`
	Timeline       []TimelineItem `json:"timeline"`
	Executions     []Execution    `json:"executions"`
	PostureScore   int            `json:"posture_score"`
	Methodology    []string       `json:"methodology"`
	ReportHash     string         `json:"report_hash,omitempty"`
	GeneratedBy    string         `json:"generated_by"`
}

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func (d *Data) Finalize() {
	sort.SliceStable(d.Findings, func(i, j int) bool {
		ai, aj := severityOrder[d.Findings[i].Severity], severityOrder[d.Findings[j].Severity]
		if ai != aj {
			return ai < aj
		}
		return d.Findings[i].Title < d.Findings[j].Title
	})
	if d.SeverityCounts == nil {
		d.SeverityCounts = map[string]int{}
	}
	d.SeverityCounts = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range d.Findings {
		d.SeverityCounts[f.Severity]++
	}
	if d.GeneratedAt == "" {
		d.GeneratedAt = time.Now().UTC().Format("2 January 2006, 15:04 UTC")
	}
	if d.Methodology == nil {
		d.Methodology = defaultMethodology()
	}
}

func defaultMethodology() []string {
	return []string{
		"Scope validation: every target was matched against a recorded authorization, validity window and intrusive-testing approval before execution.",
		"Discovery and enumeration: non-intrusive fingerprinting established the reachable attack surface, technologies and exposed services.",
		"Vulnerability detection: automated scanners and targeted verification requests identified weaknesses. Findings are deduplicated by a stable fingerprint.",
		"Validation: only conditions proven by a concrete response or configuration state were reported. Tool output was normalized to a common schema.",
		"Risk rating: severity follows CVSS where available and contextual exposure otherwise. Business impact considers the affected asset environment.",
		"Reporting: findings were reviewed, linked to evidence and mapped to remediation guidance. No finding was inferred without scanner evidence.",
	}
}

func (d *Data) TotalFindings() int { return len(d.Findings) }

func (d *Data) RiskStatement() string {
	c, h := d.SeverityCounts["critical"], d.SeverityCounts["high"]
	switch {
	case c > 0:
		return fmt.Sprintf("The assessment identified %d critical and %d high severity findings. Critical findings represent conditions that can typically be exploited without significant preconditions and should be remediated before the affected system is exposed further.", c, h)
	case h > 0:
		return fmt.Sprintf("The assessment identified %d high severity findings and no critical findings. These issues require prioritised remediation, particularly where the affected asset handles authentication or sensitive data.", h)
	case d.TotalFindings() > 0:
		return "No critical or high severity findings were identified. The remaining findings represent hygiene and defence-in-depth improvements rather than directly exploitable weaknesses."
	default:
		return "No findings were recorded for the assessed scope. This reflects the coverage of the selected scanner profile and does not prove the absence of vulnerabilities."
	}
}

func (d *Data) Conclusion() string {
	if d.TotalFindings() == 0 {
		return "The assessment completed without producing findings for the authorized scope. The tested surface should be re-assessed as the application changes, and the limitations of the selected scanner profile should be considered when interpreting this result."
	}
	if d.SeverityCounts["critical"] > 0 || d.SeverityCounts["high"] > 0 {
		return "The assessed surface contains issues that require remediation before it can be considered resilient against a motivated attacker. Priority should be given to the critical and high findings, followed by verification through a retest. Medium and low findings should be scheduled into normal engineering work."
	}
	return "The assessed surface does not currently expose critical or high severity weaknesses within the tested scope. The findings in this report should be addressed as part of routine security hygiene, and a retest is recommended after remediation."
}

func (d *Data) FindingNumber(i int) string { return fmt.Sprintf("KM-%03d", i+1) }

func (d *Data) SeverityClass(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	}
	return "info"
}

func (d *Data) FindingCountBySeverity(s string) int { return d.SeverityCounts[s] }

func BuildHTML(d *Data) ([]byte, error) {
	d.Finalize()
	funcs := template.FuncMap{
		"severityClass": func(s string) string { return d.SeverityClass(s) },
		"title":         strings.Title,
		"join":          strings.Join,
		"hasPrefix":     strings.HasPrefix,
		"add":           func(a, b int) int { return a + b },
	}
	tmpl, err := template.New("report").Funcs(funcs).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — King Malhare</title>
<style>
  :root { --ink:#17150f; --muted:#6b665c; --line:#ded8cc; --paper:#faf7f0; --accent:#b45309; --critical:#b91c1c; --high:#c2410c; --medium:#a16207; --low:#3f6212; --info:#475569; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--paper); color:var(--ink); font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size:10.5pt; line-height:1.55; }
  .page { max-width: 820px; margin: 0 auto; padding: 56px 64px; }
  .cover { min-height: 100vh; background:#12110e; color:#f7f2e8; display:flex; flex-direction:column; justify-content:space-between; padding:64px; }
  .brand { font-weight:700; letter-spacing:.22em; font-size:11pt; text-transform:uppercase; }
  .brand span { color:#f5a524; }
  .cover h1 { font-size:42pt; line-height:1.02; margin:0 0 20px; letter-spacing:-.03em; font-family: Georgia, "Times New Roman", serif; font-weight:400; }
  .cover .sub { color:#b8b0a0; font-size:13pt; max-width:520px; }
  .cover .meta { display:flex; gap:48px; border-top:1px solid #3a3529; padding-top:24px; font-size:9pt; color:#b8b0a0; }
  .cover .meta strong { display:block; color:#f7f2e8; font-size:11pt; margin-top:4px; text-transform:none; letter-spacing:0; }
  .confidential { display:inline-block; border:1px solid #6b5b35; color:#f5a524; padding:4px 10px; font-size:8pt; letter-spacing:.16em; text-transform:uppercase; border-radius:2px; }
  h2 { font-family: Georgia, serif; font-weight:400; font-size:22pt; margin:0 0 8px; letter-spacing:-.02em; }
  h3 { font-size:12pt; margin:24px 0 6px; }
  .kicker { color:var(--accent); text-transform:uppercase; letter-spacing:.16em; font-size:8pt; font-weight:700; margin-bottom:8px; }
  section { page-break-before: always; }
  .rule { height:2px; background:var(--ink); width:64px; margin:16px 0 24px; }
  .lede { font-size:12pt; color:#3a352c; max-width:640px; }
  p { margin: 0 0 10px; }
  table { width:100%; border-collapse:collapse; margin:14px 0 22px; font-size:9pt; }
  th { text-align:left; text-transform:uppercase; letter-spacing:.08em; font-size:7.5pt; color:var(--muted); border-bottom:1.5px solid var(--ink); padding:8px 8px; }
  td { border-bottom:1px solid var(--line); padding:9px 8px; vertical-align:top; }
  tr { page-break-inside: avoid; }
  .sev { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff; font-size:7.5pt; font-weight:700; letter-spacing:.05em; text-transform:uppercase; }
  .sev.critical { background:var(--critical); } .sev.high { background:var(--high); } .sev.medium { background:var(--medium); }
  .sev.low { background:var(--low); } .sev.info { background:var(--info); }
  .cards { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:20px 0 24px; }
  .card { border:1px solid var(--line); background:#fffdf8; padding:12px; }
  .card .n { font-size:22pt; font-family:Georgia,serif; line-height:1; }
  .card .l { font-size:7.5pt; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); margin-top:6px; }
  .finding { border-top:2px solid var(--ink); padding-top:18px; margin-top:34px; page-break-inside: avoid; }
  .finding-head { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; }
  .finding h3 { font-size:15pt; margin:0 0 4px; }
  .attrs { display:grid; grid-template-columns:repeat(2,1fr); gap:8px 18px; margin:14px 0; font-size:8.5pt; }
  .attrs div { border-bottom:1px solid var(--line); padding-bottom:5px; }
  .attrs span { display:block; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-size:7pt; }
  .box { background:#fffdf8; border-left:3px solid var(--accent); padding:10px 14px; margin:12px 0; }
  .screens { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:10px; }
  .screens img { width:100%; border:1px solid var(--line); }
  pre { background:#17150f; color:#eae4d8; padding:14px; overflow:auto; font-size:8pt; white-space:pre-wrap; word-break:break-word; }
  .scope-note { font-size:9pt; color:var(--muted); }
  .footer { margin-top:48px; border-top:1px solid var(--line); padding-top:14px; font-size:8pt; color:var(--muted); display:flex; justify-content:space-between; }
  ul { margin:6px 0 12px; padding-left:20px; } li { margin-bottom:4px; }
  .toc td { border:none; padding:5px 0; }
  .toc .num { color:var(--muted); width:28px; }
  @media print { body { background:#fff; } .page { padding:24px 8px; } .cover { min-height: 257mm; } a { color:inherit; text-decoration:none; } }
</style>
</head>
<body>

<div class="cover">
  <div>
    <div class="brand">KING <span>MALHARE</span></div>
    <p style="color:#8d8575;font-size:9pt;margin-top:8px;">Offensive Security &amp; Vulnerability Assessment</p>
  </div>
  <div>
    <span class="confidential">Confidential</span>
    <h1>{{.Title}}</h1>
    <p class="sub">Security assessment report prepared for {{if .ClientName}}{{.ClientName}}{{else}}{{.OrgName}}{{end}}. Findings, evidence and remediation guidance are based on authorized testing performed during the reported period.</p>
  </div>
  <div class="meta">
    <div>Prepared for<strong>{{if .ClientName}}{{.ClientName}}{{else}}{{.OrgName}}{{end}}</strong></div>
    <div>Assessor<strong>{{if .AssessorName}}{{.AssessorName}}{{else}}Security Engineering{{end}}</strong></div>
    <div>Generated<strong>{{.GeneratedAt}}</strong></div>
    <div>Report ID<strong>{{.ID}}</strong></div>
  </div>
</div>

<div class="page">
<section style="page-break-before:auto;">
  <div class="kicker">Contents</div>
  <h2>Report structure</h2>
  <div class="rule"></div>
  <table class="toc">
    <tr><td class="num">01</td><td>Executive summary</td></tr>
    <tr><td class="num">02</td><td>Assessment objectives</td></tr>
    <tr><td class="num">03</td><td>Scope and authorized targets</td></tr>
    <tr><td class="num">04</td><td>Methodology</td></tr>
    <tr><td class="num">05</td><td>Tools used</td></tr>
    <tr><td class="num">06</td><td>Assessment timeline</td></tr>
    <tr><td class="num">07</td><td>Vulnerability summary</td></tr>
    <tr><td class="num">08</td><td>Detailed technical findings</td></tr>
    <tr><td class="num">09</td><td>Evidence and screenshots</td></tr>
    <tr><td class="num">10</td><td>Risk analysis</td></tr>
    <tr><td class="num">11</td><td>Remediation recommendations</td></tr>
    <tr><td class="num">12</td><td>Conclusion</td></tr>
    <tr><td class="num">13</td><td>Appendix</td></tr>
  </table>
  <div class="footer"><span>King Malhare — {{.Title}}</span><span>Page 2</span></div>
</section>

<section>
  <div class="kicker">01 — Executive summary</div>
  <h2>What the assessment found</h2>
  <div class="rule"></div>
  <p class="lede">{{.RiskStatement}}</p>
  <div class="cards">
    <div class="card"><div class="n">{{.FindingCountBySeverity "critical"}}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n">{{.FindingCountBySeverity "high"}}</div><div class="l">High</div></div>
    <div class="card"><div class="n">{{.FindingCountBySeverity "medium"}}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n">{{.FindingCountBySeverity "low"}}</div><div class="l">Low</div></div>
    <div class="card"><div class="n">{{.FindingCountBySeverity "info"}}</div><div class="l">Info</div></div>
  </div>
  <p><strong>Security posture score:</strong> {{.PostureScore}}/100. This score weights open findings against the number of assessed assets and is intended for trend comparison, not as a certification of security.</p>
  <p><strong>Assessment scope:</strong> {{len .Scope}} authorized target{{if ne (len .Scope) 1}}s{{end}}{{if .Scan}} assessed with the {{.Scan.Scanner}} profile ({{.Scan.Category}}){{end}}. Testing was performed only within the recorded authorization window and target list.</p>
  {{if .Scan}}<p><strong>Primary target:</strong> {{.Scan.AssetName}} — {{.Scan.Target}}<br><strong>Authorization:</strong> {{.Scan.AuthRef}} (approved by {{.Scan.Approver}}, expires {{.Scan.AuthExpires}})</p>{{end}}
  <p>The technical sections contain reproduction steps and evidence for every finding. Findings marked <em>info</em> are observations rather than vulnerabilities. Items that could not be verified were excluded.</p>
</section>

<section>
  <div class="kicker">02 — Objectives</div>
  <h2>Assessment objectives</h2>
  <div class="rule"></div>
  <p>The engagement was designed to answer four questions within the authorized scope:</p>
  <ul>
    <li>Which services and endpoints are reachable by an external or internal attacker, and what software versions are exposed?</li>
    <li>Which configuration weaknesses, missing defensive controls or known vulnerabilities are present?</li>
    <li>Can identified conditions be verified with concrete evidence, and what is their realistic business impact?</li>
    <li>What remediation actions reduce risk most effectively, and how should they be verified?</li>
  </ul>
  <p>The testing was time-boxed and scoped. It was not a full adversary simulation, social engineering exercise, or review of source code unless explicitly listed in scope.</p>
</section>

<section>
  <div class="kicker">03 — Scope</div>
  <h2>Scope and authorized targets</h2>
  <div class="rule"></div>
  <table>
    <thead><tr><th>Asset</th><th>Target</th><th>Type</th><th>Environment</th><th>Authorization</th><th>Expires</th></tr></thead>
    <tbody>
    {{range .Scope}}
      <tr><td>{{.Name}}</td><td>{{.Target}}</td><td>{{.Type}}</td><td>{{.Environment}}</td><td>{{.AuthRef}}<br><span class="scope-note">Approved by {{.Approver}}</span></td><td>{{.Expires}}</td></tr>
    {{end}}
    </tbody>
  </table>
  <p class="scope-note">Only the targets above were assessed. Targets discovered during scanning that fall outside the recorded scope were not tested. Private or internal ranges were reachable only when the authorization explicitly permitted them.</p>
</section>

<section>
  <div class="kicker">04 — Methodology</div>
  <h2>Methodology</h2>
  <div class="rule"></div>
  <ul>{{range .Methodology}}<li>{{.}}</li>{{end}}</ul>
</section>

<section>
  <div class="kicker">05 — Tools</div>
  <h2>Tools used</h2>
  <div class="rule"></div>
  <p>Only tools that produced the findings in this report are listed. Scanner availability and versions are recorded by the platform at execution time.</p>
  <table>
    <thead><tr><th>Tool</th><th>Purpose</th><th>Execution</th></tr></thead>
    <tbody>
    {{range .Executions}}
      <tr><td>{{.Scanner}}</td><td>{{.Command}}</td><td>{{.Status}}{{if .Finished}} — finished {{.Finished}}{{end}}</td></tr>
    {{else}}
      {{range .Tools}}<tr><td>{{.}}</td><td>Evidence collection and vulnerability detection</td><td>Completed</td></tr>{{end}}
    {{end}}
    </tbody>
  </table>
</section>

<section>
  <div class="kicker">06 — Timeline</div>
  <h2>Assessment timeline</h2>
  <div class="rule"></div>
  <table>
    <thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead>
    <tbody>
    {{range .Timeline}}<tr><td>{{.At}}</td><td>{{.Label}}</td><td>{{.Detail}}</td></tr>{{else}}<tr><td colspan="3">No execution timeline was recorded.</td></tr>{{end}}
    </tbody>
  </table>
</section>

<section>
  <div class="kicker">07 — Vulnerability summary</div>
  <h2>Vulnerability summary</h2>
  <div class="rule"></div>
  {{if .Findings}}
  <table>
    <thead><tr><th>Ref</th><th>Finding</th><th>Severity</th><th>Asset</th><th>Endpoint</th><th>Status</th></tr></thead>
    <tbody>
    {{range $i, $f := .Findings}}
      <tr><td>KM-{{printf "%03d" (add $i 1)}}</td><td>{{$f.Title}}</td><td><span class="sev {{severityClass $f.Severity}}">{{$f.Severity}}</span></td><td>{{if $.Scan}}{{$.Scan.AssetName}}{{end}}</td><td>{{$f.Endpoint}}</td><td>{{$f.Status}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<p>No findings were recorded for this assessment. The selected profile completed with no confirmed weaknesses.</p>{{end}}
</section>

<section>
  <div class="kicker">08 — Detailed findings</div>
  <h2>Detailed technical findings</h2>
  <div class="rule"></div>
  {{range $i, $f := .Findings}}
  <div class="finding">
    <div class="finding-head">
      <div><div class="kicker">KM-{{printf "%03d" (add $i 1)}} · {{$f.Confidence}} confidence</div><h3>{{$f.Title}}</h3></div>
      <span class="sev {{severityClass $f.Severity}}">{{$f.Severity}}</span>
    </div>
    <div class="attrs">
      <div><span>Affected asset</span>{{if $.Scan}}{{$.Scan.AssetName}}{{end}}</div>
      <div><span>Endpoint</span>{{$f.Endpoint}}</div>
      <div><span>CVSS</span>{{if $f.CVSS}}{{$f.CVSS}}{{else}}Not scored{{end}}</div>
      <div><span>CVE / CWE</span>{{if $f.CVE}}{{$f.CVE}}{{else}}—{{end}} / {{if $f.CWE}}{{$f.CWE}}{{else}}—{{end}}</div>
      <div><span>First seen</span>{{$f.FirstSeen}}</div>
      <div><span>Status</span>{{$f.Status}}</div>
    </div>
    <h3>Description</h3><p>{{$f.Description}}</p>
    {{if $f.TechnicalImpact}}<h3>Technical impact</h3><p>{{$f.TechnicalImpact}}</p>{{end}}
    {{if $f.BusinessImpact}}<h3>Business impact</h3><p>{{$f.BusinessImpact}}</p>{{end}}
    {{if $f.Reproduction}}<h3>Reproduction</h3><p>{{$f.Reproduction}}</p>{{end}}
    {{if $f.Evidence}}<h3>Evidence</h3><pre>{{$f.Evidence}}</pre>{{end}}
    <h3>Remediation</h3><p>{{if $f.Remediation}}{{$f.Remediation}}{{else}}Apply the vendor fix or configuration change described in the linked references and retest.{{end}}</p>
    {{if $f.References}}<h3>References</h3><ul>{{range $f.References}}<li>{{.}}</li>{{end}}</ul>{{end}}
    {{if $f.EvidenceFiles}}<h3>Attached evidence</h3><ul>{{range $f.EvidenceFiles}}<li>{{.Filename}} ({{.SizeBytes}} bytes, SHA-256 {{.SHA256}})</li>{{end}}</ul>{{end}}
  </div>
  {{else}}<p>No detailed findings are available.</p>{{end}}
</section>

<section>
  <div class="kicker">09 — Evidence and screenshots</div>
  <h2>Evidence and screenshots</h2>
  <div class="rule"></div>
  <p>Evidence captured during testing is listed below. Attachments are retained in the King Malhare evidence store with SHA-256 integrity hashes and access controlled to this organization.</p>
  {{range $i, $f := .Findings}}{{if $f.EvidenceFiles}}
    <h3>KM-{{printf "%03d" (add $i 1)}} — {{$f.Title}}</h3>
    <div class="screens">
    {{range $f.EvidenceFiles}}{{if .DataURI}}<figure style="margin:0"><img src="{{.DataURI}}" alt="{{.Filename}}"><figcaption class="scope-note">{{.Filename}}</figcaption></figure>{{end}}{{end}}
    </div>
    <ul>{{range $f.EvidenceFiles}}<li>{{.Filename}} — {{.ContentType}}, {{.SizeBytes}} bytes, SHA-256 {{.SHA256}}</li>{{end}}</ul>
  {{end}}{{end}}
  <p class="scope-note">Evidence JSON excerpts are embedded in each detailed finding. Binary attachments remain available from the finding record.</p>
</section>

<section>
  <div class="kicker">10 — Risk analysis</div>
  <h2>Risk analysis</h2>
  <div class="rule"></div>
  <p>{{.RiskStatement}}</p>
  <table>
    <thead><tr><th>Severity</th><th>Count</th><th>Interpretation</th></tr></thead>
    <tbody>
      <tr><td><span class="sev critical">Critical</span></td><td>{{.FindingCountBySeverity "critical"}}</td><td>Exploitable with severe impact; remediate immediately and consider interim exposure reduction.</td></tr>
      <tr><td><span class="sev high">High</span></td><td>{{.FindingCountBySeverity "high"}}</td><td>Significant weakness requiring priority remediation and verification.</td></tr>
      <tr><td><span class="sev medium">Medium</span></td><td>{{.FindingCountBySeverity "medium"}}</td><td>Requires context to exploit; schedule within normal engineering cycles.</td></tr>
      <tr><td><span class="sev low">Low</span></td><td>{{.FindingCountBySeverity "low"}}</td><td>Defence-in-depth or hygiene issue with limited direct impact.</td></tr>
      <tr><td><span class="sev info">Info</span></td><td>{{.FindingCountBySeverity "info"}}</td><td>Observation only; no confirmed vulnerability.</td></tr>
    </tbody>
  </table>
  <p><strong>Posture score:</strong> {{.PostureScore}}/100. Weighted by severity and open finding count. A score is not a substitute for reviewing individual findings.</p>
</section>

<section>
  <div class="kicker">11 — Remediation recommendations</div>
  <h2>Remediation recommendations</h2>
  <div class="rule"></div>
  <h3>Immediate (0–7 days)</h3>
  <p>Remediate all critical findings and any high finding exposed to the public internet. Where a fix is not immediately available, apply compensating controls such as restricting access, disabling the affected feature, or adding a virtual patch at the edge.</p>
  <h3>Short term (7–30 days)</h3>
  <p>Address high and medium findings, prioritising authentication, access control and injection classes. Re-run the assessment after changes and compare results against this baseline.</p>
  <h3>Planned (30–90 days)</h3>
  <p>Resolve low and informational findings, remove unnecessary services, tighten TLS and header configuration, and add regression checks to CI where the issue class can be tested automatically.</p>
  <h3>Verification</h3>
  <p>Every fixed finding should be retested. A finding is closed only when the same test no longer reproduces the condition and the retest is recorded in the platform.</p>
</section>

<section>
  <div class="kicker">12 — Conclusion</div>
  <h2>Conclusion</h2>
  <div class="rule"></div>
  <p>{{.Conclusion}}</p>
  <p>This report reflects the state of the authorized targets at the time of testing. Systems change; a clean result does not guarantee future security. Continuous assessment and timely remediation are required to maintain the posture described here.</p>
</section>

<section>
  <div class="kicker">13 — Appendix</div>
  <h2>Appendix</h2>
  <div class="rule"></div>
  <h3>Authorization and scope</h3>
  <p>Testing was restricted to the assets listed in Section 03 and the authorization window recorded at scan creation. The platform enforces target scope in both the API and scanner worker.</p>
  {{if .Scan}}<p><strong>Scan ID:</strong> {{.Scan.ID}}<br><strong>Authorization reference:</strong> {{.Scan.AuthRef}}<br><strong>Approved by:</strong> {{.Scan.Approver}}<br><strong>Authorization expiry:</strong> {{.Scan.AuthExpires}}</p>{{end}}
  <h3>Finding references</h3>
  <table><thead><tr><th>Reference</th><th>Fingerprint</th></tr></thead><tbody>
  {{range $i, $f := .Findings}}<tr><td>KM-{{printf "%03d" (add $i 1)}}</td><td style="font-family:monospace;font-size:7.5pt">{{$f.Fingerprint}}</td></tr>{{end}}
  </tbody></table>
  <h3>Report integrity</h3>
  <p>Report ID {{.ID}}. Generated {{.GeneratedAt}}{{if .GeneratedBy}} by {{.GeneratedBy}}{{end}}. SHA-256 of the HTML artifact is recorded in the platform report record. Evidence files carry their own SHA-256 hashes.</p>
  <h3>Rating definitions</h3>
  <p>Critical: remotely exploitable, severe impact, no significant preconditions. High: exploitable weakness with material impact. Medium: requires specific conditions or has limited impact. Low: hygiene or defence-in-depth. Info: observation without confirmed weakness.</p>
</section>
</div>
</body>
</html>`

// --- PDF ---

func BuildPDF(d *Data) ([]byte, error) {
	d.Finalize()
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 18)
	pdf.SetMargins(18, 18, 18)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetTextColor(120, 116, 106)
		pdf.CellFormat(0, 5, ascii(fmt.Sprintf("King Malhare  ·  %s  ·  Page %d", d.Title, pdf.PageNo())), "", 0, "C", false, 0, "")
	})
	pdf.SetTitle(ascii(d.Title), true)
	pdf.SetAuthor("King Malhare", true)
	pdf.SetCreator("King Malhare Report Engine", true)

	// Cover page. AddPage must precede any drawing, otherwise fpdf writes the
	// first drawing operations before the PDF header.
	pdf.AddPage()
	pdf.SetFillColor(18, 17, 14)
	pdf.Rect(0, 0, 210, 297, "F")
	pdf.SetTextColor(245, 165, 36)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetXY(18, 24)
	pdf.CellFormat(0, 6, "KING MALHARE", "", 0, "L", false, 0, "")
	pdf.SetTextColor(184, 176, 160)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(18, 31)
	pdf.CellFormat(0, 5, "OFFENSIVE SECURITY & VULNERABILITY ASSESSMENT", "", 0, "L", false, 0, "")
	pdf.SetTextColor(247, 242, 232)
	pdf.SetFont("Times", "", 30)
	pdf.SetXY(18, 105)
	pdf.MultiCell(174, 12, ascii(d.Title), "", "L", false)
	pdf.SetTextColor(184, 176, 160)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetXY(18, 150)
	pdf.MultiCell(140, 6, ascii("Security assessment report prepared for "+clientOrOrg(d)+". Findings, evidence and remediation guidance are based on authorized testing performed during the reported period."), "", "L", false)
	pdf.SetDrawColor(58, 53, 41)
	pdf.Line(18, 225, 192, 225)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(184, 176, 160)
	pdf.SetXY(18, 233)
	pdf.CellFormat(44, 4, "PREPARED FOR", "", 0, "L", false, 0, "")
	pdf.CellFormat(44, 4, "ASSESSOR", "", 0, "L", false, 0, "")
	pdf.CellFormat(50, 4, "GENERATED", "", 0, "L", false, 0, "")
	pdf.CellFormat(0, 4, "REPORT ID", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(247, 242, 232)
	pdf.SetXY(18, 239)
	pdf.CellFormat(44, 5, ascii(clientOrOrg(d)), "", 0, "L", false, 0, "")
	pdf.CellFormat(44, 5, ascii(assessor(d)), "", 0, "L", false, 0, "")
	pdf.CellFormat(50, 5, ascii(d.GeneratedAt), "", 0, "L", false, 0, "")
	pdf.CellFormat(0, 5, ascii(d.ID), "", 0, "L", false, 0, "")
	pdf.SetTextColor(245, 165, 36)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetXY(18, 270)
	pdf.CellFormat(0, 5, "CONFIDENTIAL", "", 0, "L", false, 0, "")

	// Contents / summary
	pdf.AddPage()
	pdf.SetTextColor(180, 83, 9)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(0, 5, "EXECUTIVE SUMMARY", "", 1, "L", false, 0, "")
	pdf.SetTextColor(23, 21, 15)
	pdf.SetFont("Times", "", 22)
	pdf.MultiCell(0, 9, "Security assessment summary", "", "L", false)
	pdf.Ln(3)
	pdf.SetFont("Helvetica", "", 9.5)
	pdf.SetTextColor(58, 53, 44)
	pdf.MultiCell(0, 5, ascii(d.RiskStatement()), "", "L", false)
	pdf.Ln(4)
	cols := []struct {
		label   string
		key     string
		r, g, b int
	}{
		{"CRITICAL", "critical", 185, 28, 28},
		{"HIGH", "high", 194, 65, 12},
		{"MEDIUM", "medium", 161, 98, 7},
		{"LOW", "low", 63, 98, 18},
		{"INFO", "info", 71, 85, 105},
	}
	x, y := 18.0, pdf.GetY()
	w := 34.0
	for i, c := range cols {
		pdf.SetFillColor(c.r, c.g, c.b)
		pdf.Rect(x+float64(i)*w, y, w-2, 18, "F")
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Times", "", 16)
		pdf.SetXY(x+float64(i)*w+3, y+2)
		pdf.CellFormat(w-8, 8, fmt.Sprintf("%d", d.SeverityCounts[c.key]), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 6.5)
		pdf.SetXY(x+float64(i)*w+3, y+12)
		pdf.CellFormat(w-8, 4, c.label, "", 0, "L", false, 0, "")
	}
	pdf.SetY(y + 26)
	pdf.SetTextColor(23, 21, 15)
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, ascii(fmt.Sprintf("Posture score: %d/100. Scope: %d authorized target(s). The detailed sections of this report contain reproduction steps and evidence for every finding.", d.PostureScore, len(d.Scope))), "", "L", false)

	section(pdf, "01  Scope and authorization")
	for _, s := range d.Scope {
		pdf.SetFont("Helvetica", "B", 9)
		pdf.MultiCell(0, 5, ascii(s.Name+"  ·  "+s.Target), "", "L", false)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(110, 105, 96)
		pdf.MultiCell(0, 4.5, ascii(fmt.Sprintf("%s · %s · Authorization %s · approved by %s · expires %s", s.Type, s.Environment, s.AuthRef, s.Approver, s.Expires)), "", "L", false)
		pdf.SetTextColor(23, 21, 15)
		pdf.Ln(2)
	}
	section(pdf, "02  Methodology")
	for _, m := range d.Methodology {
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 5, ascii("•  "+m), "", "L", false)
		pdf.Ln(1)
	}
	section(pdf, "03  Tools and timeline")
	for _, e := range d.Executions {
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.CellFormat(40, 5, ascii(e.Scanner), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.MultiCell(0, 5, ascii(e.Status+" · "+e.Started), "", "L", false)
	}
	if len(d.Executions) == 0 {
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 5, ascii(strings.Join(d.Tools, ", ")), "", "L", false)
	}
	for _, t := range d.Timeline {
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.MultiCell(0, 5, ascii(t.At+"  ·  "+t.Label+"  ·  "+t.Detail), "", "L", false)
	}

	section(pdf, "04  Detailed findings")
	if len(d.Findings) == 0 {
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 5, "No findings were recorded for this assessment.", "", "L", false)
	}
	for i, f := range d.Findings {
		pdf.Ln(3)
		pdf.SetFillColor(severeRGB(f.Severity))
		pdf.Rect(18, pdf.GetY(), 174, 7, "F")
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetXY(21, pdf.GetY()+1.5)
		pdf.CellFormat(0, 4, ascii(fmt.Sprintf("KM-%03d   %s   %s", i+1, strings.ToUpper(f.Severity), f.Confidence)), "", 0, "L", false, 0, "")
		pdf.SetTextColor(23, 21, 15)
		pdf.SetY(pdf.GetY() + 11)
		pdf.SetFont("Times", "", 15)
		pdf.MultiCell(0, 7, ascii(f.Title), "", "L", false)
		pdf.SetFont("Helvetica", "", 7.8)
		pdf.SetTextColor(110, 105, 96)
		meta := fmt.Sprintf("Endpoint: %s   ·   CVE: %s   ·   CWE: %s   ·   CVSS: %s   ·   Status: %s", f.Endpoint, orDash(f.CVE), orDash(f.CWE), cvssText(f.CVSS), f.Status)
		pdf.MultiCell(0, 4.5, ascii(meta), "", "L", false)
		pdf.SetTextColor(23, 21, 15)
		para(pdf, "Description", f.Description)
		if f.TechnicalImpact != "" {
			para(pdf, "Technical impact", f.TechnicalImpact)
		}
		if f.BusinessImpact != "" {
			para(pdf, "Business impact", f.BusinessImpact)
		}
		if f.Reproduction != "" {
			para(pdf, "Reproduction", f.Reproduction)
		}
		if f.Evidence != nil {
			ev := fmt.Sprintf("%v", f.Evidence)
			if len(ev) > 2000 {
				ev = ev[:2000] + "…"
			}
			para(pdf, "Evidence", ev)
		}
		if f.Remediation != "" {
			para(pdf, "Remediation", f.Remediation)
		}
		if len(f.References) > 0 {
			pdf.SetFont("Helvetica", "B", 8)
			pdf.CellFormat(0, 5, "References", "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 7.5)
			for _, r := range f.References {
				pdf.MultiCell(0, 4, ascii("• "+r), "", "L", false)
			}
		}
		if len(f.EvidenceFiles) > 0 {
			pdf.SetFont("Helvetica", "B", 8)
			pdf.CellFormat(0, 5, "Attached evidence", "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 7.5)
			for _, e := range f.EvidenceFiles {
				pdf.MultiCell(0, 4, ascii(fmt.Sprintf("• %s (%d bytes, SHA-256 %s)", e.Filename, e.SizeBytes, e.SHA256)), "", "L", false)
				if e.DataURI != "" {
					embedPDFImage(pdf, e)
				}
			}
		}
		if i < len(d.Findings)-1 {
			pdf.Ln(4)
		}
	}

	section(pdf, "05  Risk analysis and conclusion")
	pdf.SetFont("Helvetica", "", 9.5)
	pdf.MultiCell(0, 5, ascii(d.RiskStatement()), "", "L", false)
	pdf.Ln(3)
	pdf.MultiCell(0, 5, ascii(d.Conclusion()), "", "L", false)
	pdf.Ln(3)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(0, 5, "REMEDIATION PRIORITIES", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, ascii("Immediate: critical and publicly exposed high findings. Short term: remaining high and medium findings including authentication and access control. Planned: low and informational hygiene. Retest every fixed finding and retain the retest evidence."), "", "L", false)
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetTextColor(110, 105, 96)
	pdf.MultiCell(0, 4, ascii("Report ID "+d.ID+" · Generated "+d.GeneratedAt+" · Confidential. This report reflects the authorized scope and the time of testing."), "", "L", false)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func section(pdf *fpdf.Fpdf, title string) {
	pdf.AddPage()
	pdf.SetTextColor(180, 83, 9)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(0, 5, ascii(strings.ToUpper(title)), "", 1, "L", false, 0, "")
	pdf.SetDrawColor(23, 21, 15)
	pdf.SetLineWidth(0.6)
	pdf.Line(18, pdf.GetY(), 60, pdf.GetY())
	pdf.Ln(4)
	pdf.SetTextColor(23, 21, 15)
}

func embedPDFImage(pdf *fpdf.Fpdf, evidence EvidenceFile) {
	comma := strings.IndexByte(evidence.DataURI, ',')
	if comma < 0 {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(evidence.DataURI[comma+1:])
	if err != nil || len(raw) == 0 {
		return
	}
	imageType := "PNG"
	if strings.Contains(evidence.ContentType, "jpeg") {
		imageType = "JPG"
	} else if strings.Contains(evidence.ContentType, "gif") {
		imageType = "GIF"
	} else if !strings.Contains(evidence.ContentType, "png") {
		return
	}
	options := fpdf.ImageOptions{ImageType: imageType}
	info := pdf.RegisterImageOptionsReader(evidence.Filename, options, bytes.NewReader(raw))
	if info == nil {
		return
	}
	width, height := info.Extent()
	if width <= 0 || height <= 0 {
		return
	}
	drawWidth := 72.0
	drawHeight := drawWidth * height / width
	if drawHeight > 100 {
		drawHeight = 100
		drawWidth = drawHeight * width / height
	}
	if pdf.GetY()+drawHeight+8 > 280 {
		pdf.AddPage()
	}
	pdf.ImageOptions(evidence.Filename, 18, pdf.GetY()+1, drawWidth, drawHeight, false, options, 0, "")
	pdf.Ln(drawHeight + 4)
}

func para(pdf *fpdf.Fpdf, label, text string) {
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(23, 21, 15)
	pdf.CellFormat(0, 5, ascii(label), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8.5)
	pdf.SetTextColor(58, 53, 44)
	pdf.MultiCell(0, 4.6, ascii(text), "", "L", false)
}

func severeRGB(sev string) (int, int, int) {
	switch sev {
	case "critical":
		return 185, 28, 28
	case "high":
		return 194, 65, 12
	case "medium":
		return 161, 98, 7
	case "low":
		return 63, 98, 18
	default:
		return 71, 85, 105
	}
}

func ascii(s string) string {
	replacer := strings.NewReplacer(
		"—", "-", "–", "-", "’", "'", "‘", "'", "“", `"`, "”", `"`,
		"…", "...", "·", "-", "•", "-", "→", "->", "≥", ">=", "≤", "<=", "®", "(R)", "©", "(C)",
	)
	out := replacer.Replace(s)
	var b strings.Builder
	for _, r := range out {
		if r < 128 {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	return b.String()
}

func clientOrOrg(d *Data) string {
	if d.ClientName != "" {
		return d.ClientName
	}
	return d.OrgName
}

func assessor(d *Data) string {
	if d.AssessorName != "" {
		return d.AssessorName
	}
	return "Security Engineering"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cvssText(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f", *v)
}
