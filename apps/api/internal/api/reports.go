package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/report"
	"github.com/kingmalhare/api/internal/scanner"
	"github.com/kingmalhare/api/internal/storage"
)

type createReportRequest struct {
	Title        string   `json:"title"`
	ClientName   string   `json:"client_name"`
	AssessorName string   `json:"assessor_name"`
	ScanID       string   `json:"scan_id"`
	FindingIDs   []string `json:"finding_ids"`
	PeriodStart  string   `json:"period_start"`
	PeriodEnd    string   `json:"period_end"`
}

func (s *Server) handleCreateReport(w http.ResponseWriter, r *http.Request) {
	var req createReportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	req.Title = strings.TrimSpace(req.Title)
	if len(req.Title) < 3 || len(req.Title) > 160 {
		s.writeValidation(w, "Report title must be between 3 and 160 characters.")
		return
	}
	if req.ScanID == "" && len(req.FindingIDs) == 0 {
		s.writeValidation(w, "Provide a scan_id or a list of finding_ids.")
		return
	}
	if (req.ScanID != "" && !validUUID(req.ScanID)) || len(req.FindingIDs) > 500 {
		s.writeValidation(w, "Report scope is invalid.")
		return
	}
	for _, id := range req.FindingIDs {
		if !validUUID(id) {
			s.writeValidation(w, "One or more finding ids are invalid.")
			return
		}
	}
	if req.ScanID != "" {
		var exists bool
		_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM scans WHERE id=$1 AND org_id=$2)`, req.ScanID, ac.OrgID).Scan(&exists)
		if !exists {
			writeError(w, http.StatusNotFound, "not_found", "Assessment not found.", nil)
			return
		}
	} else {
		var count int
		_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM findings WHERE org_id=$1 AND id = ANY($2::uuid[])`, ac.OrgID, req.FindingIDs).Scan(&count)
		if count != len(req.FindingIDs) {
			writeError(w, http.StatusNotFound, "not_found", "One or more findings were not found in this organization.", nil)
			return
		}
	}
	var reportID string
	var scanParam interface{}
	if req.ScanID != "" {
		scanParam = req.ScanID
	}
	err := s.db.QueryRow(r.Context(), `
		INSERT INTO reports (org_id, scan_id, title, client_name, assessor_name, period_start, period_end, status, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'generating',$8) RETURNING id::text`,
		ac.OrgID, scanParam, req.Title, strings.TrimSpace(req.ClientName), strings.TrimSpace(req.AssessorName),
		parseTimePtr(req.PeriodStart), parseTimePtr(req.PeriodEnd), ac.UserID).Scan(&reportID)
	if err != nil {
		s.dbError(w, err, "report")
		return
	}

	data, buildErr := s.buildReportData(r.Context(), ac, reportID, req)
	if buildErr != nil {
		_, _ = s.db.Exec(r.Context(), `UPDATE reports SET status='failed', error=$1 WHERE id=$2`, buildErr.Error(), reportID)
		var se *scanRequestError
		if errors.As(buildErr, &se) {
			writeError(w, se.Status, se.Code, se.Message, nil)
			return
		}
		s.log.Error("report build failed", "report", reportID, "error", buildErr)
		writeError(w, http.StatusInternalServerError, "report_failed", "The report could not be generated.", nil)
		return
	}
	html, err := report.BuildHTML(data)
	if err != nil {
		_, _ = s.db.Exec(r.Context(), `UPDATE reports SET status='failed', error=$1 WHERE id=$2`, err.Error(), reportID)
		s.log.Error("report html failed", "error", err)
		writeError(w, http.StatusInternalServerError, "report_failed", "The HTML report could not be rendered.", nil)
		return
	}
	pdf, err := report.BuildPDF(data)
	if err != nil {
		_, _ = s.db.Exec(r.Context(), `UPDATE reports SET status='failed', error=$1 WHERE id=$2`, err.Error(), reportID)
		s.log.Error("report pdf failed", "error", err)
		writeError(w, http.StatusInternalServerError, "report_failed", "The PDF report could not be rendered.", nil)
		return
	}
	htmlKey := storage.NewKey("reports/"+ac.OrgID+"/"+reportID, ".html")
	pdfKey := storage.NewKey("reports/"+ac.OrgID+"/"+reportID, ".pdf")
	if err := s.store.Put(r.Context(), htmlKey, strings.NewReader(string(html)), int64(len(html)), "text/html; charset=utf-8"); err != nil {
		_, _ = s.db.Exec(r.Context(), `UPDATE reports SET status='failed', error=$1 WHERE id=$2`, "storage unavailable", reportID)
		s.log.Error("report storage failed", "error", err)
		writeError(w, http.StatusInternalServerError, "storage_failed", "The report could not be stored.", nil)
		return
	}
	if err := s.store.Put(r.Context(), pdfKey, strings.NewReader(string(pdf)), int64(len(pdf)), "application/pdf"); err != nil {
		_ = s.store.Delete(r.Context(), htmlKey)
		_, _ = s.db.Exec(r.Context(), `UPDATE reports SET status='failed', error=$1 WHERE id=$2`, "storage unavailable", reportID)
		s.log.Error("report pdf storage failed", "error", err)
		writeError(w, http.StatusInternalServerError, "storage_failed", "The report could not be stored.", nil)
		return
	}
	htmlSum := sha256.Sum256(html)
	pdfSum := sha256.Sum256(pdf)
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(data.Findings)}
	for _, f := range data.Findings {
		counts[f.Severity]++
	}
	summary, _ := json.Marshal(map[string]any{
		"counts": counts, "posture_score": data.PostureScore,
		"html_sha256": hex.EncodeToString(htmlSum[:]), "pdf_sha256": hex.EncodeToString(pdfSum[:]),
		"findings": len(data.Findings), "scope": len(data.Scope),
	})
	_, err = s.db.Exec(r.Context(), `
		UPDATE reports SET status='ready', summary=$1, html_key=$2, pdf_key=$3,
			period_start=COALESCE($4, period_start), period_end=COALESCE($5, period_end)
		WHERE id=$6 AND org_id=$7`,
		summary, htmlKey, pdfKey, parseTimePtr(req.PeriodStart), parseTimePtr(req.PeriodEnd), reportID, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "report")
		return
	}
	assetName := "selected findings"
	if data.Scan != nil {
		assetName = data.Scan.AssetName
	}
	s.audit(r, "report.created", "report", reportID, map[string]any{"scan_id": req.ScanID, "findings": len(data.Findings)})
	s.notify(r.Context(), ac.OrgID, nil, "report", "Report ready", req.Title+" for "+assetName+" is ready to download.", "/reports/"+reportID)
	writeJSON(w, http.StatusCreated, map[string]any{"id": reportID, "status": "ready"})
}

func (s *Server) buildReportData(ctx context.Context, ac *AuthContext, reportID string, req createReportRequest) (*report.Data, error) {
	d := &report.Data{
		ID: reportID, Title: req.Title, ClientName: strings.TrimSpace(req.ClientName),
		AssessorName: strings.TrimSpace(req.AssessorName), GeneratedAt: time.Now().UTC().Format("2 January 2006, 15:04 UTC"),
		GeneratedBy: ac.Name, Findings: []report.Finding{}, Scope: []report.ScopeItem{},
		Tools: []string{}, Timeline: []report.TimelineItem{}, Executions: []report.Execution{},
		Methodology: defaultReportMethodology(),
	}
	var orgName string
	_ = s.db.QueryRow(ctx, `SELECT name FROM organizations WHERE id=$1`, ac.OrgID).Scan(&orgName)
	d.OrgName = orgName

	if req.ScanID != "" {
		var started, finished, queued *time.Time
		var authExpires time.Time
		si := &report.ScanInfo{}
		var assetName, assetType, environment, authRef, approver string
		err := s.db.QueryRow(ctx, `
			SELECT sc.scanner, sc.category, sc.target_snapshot, sc.status, sc.started_at, sc.finished_at, sc.queued_at,
			       a.name, a.type, a.environment, au.reference, au.approved_by_name, au.expires_at, sc.id::text
			FROM scans sc JOIN assets a ON a.id=sc.asset_id JOIN authorizations au ON au.id=sc.authorization_id
			WHERE sc.id=$1 AND sc.org_id=$2`, req.ScanID, ac.OrgID).
			Scan(&si.Scanner, &si.Category, &si.Target, &si.Status, &started, &finished, &queued,
				&assetName, &assetType, &environment, &authRef, &approver, &authExpires, &si.ID)
		if isNotFound(err) {
			return nil, scanErr(http.StatusNotFound, "scan_not_found", "Assessment not found.")
		}
		if err != nil {
			return nil, err
		}
		si.AssetName = assetName
		si.AuthRef = authRef
		si.Approver = approver
		si.AuthExpires = authExpires.UTC().Format("2 January 2006")
		if started != nil {
			si.StartedAt = started.UTC().Format("2 Jan 2006 15:04 UTC")
		}
		if finished != nil {
			si.FinishedAt = finished.UTC().Format("2 Jan 2006 15:04 UTC")
		}
		d.Scan = si
		d.Scope = append(d.Scope, report.ScopeItem{Name: assetName, Target: si.Target, Type: assetType,
			Environment: environment, AuthRef: authRef, Approver: approver, Expires: si.AuthExpires})
		if meta, ok := scanner.Find(si.Scanner); ok {
			d.Tools = append(d.Tools, meta.Label)
		} else {
			d.Tools = append(d.Tools, si.Scanner)
		}
		if queued != nil {
			d.Timeline = append(d.Timeline, report.TimelineItem{At: queued.UTC().Format("2 Jan 2006 15:04"), Label: "Assessment queued", Detail: si.Scanner + " · " + assetName})
		}
		if started != nil {
			d.Timeline = append(d.Timeline, report.TimelineItem{At: started.UTC().Format("2 Jan 2006 15:04"), Label: "Execution started", Detail: si.Scanner + " initialized against " + si.Target})
		}
		if finished != nil {
			d.Timeline = append(d.Timeline, report.TimelineItem{At: finished.UTC().Format("2 Jan 2006 15:04"), Label: "Assessment finished", Detail: si.Status})
		}
		findings, err := s.scanFindingsForReport(ctx, ac.OrgID, req.ScanID)
		if err != nil {
			return nil, err
		}
		d.Findings = findings
		execs, err := s.reportExecutions(ctx, ac.OrgID, req.ScanID)
		if err == nil {
			d.Executions = execs
			for _, e := range execs {
				if e.Started != "" {
					d.Timeline = append(d.Timeline, report.TimelineItem{At: e.Started, Label: "Tool: " + e.Scanner, Detail: e.Status + " · " + e.Command})
				}
			}
		}
		if req.PeriodStart == "" {
			if started != nil {
				d.PeriodStart = started.UTC().Format("2 Jan 2006 15:04 UTC")
			} else if queued != nil {
				d.PeriodStart = queued.UTC().Format("2 Jan 2006 15:04 UTC")
			}
		}
		if req.PeriodEnd == "" {
			if finished != nil {
				d.PeriodEnd = finished.UTC().Format("2 Jan 2006 15:04 UTC")
			}
		}
	} else {
		findings, scope, err := s.findingSetForReport(ctx, ac.OrgID, req.FindingIDs)
		if err != nil {
			return nil, err
		}
		d.Findings = findings
		d.Scope = scope
		for _, f := range findings {
			if f.CVE != "" || f.CWE != "" {
				d.Tools = append(d.Tools, "King Malhare finding register")
				break
			}
		}
		if len(d.Tools) == 0 {
			d.Tools = append(d.Tools, "King Malhare finding register")
		}
	}
	if req.PeriodStart != "" {
		if t := parseTimePtr(req.PeriodStart); t != nil {
			d.PeriodStart = t.UTC().Format("2 Jan 2006 15:04 UTC")
		}
	}
	if req.PeriodEnd != "" {
		if t := parseTimePtr(req.PeriodEnd); t != nil {
			d.PeriodEnd = t.UTC().Format("2 Jan 2006 15:04 UTC")
		}
	}
	// Deduplicate and attach evidence.
	d.Findings = dedupeFindings(d.Findings)
	d.PostureScore = postureScoreMap(d.Findings, max(len(d.Scope), 1))
	if err := s.attachEvidence(ctx, ac.OrgID, d.Findings); err != nil {
		s.log.Warn("evidence attachment failed for report", "error", err)
	}
	if d.PeriodStart == "" {
		d.PeriodStart = time.Now().UTC().Format("2 Jan 2006 15:04 UTC")
	}
	if d.PeriodEnd == "" {
		d.PeriodEnd = time.Now().UTC().Format("2 Jan 2006 15:04 UTC")
	}
	return d, nil
}

func defaultReportMethodology() []string {
	return []string{
		"Scope validation: every target was matched against a recorded authorization, validity window and intrusive-testing approval before execution.",
		"Discovery and enumeration: non-intrusive fingerprinting established the reachable attack surface, technologies and exposed services.",
		"Vulnerability detection: scanners and targeted verification requests identified weaknesses. Results were normalized and deduplicated by a stable fingerprint.",
		"Validation: only conditions proven by a concrete response or configuration state were reported. Unverified output was excluded.",
		"Risk rating: severity follows CVSS where available and contextual exposure otherwise. Business impact considers the affected environment.",
		"Reporting: findings were mapped to evidence, reproduction steps and remediation guidance. No finding was inferred without scanner evidence.",
	}
}

func (s *Server) scanFindingsForReport(ctx context.Context, orgID, scanID string) ([]report.Finding, error) {
	rows, err := s.db.Query(ctx, `
		SELECT sr.title, sr.severity, sr.confidence, COALESCE(sr.cve,''), COALESCE(sr.cwe,''), sr.cvss,
		       sr.endpoint, sr.description, sr.remediation, sr.evidence, sr.fingerprint, sr.created_at,
		       COALESCE(f.id::text,''), COALESCE(f.reproduction,''), COALESCE(f.business_impact,''),
		       COALESCE(f.technical_impact,''), COALESCE(f.remediation,''), f.references,
		       COALESCE(f.status,'open'), f.first_seen, f.last_seen
		FROM scan_results sr
		LEFT JOIN findings f ON f.org_id=sr.org_id AND f.fingerprint=sr.fingerprint
		WHERE sr.scan_id=$1 AND sr.org_id=$2
		ORDER BY CASE sr.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         sr.title`, scanID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []report.Finding{}
	for rows.Next() {
		var f report.Finding
		var evidence, refs []byte
		var created time.Time
		var first, last *time.Time
		var cvss *float64
		if err := rows.Scan(&f.Title, &f.Severity, &f.Confidence, &f.CVE, &f.CWE, &cvss,
			&f.Endpoint, &f.Description, &f.Remediation, &evidence, &f.Fingerprint, &created,
			&f.ID, &f.Reproduction, &f.BusinessImpact, &f.TechnicalImpact, &f.Remediation, &refs,
			&f.Status, &first, &last); err != nil {
			return nil, err
		}
		f.CVSS = cvss
		if first != nil {
			f.FirstSeen = first.UTC().Format("2 Jan 2006 15:04")
		} else {
			f.FirstSeen = created.UTC().Format("2 Jan 2006 15:04")
		}
		if last != nil {
			f.LastSeen = last.UTC().Format("2 Jan 2006 15:04")
		} else {
			f.LastSeen = created.UTC().Format("2 Jan 2006 15:04")
		}
		f.References = jsonStrings(refs)
		f.Evidence = prettyJSON(evidence)
		f.EvidenceFiles = []report.EvidenceFile{}
		out = append(out, f)
	}
	return out, nil
}

func (s *Server) findingSetForReport(ctx context.Context, orgID string, ids []string) ([]report.Finding, []report.ScopeItem, error) {
	rows, err := s.db.Query(ctx, `
		SELECT f.id::text, f.fingerprint, f.title, f.severity, f.confidence, COALESCE(f.cve,''), COALESCE(f.cwe,''),
		       f.cvss, f.endpoint, f.description, f.reproduction, f.business_impact, f.technical_impact,
		       f.remediation, f.references, f.evidence, f.status, f.first_seen, f.last_seen,
		       a.name, a.target, a.type, a.environment
		FROM findings f JOIN assets a ON a.id=f.asset_id
		WHERE f.org_id=$1 AND f.id = ANY($2::uuid[])
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         f.title`, orgID, ids)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := []report.Finding{}
	scopeMap := map[string]report.ScopeItem{}
	for rows.Next() {
		var f report.Finding
		var refs, evidence []byte
		var cvss *float64
		var first, last time.Time
		var assetName, assetTarget, assetType, env string
		if err := rows.Scan(&f.ID, &f.Fingerprint, &f.Title, &f.Severity, &f.Confidence, &f.CVE, &f.CWE,
			&cvss, &f.Endpoint, &f.Description, &f.Reproduction, &f.BusinessImpact, &f.TechnicalImpact,
			&f.Remediation, &refs, &evidence, &f.Status, &first, &last,
			&assetName, &assetTarget, &assetType, &env); err != nil {
			return nil, nil, err
		}
		f.CVSS = cvss
		f.FirstSeen = first.UTC().Format("2 Jan 2006 15:04")
		f.LastSeen = last.UTC().Format("2 Jan 2006 15:04")
		f.References = jsonStrings(refs)
		f.Evidence = prettyJSON(evidence)
		f.EvidenceFiles = []report.EvidenceFile{}
		out = append(out, f)
		key := assetName + assetTarget
		if _, ok := scopeMap[key]; !ok {
			item := report.ScopeItem{Name: assetName, Target: assetTarget, Type: assetType, Environment: env}
			var authExpiry *time.Time
			_ = s.db.QueryRow(ctx, `
				SELECT reference, approved_by_name, expires_at FROM authorizations
				WHERE asset_id=(SELECT id FROM assets WHERE org_id=$1 AND target=$2 LIMIT 1) AND org_id=$1
				  AND status='active' AND expires_at>now() ORDER BY created_at DESC LIMIT 1`, orgID, assetTarget).
				Scan(&item.AuthRef, &item.Approver, &authExpiry)
			if authExpiry != nil {
				item.Expires = authExpiry.UTC().Format("2 January 2006")
			}
			scopeMap[key] = item
		}
	}
	scope := make([]report.ScopeItem, 0, len(scopeMap))
	for _, v := range scopeMap {
		scope = append(scope, v)
	}
	return out, scope, nil
}

func (s *Server) reportExecutions(ctx context.Context, orgID, scanID string) ([]report.Execution, error) {
	rows, err := s.db.Query(ctx, `
		SELECT scanner, status, command_summary, started_at, finished_at, output_excerpt
		FROM scanner_executions WHERE org_id=$1 AND scan_id=$2 ORDER BY started_at`, orgID, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []report.Execution{}
	for rows.Next() {
		var e report.Execution
		var started time.Time
		var finished *time.Time
		var output string
		if err := rows.Scan(&e.Scanner, &e.Status, &e.Command, &started, &finished, &output); err != nil {
			return nil, err
		}
		e.Started = started.UTC().Format("2 Jan 2006 15:04")
		if finished != nil {
			e.Finished = finished.UTC().Format("2 Jan 2006 15:04")
		}
		e.Output = truncate(output, 1000)
		out = append(out, e)
	}
	return out, nil
}

func (s *Server) attachEvidence(ctx context.Context, orgID string, findings []report.Finding) error {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.ID != "" {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.db.Query(ctx, `
		SELECT finding_id::text, filename, content_type, size_bytes, sha256, storage_key
		FROM evidence WHERE org_id=$1 AND finding_id = ANY($2::uuid[]) ORDER BY created_at`, orgID, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	byFinding := map[string][]report.EvidenceFile{}
	type item struct {
		findingID string
		file      report.EvidenceFile
		key       string
	}
	items := []item{}
	for rows.Next() {
		var findingID, key string
		var f report.EvidenceFile
		if err := rows.Scan(&findingID, &f.Filename, &f.ContentType, &f.SizeBytes, &f.SHA256, &key); err != nil {
			return err
		}
		items = append(items, item{findingID: findingID, file: f, key: key})
	}
	for _, it := range items {
		f := it.file
		if strings.HasPrefix(f.ContentType, "image/") && f.SizeBytes <= 2<<20 {
			rc, _, _, err := s.store.Open(ctx, it.key)
			if err == nil {
				limit := io.LimitReader(rc, 2<<20)
				blob, rerr := io.ReadAll(limit)
				rc.Close()
				if rerr == nil {
					f.DataURI = "data:" + f.ContentType + ";base64," + base64.StdEncoding.EncodeToString(blob)
				}
			}
		}
		byFinding[it.findingID] = append(byFinding[it.findingID], f)
	}
	for i := range findings {
		if files, ok := byFinding[findings[i].ID]; ok {
			findings[i].EvidenceFiles = files
		}
	}
	return nil
}

func dedupeFindings(in []report.Finding) []report.Finding {
	seen := map[string]bool{}
	out := make([]report.Finding, 0, len(in))
	for _, f := range in {
		key := f.Fingerprint
		if key == "" {
			key = f.Title + "|" + f.Endpoint
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func postureScoreMap(findings []report.Finding, assets int) int {
	open := map[string]int{}
	for _, f := range findings {
		switch f.Status {
		case "fixed", "false_positive", "accepted_risk":
			continue
		}
		open[f.Severity]++
	}
	return postureScore(open, max(assets, 1))
}

func jsonStrings(raw []byte) []string {
	var out []string
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		return []string{}
	}
	return out
}

func prettyJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	if len(b) > 6000 {
		return string(b[:6000]) + "\n…"
	}
	return string(b)
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	pageNo, perPage := pagination(r)
	status := r.URL.Query().Get("status")
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	where := `r.org_id=$1 AND ($2='' OR r.status=$2) AND ($3='' OR r.title ILIKE '%'||$3||'%' OR r.client_name ILIKE '%'||$3||'%')`
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM reports r WHERE `+where, ac.OrgID, status, search).Scan(&total); err != nil {
		s.dbError(w, err, "reports")
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT r.id::text, r.title, r.client_name, r.assessor_name, r.scan_id::text, r.status, r.summary,
		       r.created_at, u.name, sc.scanner, a.name, a.id::text
		FROM reports r LEFT JOIN users u ON u.id=r.created_by
		LEFT JOIN scans sc ON sc.id=r.scan_id LEFT JOIN assets a ON a.id=sc.asset_id
		WHERE `+where+` ORDER BY r.created_at DESC LIMIT $4 OFFSET $5`, ac.OrgID, status, search, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "reports")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, title, client, assessor, status, createdBy string
		var scanID, scannerName, assetName, assetID *string
		var summary []byte
		var created time.Time
		if err := rows.Scan(&id, &title, &client, &assessor, &scanID, &status, &summary, &created, &createdBy, &scannerName, &assetName, &assetID); err != nil {
			s.dbError(w, err, "report")
			return
		}
		items = append(items, map[string]any{"id": id, "title": title, "client_name": client, "assessor_name": assessor,
			"scan_id": scanID, "status": status, "summary": json.RawMessage(summary), "created_at": created.UTC().Format(time.RFC3339),
			"created_by": createdBy, "scanner": scannerName, "asset_name": assetName, "asset_id": assetID})
	}
	writeJSON(w, http.StatusOK, page{Items: items, Page: pageNo, PerPage: perPage, Total: total})
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "reportID")
	var title, client, assessor, status, createdBy string
	var scanID, scannerName, assetName *string
	var summary []byte
	var created time.Time
	var periodStart, periodEnd *time.Time
	var htmlKey, pdfKey *string
	var reportErr *string
	err := s.db.QueryRow(r.Context(), `
		SELECT r.title, r.client_name, r.assessor_name, r.status, r.summary, r.created_at, u.name,
		       r.scan_id::text, sc.scanner, a.name, r.period_start, r.period_end, r.html_key, r.pdf_key, r.error
		FROM reports r LEFT JOIN users u ON u.id=r.created_by
		LEFT JOIN scans sc ON sc.id=r.scan_id LEFT JOIN assets a ON a.id=sc.asset_id
		WHERE r.id=$1 AND r.org_id=$2`, id, ac.OrgID).
		Scan(&title, &client, &assessor, &status, &summary, &created, &createdBy,
			&scanID, &scannerName, &assetName, &periodStart, &periodEnd, &htmlKey, &pdfKey, &reportErr)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Report not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "report")
		return
	}
	resp := map[string]any{"id": id, "title": title, "client_name": client, "assessor_name": assessor,
		"status": status, "summary": json.RawMessage(summary), "created_at": created.UTC().Format(time.RFC3339),
		"created_by": createdBy, "scan_id": scanID, "scanner": scannerName, "asset_name": assetName,
		"error": reportErr, "has_html": htmlKey != nil && *htmlKey != "", "has_pdf": pdfKey != nil && *pdfKey != ""}
	if periodStart != nil {
		resp["period_start"] = periodStart.UTC().Format(time.RFC3339)
	}
	if periodEnd != nil {
		resp["period_end"] = periodEnd.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "reportID")
	var key, title string
	err := s.db.QueryRow(r.Context(), `SELECT html_key, title FROM reports WHERE id=$1 AND org_id=$2 AND status='ready'`, id, ac.OrgID).Scan(&key, &title)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Report HTML not available.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "report")
		return
	}
	rc, _, _, err := s.store.Open(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Report artifact is missing from storage.", nil)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleReportPDF(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "reportID")
	var key, title string
	err := s.db.QueryRow(r.Context(), `SELECT pdf_key, title FROM reports WHERE id=$1 AND org_id=$2 AND status='ready'`, id, ac.OrgID).Scan(&key, &title)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Report PDF not available.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "report")
		return
	}
	rc, _, _, err := s.store.Open(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Report artifact is missing from storage.", nil)
		return
	}
	defer rc.Close()
	filename := sanitizeFilename(strings.ReplaceAll(title, " ", "-")) + ".pdf"
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "reportID")
	var htmlKey, pdfKey *string
	err := s.db.QueryRow(r.Context(), `SELECT html_key, pdf_key FROM reports WHERE id=$1 AND org_id=$2`, id, ac.OrgID).Scan(&htmlKey, &pdfKey)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Report not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "report")
		return
	}
	for _, key := range []*string{htmlKey, pdfKey} {
		if key != nil && *key != "" {
			_ = s.store.Delete(r.Context(), *key)
		}
	}
	if _, err := s.db.Exec(r.Context(), `DELETE FROM reports WHERE id=$1 AND org_id=$2`, id, ac.OrgID); err != nil {
		s.dbError(w, err, "report")
		return
	}
	s.audit(r, "report.deleted", "report", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
