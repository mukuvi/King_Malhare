package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/scanner"
)

type progressRequest struct {
	Phase    string `json:"phase"`
	Progress int    `json:"progress"`
	Message  string `json:"message"`
}

func (s *Server) handleWorkerClaim(w http.ResponseWriter, r *http.Request) {
	scanID := chiURLParam(r, "scanID")
	var status string
	var cancel bool
	var orgID string
	var attempt int
	err := s.db.QueryRow(r.Context(), `SELECT status, cancel_requested, org_id::text, attempt FROM scans WHERE id=$1`, scanID).
		Scan(&status, &cancel, &orgID, &attempt)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Scan job not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	emergency, _ := s.queue.EmergencyStop(r.Context(), orgID)
	redisCancel, _ := s.queue.IsCancelled(r.Context(), scanID)
	if cancel || emergency || redisCancel || status == "cancelled" {
		writeError(w, http.StatusConflict, "job_cancelled", "This job has been cancelled.", nil)
		return
	}
	if status != "queued" && status != "initializing" {
		writeError(w, http.StatusConflict, "job_not_claimable", "This job is not in a claimable state.", map[string]any{"status": status})
		return
	}
	tag, err := s.db.Exec(r.Context(), `
		UPDATE scans SET status='initializing', started_at=COALESCE(started_at, now()), last_heartbeat_at=now(),
			attempt=attempt+1, phase='initializing'
		WHERE id=$1 AND status IN ('queued','initializing')`, scanID)
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusConflict, "job_not_claimable", "This job was claimed by another worker.", nil)
		return
	}
	s.queue.Publish(r.Context(), scanner.Event{Type: "status", ScanID: scanID, Status: "initializing", Phase: "initializing", Message: "Worker initialized", At: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "org_id": orgID, "attempt": attempt + 1})
}

func (s *Server) handleWorkerProgress(w http.ResponseWriter, r *http.Request) {
	var req progressRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	scanID := chiURLParam(r, "scanID")
	if req.Progress < 0 || req.Progress > 100 {
		s.writeValidation(w, "Progress must be between 0 and 100.")
		return
	}
	if len(req.Phase) > 120 || len(req.Message) > 1000 {
		s.writeValidation(w, "Progress payload is too large.")
		return
	}
	var orgID string
	var cancel, emergency bool
	err := s.db.QueryRow(r.Context(), `
		UPDATE scans SET status = CASE WHEN status='initializing' THEN 'running' ELSE status END,
			progress=GREATEST(progress,$2), phase=$3, last_heartbeat_at=now()
		WHERE id=$1 RETURNING org_id::text`, scanID, req.Progress, truncate(req.Phase, 120)).Scan(&orgID)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Scan job not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	emergency, _ = s.queue.EmergencyStop(r.Context(), orgID)
	redisCancel, _ := s.queue.IsCancelled(r.Context(), scanID)
	_ = s.db.QueryRow(r.Context(), `SELECT cancel_requested FROM scans WHERE id=$1`, scanID).Scan(&cancel)
	s.queue.Publish(r.Context(), scanner.Event{Type: "progress", ScanID: scanID, Phase: req.Phase, Progress: req.Progress, Message: req.Message, At: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"cancel": cancel || emergency || redisCancel})
}

type workerExecutionRequest struct {
	ExecutionID string `json:"execution_id"`
	Scanner     string `json:"scanner"`
	Status      string `json:"status"`
	Command     string `json:"command"`
	ExitCode    *int   `json:"exit_code"`
	Output      string `json:"output_excerpt"`
	Error       string `json:"error"`
}

func (s *Server) handleWorkerExecution(w http.ResponseWriter, r *http.Request) {
	var req workerExecutionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	scanID := chiURLParam(r, "scanID")
	var orgID string
	if err := s.db.QueryRow(r.Context(), `SELECT org_id::text FROM scans WHERE id=$1`, scanID).Scan(&orgID); isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Scan job not found.", nil)
		return
	}
	req.Command = truncate(req.Command, 2000)
	req.Output = truncate(req.Output, 20000)
	req.Error = truncate(req.Error, 2000)
	if req.ExecutionID == "" {
		var id string
		err := s.db.QueryRow(r.Context(), `
			INSERT INTO scanner_executions (org_id, scan_id, scanner, status, command_summary)
			VALUES ($1,$2,$3,'running',$4) RETURNING id::text`, orgID, scanID, req.Scanner, req.Command).Scan(&id)
		if err != nil {
			s.dbError(w, err, "execution")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
		return
	}
	status := req.Status
	if status == "" {
		status = "completed"
	}
	switch status {
	case "running", "completed", "failed", "cancelled", "unavailable":
	default:
		s.writeValidation(w, "Invalid execution status.")
		return
	}
	var errText *string
	if req.Error != "" {
		errText = &req.Error
	}
	tag, err := s.db.Exec(r.Context(), `
		UPDATE scanner_executions SET status=$1, exit_code=$2, output_excerpt=$3, error=$4,
			finished_at=CASE WHEN $1='running' THEN NULL ELSE now() END
		WHERE id=$5 AND scan_id=$6 AND org_id=$7`, status, req.ExitCode, req.Output, errText, req.ExecutionID, scanID, orgID)
	if err != nil {
		s.dbError(w, err, "execution")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Execution not found.", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type workerResult struct {
	Fingerprint string         `json:"fingerprint"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Confidence  string         `json:"confidence"`
	CVE         string         `json:"cve"`
	CWE         string         `json:"cwe"`
	CVSS        *float64       `json:"cvss"`
	Endpoint    string         `json:"endpoint"`
	Description string         `json:"description"`
	Remediation string         `json:"remediation"`
	Evidence    map[string]any `json:"evidence"`
	Raw         map[string]any `json:"raw"`
}

type workerResultsRequest struct {
	Results []workerResult `json:"results"`
}

var (
	cweRe         = regexp.MustCompile(`^CWE-\d{1,5}$`)
	cveFormatRe   = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,7}$`)
	fingerprintRe = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func (s *Server) handleWorkerResults(w http.ResponseWriter, r *http.Request) {
	var req workerResultsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	scanID := chiURLParam(r, "scanID")
	if len(req.Results) > 500 {
		s.writeValidation(w, "At most 500 results can be submitted per request.")
		return
	}
	var orgID, assetID, scannerName string
	err := s.db.QueryRow(r.Context(), `SELECT org_id::text, asset_id::text, scanner FROM scans WHERE id=$1`, scanID).Scan(&orgID, &assetID, &scannerName)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Scan job not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	inserted, updated, skipped := 0, 0, 0
	for _, res := range req.Results {
		if err := validateWorkerResult(&res); err != nil {
			skipped++
			s.log.Warn("invalid worker result skipped", "scan", scanID, "error", err, "title", truncate(res.Title, 80))
			continue
		}
		evidenceBody, _ := json.Marshal(res.Evidence)
		rawBody, _ := json.Marshal(res.Raw)
		if len(evidenceBody) > 64<<10 {
			evidenceBody = []byte(`{"truncated":true}`)
		}
		if len(rawBody) > 64<<10 {
			rawBody = []byte(`{"truncated":true}`)
		}
		fp := strings.ToLower(res.Fingerprint)
		if !fingerprintRe.MatchString(fp) {
			fp = fingerprint(scannerName, res.Title, res.Endpoint, res.CVE, res.CWE)
		}
		var cve, cwe *string
		if res.CVE != "" {
			v := strings.ToUpper(res.CVE)
			cve = &v
		}
		if res.CWE != "" {
			v := strings.ToUpper(res.CWE)
			cwe = &v
		}
		tx, err := s.db.Begin(r.Context())
		if err != nil {
			s.dbError(w, err, "results")
			return
		}
		_, err = tx.Exec(r.Context(), `
			INSERT INTO scan_results (org_id, scan_id, asset_id, scanner, fingerprint, title, severity, confidence,
				cve, cwe, cvss, endpoint, description, remediation, evidence, raw)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			orgID, scanID, assetID, scannerName, fp, res.Title, res.Severity, res.Confidence,
			cve, cwe, res.CVSS, truncate(res.Endpoint, 2000), truncate(res.Description, 5000),
			truncate(res.Remediation, 5000), evidenceBody, rawBody)
		if err != nil {
			_ = tx.Rollback(r.Context())
			s.log.Error("scan result insert failed", "scan", scanID, "error", err)
			skipped++
			continue
		}
		var findingID string
		var isNew bool
		err = tx.QueryRow(r.Context(), `
			INSERT INTO findings (org_id, asset_id, scan_id, fingerprint, title, severity, confidence, cve, cwe, cvss,
				endpoint, description, remediation, evidence, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now())
			ON CONFLICT (org_id, fingerprint) DO UPDATE SET
			  last_seen=now(), scan_id=EXCLUDED.scan_id, evidence=EXCLUDED.evidence,
			  severity=CASE WHEN findings.status='open' THEN EXCLUDED.severity ELSE findings.severity END,
			  title=EXCLUDED.title, endpoint=EXCLUDED.endpoint, cve=EXCLUDED.cve, cwe=EXCLUDED.cwe,
			  cvss=EXCLUDED.cvss, updated_at=now()
			RETURNING id::text, (xmax = 0) AS inserted`, orgID, assetID, scanID, fp, res.Title, res.Severity,
			res.Confidence, cve, cwe, res.CVSS, truncate(res.Endpoint, 2000), truncate(res.Description, 5000),
			truncate(res.Remediation, 5000), evidenceBody).Scan(&findingID, &isNew)
		if err != nil {
			_ = tx.Rollback(r.Context())
			s.log.Error("finding upsert failed", "scan", scanID, "error", err)
			skipped++
			continue
		}
		if isNew {
			_, _ = tx.Exec(r.Context(), `INSERT INTO finding_events (org_id,finding_id,type,to_value) VALUES ($1,$2,'created',$3)`, orgID, findingID, res.Severity)
			inserted++
		} else {
			updated++
		}
		if err := tx.Commit(r.Context()); err != nil {
			s.log.Error("finding commit failed", "error", err)
			skipped++
			continue
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": inserted + updated, "created": inserted, "updated": updated, "skipped": skipped})
}

func validateWorkerResult(res *workerResult) error {
	res.Title = strings.TrimSpace(res.Title)
	res.Endpoint = strings.TrimSpace(res.Endpoint)
	res.Severity = strings.ToLower(strings.TrimSpace(res.Severity))
	res.Confidence = strings.ToLower(strings.TrimSpace(res.Confidence))
	res.CVE = strings.ToUpper(strings.TrimSpace(res.CVE))
	res.CWE = strings.ToUpper(strings.TrimSpace(res.CWE))
	if len(res.Title) < 3 || len(res.Title) > 240 {
		return fmt.Errorf("title length invalid")
	}
	if !validSeverity(res.Severity) {
		return fmt.Errorf("invalid severity")
	}
	if res.Confidence == "" {
		res.Confidence = "firm"
	}
	switch res.Confidence {
	case "certain", "firm", "tentative":
	default:
		return fmt.Errorf("invalid confidence")
	}
	if res.CVE != "" && !cveFormatRe.MatchString(res.CVE) {
		return fmt.Errorf("invalid CVE")
	}
	if res.CWE != "" && !cweRe.MatchString(res.CWE) {
		return fmt.Errorf("invalid CWE")
	}
	if res.CVSS != nil && (*res.CVSS < 0 || *res.CVSS > 10) {
		return fmt.Errorf("invalid CVSS")
	}
	if len(res.Endpoint) > 2000 || len(res.Description) > 5000 || len(res.Remediation) > 5000 {
		return fmt.Errorf("field too long")
	}
	if res.Evidence == nil {
		res.Evidence = map[string]any{}
	}
	if res.Raw == nil {
		res.Raw = map[string]any{}
	}
	return nil
}

func fingerprint(scannerName, title, endpoint, cve, cwe string) string {
	key := strings.ToLower(strings.Join([]string{scannerName, strings.TrimSpace(title), strings.TrimSpace(endpoint), strings.ToUpper(cve), strings.ToUpper(cwe)}, "|"))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

type completeRequest struct {
	Status  string         `json:"status"`
	Error   string         `json:"error"`
	Summary map[string]any `json:"summary"`
}

func (s *Server) handleWorkerComplete(w http.ResponseWriter, r *http.Request) {
	var req completeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	scanID := chiURLParam(r, "scanID")
	switch req.Status {
	case "completed", "failed", "cancelled":
	default:
		s.writeValidation(w, "Status must be completed, failed or cancelled.")
		return
	}
	var orgID, assetID, scannerName, assetName string
	err := s.db.QueryRow(r.Context(), `
		SELECT sc.org_id::text, sc.asset_id::text, sc.scanner, a.name
		FROM scans sc JOIN assets a ON a.id=sc.asset_id WHERE sc.id=$1`, scanID).Scan(&orgID, &assetID, &scannerName, &assetName)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Scan job not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	summaryBody, _ := json.Marshal(req.Summary)
	if len(summaryBody) > 64<<10 {
		summaryBody = []byte(`{"truncated":true}`)
	}
	progress := 100
	var currentProgress int
	var errText *string
	if req.Error != "" {
		errText = &req.Error
	}
	err = s.db.QueryRow(r.Context(), `
		UPDATE scans SET status=$1, progress=CASE WHEN $1='completed' THEN 100 ELSE progress END,
			phase=$1, summary=$2, error=$3, finished_at=now(), last_heartbeat_at=now()
		WHERE id=$4 RETURNING progress`, req.Status, summaryBody, errText, scanID).Scan(&currentProgress)
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	progress = currentProgress
	if req.Status == "completed" {
		_, _ = s.db.Exec(r.Context(), `UPDATE assets SET last_assessed_at=now() WHERE id=$1`, assetID)
	}
	var critical, high, total int
	_ = s.db.QueryRow(r.Context(), `SELECT count(DISTINCT fingerprint), count(DISTINCT fingerprint) FILTER (WHERE severity='critical'), count(DISTINCT fingerprint) FILTER (WHERE severity='high') FROM scan_results WHERE scan_id=$1`, scanID).Scan(&total, &critical, &high)
	title := "Assessment completed"
	body := fmt.Sprintf("%s on %s finished with %d findings.", strings.ReplaceAll(scannerName, "-", " "), assetName, total)
	notifType := "scan"
	if req.Status == "failed" {
		title = "Assessment failed"
		body = fmt.Sprintf("The %s assessment on %s failed: %s", strings.ReplaceAll(scannerName, "-", " "), assetName, truncate(req.Error, 300))
	} else if req.Status == "cancelled" {
		title = "Assessment cancelled"
		body = fmt.Sprintf("The %s assessment on %s was cancelled.", strings.ReplaceAll(scannerName, "-", " "), assetName)
	}
	s.notify(r.Context(), orgID, nil, notifType, title, body, "/scans/"+scanID)
	s.auditSystem(r.Context(), orgID, "scan."+req.Status, "scan", scanID, map[string]any{
		"total_findings": total, "critical": critical, "high": high, "error": truncate(req.Error, 500),
	})
	s.queue.Publish(r.Context(), scanner.Event{Type: "status", ScanID: scanID, Status: req.Status, Progress: progress,
		Message: title, Data: map[string]any{"findings": total, "critical": critical, "high": high}, At: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleWorkerCancelState(w http.ResponseWriter, r *http.Request) {
	scanID := chiURLParam(r, "scanID")
	var orgID string
	var cancel bool
	var status string
	err := s.db.QueryRow(r.Context(), `SELECT org_id::text, cancel_requested, status FROM scans WHERE id=$1`, scanID).Scan(&orgID, &cancel, &status)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Scan job not found.", nil)
		return
	}
	emergency, _ := s.queue.EmergencyStop(r.Context(), orgID)
	redisCancel, _ := s.queue.IsCancelled(r.Context(), scanID)
	writeJSON(w, http.StatusOK, map[string]any{"cancel": cancel || emergency || redisCancel, "emergency": emergency, "status": status})
}

func (s *Server) handleWorkerConfig(w http.ResponseWriter, r *http.Request) {
	orgID := chiURLParam(r, "orgID")
	if !validUUID(orgID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid organization id.", nil)
		return
	}
	emergency, err := s.queue.EmergencyStop(r.Context(), orgID)
	if err != nil {
		s.dbError(w, err, "organization")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"emergency_stop": emergency})
}
