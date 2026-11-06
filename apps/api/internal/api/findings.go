package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/storage"
)

type findingListItem struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Confidence  string   `json:"confidence"`
	AssetID     string   `json:"asset_id"`
	AssetName   string   `json:"asset_name"`
	Endpoint    string   `json:"endpoint"`
	CVE         *string  `json:"cve"`
	CWE         *string  `json:"cwe"`
	CVSS        *float64 `json:"cvss"`
	AssignedTo  *string  `json:"assigned_to"`
	Assignee    *string  `json:"assignee_name"`
	ScanID      *string  `json:"scan_id"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	VerifiedAt  *string  `json:"verified_at"`
	HasEvidence int      `json:"evidence_count"`
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	pageNo, perPage := pagination(r)
	q := r.URL.Query()
	severity := q.Get("severity")
	status := q.Get("status")
	assetID := q.Get("asset_id")
	assignee := q.Get("assigned_to")
	search := strings.TrimSpace(q.Get("search"))
	if severity != "" && !validSeverity(severity) {
		s.writeValidation(w, "Unknown severity.")
		return
	}
	if status != "" && !validFindingStatus(status) {
		s.writeValidation(w, "Unknown status.")
		return
	}
	sort := sortClause(r, map[string]string{
		"last_seen": "f.last_seen", "first_seen": "f.first_seen", "severity": "severity_rank", "status": "f.status", "title": "f.title",
	}, "severity_rank asc, f.last_seen desc")
	where := `f.org_id=$1 AND ($2='' OR f.severity=$2) AND ($3='' OR f.status=$3) AND ($4='' OR f.asset_id::text=$4)
		AND ($5='' OR f.assigned_to::text=$5) AND ($6='' OR f.title ILIKE '%'||$6||'%' OR f.endpoint ILIKE '%'||$6||'%' OR COALESCE(f.cve,'') ILIKE '%'||$6||'%')`
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM findings f WHERE `+where, ac.OrgID, severity, status, assetID, assignee, search).Scan(&total); err != nil {
		s.dbError(w, err, "findings")
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT f.id::text, f.title, f.severity, f.status, f.confidence, f.asset_id::text, a.name, f.endpoint,
		       f.cve, f.cwe, f.cvss, f.assigned_to::text, u.name, f.scan_id::text, f.first_seen, f.last_seen, f.verified_at,
		       (SELECT count(*) FROM evidence e WHERE e.finding_id=f.id),
		       CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END AS severity_rank
		FROM findings f JOIN assets a ON a.id=f.asset_id LEFT JOIN users u ON u.id=f.assigned_to
		WHERE `+where+` ORDER BY `+sort+` LIMIT $7 OFFSET $8`,
		ac.OrgID, severity, status, assetID, assignee, search, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "findings")
		return
	}
	defer rows.Close()
	items := []findingListItem{}
	for rows.Next() {
		var x findingListItem
		var first, last time.Time
		var verified *time.Time
		var rank int
		if err := rows.Scan(&x.ID, &x.Title, &x.Severity, &x.Status, &x.Confidence, &x.AssetID, &x.AssetName, &x.Endpoint,
			&x.CVE, &x.CWE, &x.CVSS, &x.AssignedTo, &x.Assignee, &x.ScanID, &first, &last, &verified, &x.HasEvidence, &rank); err != nil {
			s.dbError(w, err, "finding")
			return
		}
		x.FirstSeen = first.UTC().Format(time.RFC3339)
		x.LastSeen = last.UTC().Format(time.RFC3339)
		if verified != nil {
			v := verified.UTC().Format(time.RFC3339)
			x.VerifiedAt = &v
		}
		items = append(items, x)
	}
	writeJSON(w, http.StatusOK, page{Items: items, Page: pageNo, PerPage: perPage, Total: total})
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "findingID")
	if !validUUID(id) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid finding id.", nil)
		return
	}
	var x map[string]any
	var fID, title, desc, severity, confidence, endpoint, reproduction, business, technical, remediation, status, assetName, assetTarget string
	var assetID, scanID, assigneeID, assigneeName, verifiedBy *string
	var cve, cwe *string
	var cvss *float64
	var evidence, refs []byte
	var first, last time.Time
	var verified *time.Time
	err := s.db.QueryRow(r.Context(), `
		SELECT f.id::text, f.title, f.description, f.severity, f.confidence, f.endpoint, f.reproduction,
		       f.business_impact, f.technical_impact, f.remediation, f.status, f.asset_id::text, a.name, a.target,
		       f.scan_id::text, f.assigned_to::text, u.name, v.name, f.cve, f.cwe, f.cvss,
		       f.evidence, f.references, f.first_seen, f.last_seen, f.verified_at
		FROM findings f JOIN assets a ON a.id=f.asset_id
		LEFT JOIN users u ON u.id=f.assigned_to LEFT JOIN users v ON v.id=f.verified_by
		WHERE f.id=$1 AND f.org_id=$2`, id, ac.OrgID).
		Scan(&fID, &title, &desc, &severity, &confidence, &endpoint, &reproduction,
			&business, &technical, &remediation, &status, &assetID, &assetName, &assetTarget,
			&scanID, &assigneeID, &assigneeName, &verifiedBy, &cve, &cwe, &cvss,
			&evidence, &refs, &first, &last, &verified)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Finding not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "finding")
		return
	}
	x = map[string]any{
		"id": fID, "title": title, "description": desc, "severity": severity, "confidence": confidence,
		"endpoint": endpoint, "reproduction": reproduction, "business_impact": business,
		"technical_impact": technical, "remediation": remediation, "status": status,
		"asset_id": assetID, "asset_name": assetName, "asset_target": assetTarget,
		"scan_id": scanID, "assigned_to": assigneeID, "assignee_name": assigneeName,
		"verified_by": verifiedBy, "cve": cve, "cwe": cwe, "cvss": cvss,
		"evidence": json.RawMessage(evidence), "references": json.RawMessage(refs),
		"first_seen": first.UTC().Format(time.RFC3339), "last_seen": last.UTC().Format(time.RFC3339),
	}
	if verified != nil {
		x["verified_at"] = verified.UTC().Format(time.RFC3339)
	}
	events, _ := s.findingEvents(r.Context(), ac.OrgID, id)
	x["events"] = events
	remediationRows, _ := s.remediationRecords(r.Context(), ac.OrgID, id)
	x["remediation_records"] = remediationRows
	evidenceRows, _ := s.evidenceList(r.Context(), ac.OrgID, id)
	x["evidence_files"] = evidenceRows
	writeJSON(w, http.StatusOK, x)
}

func (s *Server) findingEvents(rctx context.Context, orgID, findingID string) ([]map[string]any, error) {
	rows, err := s.db.Query(rctx, `
		SELECT e.id::text, e.type, e.from_value, e.to_value, e.note, u.name, e.created_at
		FROM finding_events e LEFT JOIN users u ON u.id=e.actor_id
		WHERE e.org_id=$1 AND e.finding_id=$2 ORDER BY e.created_at DESC`, orgID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, typ, note string
		var from, to, actor *string
		var created time.Time
		if err := rows.Scan(&id, &typ, &from, &to, &note, &actor, &created); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "type": typ, "from": from, "to": to, "note": note,
			"actor": actor, "created_at": created.UTC().Format(time.RFC3339)})
	}
	return out, nil
}

func (s *Server) remediationRecords(ctx context.Context, orgID, findingID string) ([]map[string]any, error) {
	rows, err := s.db.Query(ctx, `
		SELECT r.id::text, r.action, r.notes, u.name, r.performed_at, r.deadline
		FROM remediation_records r LEFT JOIN users u ON u.id=r.performed_by
		WHERE r.org_id=$1 AND r.finding_id=$2 ORDER BY r.performed_at DESC`, orgID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, action, notes string
		var actor *string
		var performed time.Time
		var deadline *time.Time
		if err := rows.Scan(&id, &action, &notes, &actor, &performed, &deadline); err != nil {
			return nil, err
		}
		m := map[string]any{"id": id, "action": action, "notes": notes, "performed_by": actor,
			"performed_at": performed.UTC().Format(time.RFC3339)}
		if deadline != nil {
			m["deadline"] = deadline.UTC().Format(time.RFC3339)
		}
		out = append(out, m)
	}
	return out, nil
}

type updateFindingRequest struct {
	Status          *string `json:"status"`
	Severity        *string `json:"severity"`
	AssignedTo      *string `json:"assigned_to"`
	Description     *string `json:"description"`
	Reproduction    *string `json:"reproduction"`
	BusinessImpact  *string `json:"business_impact"`
	TechnicalImpact *string `json:"technical_impact"`
	Remediation     *string `json:"remediation"`
	Note            string  `json:"note"`
}

func (s *Server) handleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	var req updateFindingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	id := chiURLParam(r, "findingID")
	var oldStatus, oldSeverity string
	var oldAssignee *string
	err := s.db.QueryRow(r.Context(), `SELECT status, severity, assigned_to::text FROM findings WHERE id=$1 AND org_id=$2`, id, ac.OrgID).
		Scan(&oldStatus, &oldSeverity, &oldAssignee)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Finding not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "finding")
		return
	}
	if req.Status != nil && !validFindingStatus(*req.Status) {
		s.writeValidation(w, "Unknown finding status.")
		return
	}
	if req.Severity != nil && !validSeverity(*req.Severity) {
		s.writeValidation(w, "Unknown severity.")
		return
	}
	if req.AssignedTo != nil && *req.AssignedTo != "" {
		var member bool
		_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$2)`, ac.OrgID, *req.AssignedTo).Scan(&member)
		if !member {
			s.writeValidation(w, "Assignee must be an organization member.")
			return
		}
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.dbError(w, err, "finding")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if req.Status != nil {
		_, err = tx.Exec(r.Context(), `UPDATE findings SET status=$1 WHERE id=$2 AND org_id=$3`, *req.Status, id, ac.OrgID)
		if err == nil && *req.Status != oldStatus {
			_, _ = tx.Exec(r.Context(), `INSERT INTO finding_events (org_id,finding_id,actor_id,type,from_value,to_value,note) VALUES ($1,$2,$3,'status_changed',$4,$5,$6)`,
				ac.OrgID, id, ac.UserID, oldStatus, *req.Status, truncate(req.Note, 1000))
		}
	}
	if req.Severity != nil {
		_, err = tx.Exec(r.Context(), `UPDATE findings SET severity=$1 WHERE id=$2 AND org_id=$3`, *req.Severity, id, ac.OrgID)
		if err == nil && *req.Severity != oldSeverity {
			_, _ = tx.Exec(r.Context(), `INSERT INTO finding_events (org_id,finding_id,actor_id,type,from_value,to_value,note) VALUES ($1,$2,$3,'severity_changed',$4,$5,$6)`,
				ac.OrgID, id, ac.UserID, oldSeverity, *req.Severity, truncate(req.Note, 1000))
		}
	}
	if req.AssignedTo != nil {
		assignee := *req.AssignedTo
		if assignee == "" {
			_, err = tx.Exec(r.Context(), `UPDATE findings SET assigned_to=NULL WHERE id=$1 AND org_id=$2`, id, ac.OrgID)
		} else {
			_, err = tx.Exec(r.Context(), `UPDATE findings SET assigned_to=$1 WHERE id=$2 AND org_id=$3`, assignee, id, ac.OrgID)
		}
		if err == nil {
			_, _ = tx.Exec(r.Context(), `INSERT INTO finding_events (org_id,finding_id,actor_id,type,from_value,to_value,note) VALUES ($1,$2,$3,'assigned',$4,$5,$6)`,
				ac.OrgID, id, ac.UserID, oldAssignee, assignee, truncate(req.Note, 1000))
		}
	}
	for _, field := range []struct {
		name string
		val  *string
	}{
		{"description", req.Description}, {"reproduction", req.Reproduction},
		{"business_impact", req.BusinessImpact}, {"technical_impact", req.TechnicalImpact}, {"remediation", req.Remediation},
	} {
		if field.val == nil {
			continue
		}
		if len(*field.val) > 20000 {
			s.writeValidation(w, "One of the fields is too long.")
			return
		}
		if _, err = tx.Exec(r.Context(), `UPDATE findings SET `+field.name+`=$1 WHERE id=$2 AND org_id=$3`, *field.val, id, ac.OrgID); err != nil {
			break
		}
	}
	if err != nil {
		s.dbError(w, err, "finding")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.dbError(w, err, "finding")
		return
	}
	s.audit(r, "finding.updated", "finding", id, map[string]any{"note": truncate(req.Note, 500)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleVerifyFinding(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "findingID")
	tag, err := s.db.Exec(r.Context(), `
		UPDATE findings SET status='confirmed', verified_at=now(), verified_by=$1
		WHERE id=$2 AND org_id=$3 AND status NOT IN ('false_positive')`, ac.UserID, id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "finding")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusConflict, "not_verifiable", "This finding cannot be verified in its current state.", nil)
		return
	}
	_, _ = s.db.Exec(r.Context(), `INSERT INTO finding_events (org_id,finding_id,actor_id,type,to_value) VALUES ($1,$2,$3,'verified','confirmed')`, ac.OrgID, id, ac.UserID)
	s.audit(r, "finding.verified", "finding", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type remediationRequest struct {
	Action   string `json:"action"`
	Notes    string `json:"notes"`
	Deadline string `json:"deadline"`
}

func (s *Server) handleCreateRemediation(w http.ResponseWriter, r *http.Request) {
	var req remediationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	id := chiURLParam(r, "findingID")
	req.Action = strings.TrimSpace(req.Action)
	if req.Action == "" || len(req.Action) > 500 {
		s.writeValidation(w, "Describe the remediation action.")
		return
	}
	var deadline *time.Time
	if req.Deadline != "" {
		t, err := time.Parse(time.RFC3339, req.Deadline)
		if err != nil {
			s.writeValidation(w, "deadline must be RFC 3339.")
			return
		}
		deadline = &t
	}
	var findingExists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1 AND org_id=$2)`, id, ac.OrgID).Scan(&findingExists)
	if !findingExists {
		writeError(w, http.StatusNotFound, "not_found", "Finding not found.", nil)
		return
	}
	_, err := s.db.Exec(r.Context(), `
		INSERT INTO remediation_records (org_id, finding_id, action, notes, performed_by, deadline)
		VALUES ($1,$2,$3,$4,$5,$6)`, ac.OrgID, id, req.Action, truncate(req.Notes, 5000), ac.UserID, deadline)
	if err != nil {
		s.dbError(w, err, "remediation")
		return
	}
	_, _ = s.db.Exec(r.Context(), `INSERT INTO finding_events (org_id,finding_id,actor_id,type,note) VALUES ($1,$2,$3,'remediation',$4)`, ac.OrgID, id, ac.UserID, truncate(req.Action, 1000))
	s.audit(r, "finding.remediation_recorded", "finding", id, nil)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

func (s *Server) evidenceList(rctx context.Context, orgID, findingID string) ([]map[string]any, error) {
	rows, err := s.db.Query(rctx, `
		SELECT e.id::text, e.filename, e.content_type, e.size_bytes, e.sha256, e.created_at, u.name
		FROM evidence e LEFT JOIN users u ON u.id=e.uploaded_by
		WHERE e.org_id=$1 AND e.finding_id=$2 ORDER BY e.created_at DESC`, orgID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, ct, sha string
		var size int64
		var created time.Time
		var uploader *string
		if err := rows.Scan(&id, &name, &ct, &size, &sha, &created, &uploader); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "filename": name, "content_type": ct, "size_bytes": size,
			"sha256": sha, "uploaded_by": uploader, "created_at": created.UTC().Format(time.RFC3339)})
	}
	return out, nil
}

func (s *Server) handleListEvidence(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "findingID")
	out, err := s.evidenceList(r.Context(), ac.OrgID, id)
	if err != nil {
		s.dbError(w, err, "evidence")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

var allowedEvidence = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/webp": true, "image/gif": true,
	"application/pdf": true, "text/plain": true, "application/json": true, "text/csv": true,
	"application/octet-stream": true,
}

func (s *Server) handleUploadEvidence(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	findingID := chiURLParam(r, "findingID")
	var exists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1 AND org_id=$2)`, findingID, ac.OrgID).Scan(&exists)
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "Finding not found.", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 26<<20)
	if err := r.ParseMultipartForm(26 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_upload", "The upload is invalid or exceeds 25 MB.", nil)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file_required", "Attach a file using the 'file' field.", nil)
		return
	}
	defer file.Close()
	if header.Size <= 0 || header.Size > 25<<20 {
		s.writeValidation(w, "Evidence must be between 1 byte and 25 MB.")
		return
	}
	head := make([]byte, 512)
	n, _ := io.ReadFull(file, head)
	head = head[:n]
	ct := http.DetectContentType(head)
	ext := strings.ToLower(filepath.Ext(header.Filename))
	switch ext {
	case ".png":
		ct = "image/png"
	case ".jpg", ".jpeg":
		ct = "image/jpeg"
	case ".webp":
		ct = "image/webp"
	case ".gif":
		ct = "image/gif"
	case ".pdf":
		ct = "application/pdf"
	case ".txt", ".log":
		ct = "text/plain"
	case ".json":
		ct = "application/json"
	case ".csv":
		ct = "text/csv"
	}
	if !allowedEvidence[ct] {
		s.writeValidation(w, "Unsupported evidence type. Use PNG, JPEG, WEBP, GIF, PDF, TXT, LOG, JSON or CSV.")
		return
	}
	if ct == "application/pdf" && !strings.HasPrefix(string(head), "%PDF") {
		s.writeValidation(w, "The file does not look like a valid PDF.")
		return
	}
	if strings.HasPrefix(ct, "image/") {
		switch {
		case ct == "image/png" && !strings.HasPrefix(string(head), "\x89PNG"):
			s.writeValidation(w, "The file does not look like a valid PNG.")
			return
		case ct == "image/jpeg" && !strings.HasPrefix(string(head), "\xff\xd8"):
			s.writeValidation(w, "The file does not look like a valid JPEG.")
			return
		case ct == "image/gif" && !strings.HasPrefix(string(head), "GIF8"):
			s.writeValidation(w, "The file does not look like a valid GIF.")
			return
		case ct == "image/webp" && !(strings.HasPrefix(string(head), "RIFF") && strings.Contains(string(head[:min(len(head), 16)]), "WEBP")):
			s.writeValidation(w, "The file does not look like a valid WEBP.")
			return
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeError(w, http.StatusInternalServerError, "upload_failed", "Could not read the uploaded file.", nil)
		return
	}
	hasher := sha256.New()
	tee := io.TeeReader(io.LimitReader(file, header.Size), hasher)
	storageKey := storage.NewKey("evidence/"+ac.OrgID+"/"+findingID, ext)
	if err := s.store.Put(r.Context(), storageKey, tee, header.Size, ct); err != nil {
		s.log.Error("evidence storage failed", "error", err)
		writeError(w, http.StatusInternalServerError, "storage_failed", "Evidence could not be stored.", nil)
		return
	}
	sha := hex.EncodeToString(hasher.Sum(nil))
	filename := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	if len(filename) > 180 {
		filename = filename[:180]
	}
	var id string
	err = s.db.QueryRow(r.Context(), `
		INSERT INTO evidence (org_id, finding_id, filename, content_type, size_bytes, storage_key, sha256, uploaded_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text`,
		ac.OrgID, findingID, filename, ct, header.Size, storageKey, sha, ac.UserID).Scan(&id)
	if err != nil {
		_ = s.store.Delete(r.Context(), storageKey)
		s.dbError(w, err, "evidence")
		return
	}
	s.audit(r, "evidence.uploaded", "evidence", id, map[string]any{"finding_id": findingID, "filename": filename, "size": header.Size})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "filename": filename, "sha256": sha})
}

func (s *Server) handleDownloadEvidence(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "evidenceID")
	var key, filename, ct string
	var size int64
	err := s.db.QueryRow(r.Context(), `
		SELECT e.storage_key, e.filename, e.content_type, e.size_bytes
		FROM evidence e JOIN findings f ON f.id=e.finding_id
		WHERE e.id=$1 AND e.org_id=$2 AND f.org_id=$2`, id, ac.OrgID).Scan(&key, &filename, &ct, &size)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Evidence not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "evidence")
		return
	}
	rc, actualSize, storedCT, err := s.store.Open(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusNotFound, "evidence_missing", "Evidence object is no longer available.", nil)
		return
	}
	defer rc.Close()
	if storedCT != "" && storedCT != "application/octet-stream" {
		ct = storedCT
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeFilename(filename)))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", actualSize))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
	s.audit(r, "evidence.downloaded", "evidence", id, nil)
}

func sanitizeFilename(s string) string {
	s = filepath.Base(s)
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == '"' || r == '\\' || r == '/' {
			return '_'
		}
		return r
	}, s)
	if s == "" || s == "." {
		return "evidence"
	}
	return s
}
