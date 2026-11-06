package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

type apiError struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details,omitempty"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	e.Error.Details = details
	writeJSON(w, status, e)
}

func chiURLParam(r *http.Request, key string) string { return chi.URLParam(r, key) }

type page struct {
	Items   any `json:"items"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

func pagination(r *http.Request) (int, int) {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if p < 1 {
		p = 1
	}
	pp, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if pp < 1 {
		pp = 25
	}
	if pp > 100 {
		pp = 100
	}
	return p, pp
}

func queryInt(r *http.Request, key string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil {
		return def
	}
	return v
}

func sortClause(r *http.Request, allowed map[string]string, def string) string {
	key := r.URL.Query().Get("sort")
	col, ok := allowed[key]
	if !ok {
		return def
	}
	order := strings.ToLower(r.URL.Query().Get("order"))
	if order != "asc" {
		order = "desc"
	}
	return col + " " + order
}

func isNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func (s *Server) audit(r *http.Request, action, resourceType, resourceID string, metadata map[string]any) {
	ac := actor(r)
	var userID *string
	var orgID *string
	if ac != nil {
		userID = &ac.UserID
		orgID = &ac.OrgID
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	body, _ := json.Marshal(metadata)
	meta := r.RemoteAddr
	if ac == nil {
		meta = r.RemoteAddr
	}
	_, err := s.db.Exec(r.Context(), `
		INSERT INTO audit_events (org_id, actor_user_id, action, resource_type, resource_id, metadata, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		orgID, userID, action, resourceType, resourceID, body, meta, truncate(r.UserAgent(), 400))
	if err != nil {
		s.log.Error("audit write failed", "action", action, "error", err)
	}
}

func (s *Server) auditSystem(ctx context.Context, orgID, action, resourceType, resourceID string, metadata map[string]any) {
	body, _ := json.Marshal(metadata)
	_, err := s.db.Exec(ctx, `
		INSERT INTO audit_events (org_id, action, resource_type, resource_id, metadata)
		VALUES (NULLIF($1,'')::uuid,$2,$3,$4,$5)`, orgID, action, resourceType, resourceID, body)
	if err != nil {
		s.log.Error("system audit write failed", "action", action, "error", err)
	}
}

func (s *Server) notify(ctx context.Context, orgID string, userID *string, typ, title, body, link string) {
	_, err := s.db.Exec(ctx, `
		INSERT INTO notifications (org_id, user_id, type, title, body, link)
		VALUES ($1,$2,$3,$4,$5,$6)`, orgID, userID, typ, title, body, link)
	if err != nil {
		s.log.Error("notification write failed", "error", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func ptr[T any](v T) *T { return &v }

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

func validFindingStatus(s string) bool {
	switch s {
	case "open", "confirmed", "in_progress", "fixed", "retest_required", "accepted_risk", "false_positive":
		return true
	}
	return false
}

func validScanStatus(s string) bool {
	switch s {
	case "pending", "queued", "initializing", "running", "completed", "failed", "cancelled":
		return true
	}
	return false
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func severityWeight(sev string) float64 {
	switch sev {
	case "critical":
		return 12
	case "high":
		return 6
	case "medium":
		return 3
	case "low":
		return 1
	case "info":
		return 0.2
	}
	return 0
}

func postureScore(open map[string]int, assets int) int {
	if assets <= 0 {
		return 100
	}
	total := 0.0
	for sev, n := range open {
		total += severityWeight(sev) * float64(n)
	}
	penalty := total / float64(assets)
	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return int(score)
}

func parseTimePtr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func commaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) orgSetting(ctx context.Context, orgID string) (emergency bool, retention int, err error) {
	err = s.db.QueryRow(ctx, `SELECT emergency_stop, retention_days FROM organizations WHERE id=$1`, orgID).Scan(&emergency, &retention)
	return
}

func (s *Server) writeValidation(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusUnprocessableEntity, "validation_error", msg, nil)
}

func (s *Server) dbError(w http.ResponseWriter, err error, resource string) {
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("%s not found.", resource), nil)
		return
	}
	s.log.Error("database error", "resource", resource, "error", err)
	writeError(w, http.StatusInternalServerError, "database_error", "The request could not be completed.", nil)
}
