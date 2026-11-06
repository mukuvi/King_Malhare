package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var cveRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,7}$`)

type intelResult struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	CVSS        *float64 `json:"cvss"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	Severity    string   `json:"severity"`
	CWE         []string `json:"cwe"`
	References  []string `json:"references"`
	Published   string   `json:"published,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	Affected    []string `json:"affected"`
	Exploited   bool     `json:"known_exploited"`
	Source      string   `json:"source"`
	Cached      bool     `json:"cached"`
	Stale       bool     `json:"stale"`
	FetchedAt   string   `json:"fetched_at,omitempty"`
	CVSSVersion string   `json:"cvss_version,omitempty"`
}

func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(chiURLParam(r, "cveID")))
	if !cveRe.MatchString(id) {
		s.writeValidation(w, "CVE id must look like CVE-2024-12345.")
		return
	}
	var raw []byte
	var fetched time.Time
	cached := false
	err := s.db.QueryRow(r.Context(), `SELECT payload, fetched_at FROM cve_cache WHERE cve_id=$1`, id).Scan(&raw, &fetched)
	if err == nil {
		cached = true
		if time.Since(fetched) < 7*24*time.Hour {
			result := normalizeCVE(id, raw)
			result.Cached = true
			result.FetchedAt = fetched.UTC().Format(time.RFC3339)
			writeJSON(w, http.StatusOK, result)
			return
		}
	}
	fresh, fetchErr := s.fetchCVE(r.Context(), id)
	if fetchErr == nil {
		result := normalizeCVE(id, fresh)
		result.Source = "CIRCL CVE Search"
		result.Cached = false
		if _, err := s.db.Exec(r.Context(), `
			INSERT INTO cve_cache (cve_id, payload, fetched_at) VALUES ($1,$2,now())
			ON CONFLICT (cve_id) DO UPDATE SET payload=excluded.payload, fetched_at=now()`, id, fresh); err != nil {
			s.log.Warn("cve cache write failed", "error", err)
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	if cached {
		result := normalizeCVE(id, raw)
		result.Cached = true
		result.Stale = true
		result.FetchedAt = fetched.UTC().Format(time.RFC3339)
		result.Source = "CIRCL CVE Search (stale cache)"
		writeJSON(w, http.StatusOK, result)
		return
	}
	s.log.Warn("cve lookup failed", "cve", id, "error", fetchErr)
	writeError(w, http.StatusBadGateway, "intel_unavailable", "Vulnerability intelligence is temporarily unavailable and no cached record exists.", map[string]any{"detail": fetchErr.Error()})
}

func (s *Server) fetchCVE(ctx context.Context, id string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	url := strings.TrimRight(s.cfg.VulnIntelURL, "/") + "/api/cve/" + id
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "KingMalhare/1.0 vulnerability-intel")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("CVE not found at intelligence source")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intelligence source returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("intelligence source returned invalid JSON")
	}
	if len(probe) == 0 {
		return nil, errors.New("empty vulnerability record")
	}
	return body, nil
}

func normalizeCVE(id string, raw []byte) intelResult {
	out := intelResult{ID: id, CWE: []string{}, References: []string{}, Affected: []string{}, Source: "CIRCL CVE Search"}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return out
	}
	if v, ok := m["id"].(string); ok && v != "" {
		out.ID = strings.ToUpper(v)
	}
	out.Summary = stringValue(m["summary"])
	if out.Summary == "" {
		if containers, ok := m["containers"].(map[string]any); ok {
			if cna, ok := containers["cna"].(map[string]any); ok {
				if descriptions, ok := cna["descriptions"].([]any); ok {
					for _, d := range descriptions {
						if dm, ok := d.(map[string]any); ok && (dm["lang"] == "en" || dm["lang"] == nil) {
							out.Summary = stringValue(dm["value"])
							break
						}
					}
				}
			}
		}
	}
	if out.Summary == "" {
		out.Summary = "No description was published for this record."
	}
	for _, key := range []string{"cvss3", "cvss", "cvssV3", "cvssV2"} {
		if f, ok := numberValue(m[key]); ok {
			out.CVSS = &f
			switch key {
			case "cvss3":
				out.CVSSVersion = "3.x"
			case "cvss":
				out.CVSSVersion = "2.0"
			default:
				out.CVSSVersion = key
			}
			break
		}
	}
	if out.CVSS != nil {
		out.Severity = severityFromCVSS(*out.CVSS)
	}
	if sev := strings.ToLower(stringValue(m["severity"])); sev != "" {
		out.Severity = sev
	}
	if out.Severity == "" {
		out.Severity = "unknown"
	}
	if v := stringValue(m["cvss-vector"]); v != "" {
		out.CVSSVector = v
	}
	cweVal := m["cwe"]
	switch x := cweVal.(type) {
	case string:
		if x != "" {
			out.CWE = []string{x}
		}
	case []any:
		for _, item := range x {
			if str, ok := item.(string); ok && str != "" {
				out.CWE = append(out.CWE, str)
			}
		}
	}
	switch refs := m["references"].(type) {
	case []any:
		for _, ref := range refs {
			if str, ok := ref.(string); ok {
				out.References = append(out.References, str)
			}
		}
	case []string:
		out.References = refs
	}
	if out.References == nil {
		out.References = []string{}
	}
	out.Published = stringValue(m["Published"])
	if out.Published == "" {
		out.Published = stringValue(m["published"])
	}
	out.Modified = stringValue(m["Modified"])
	if out.Modified == "" {
		out.Modified = stringValue(m["modified"])
	}
	switch vc := m["vulnerable_configuration"].(type) {
	case []any:
		for _, item := range vc {
			switch x := item.(type) {
			case string:
				out.Affected = append(out.Affected, x)
			case map[string]any:
				if title := stringValue(x["title"]); title != "" {
					out.Affected = append(out.Affected, title)
				}
			}
		}
	}
	if len(out.Affected) > 40 {
		out.Affected = out.Affected[:40]
	}
	if b, ok := m["exploited"].(bool); ok {
		out.Exploited = b
	}
	return out
}

func severityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func numberValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func (s *Server) handleCWEs(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT cwe_id, name, description, category FROM cwe_catalog ORDER BY cwe_id`)
	if err != nil {
		s.dbError(w, err, "CWE catalogue")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, desc, category string
		if err := rows.Scan(&id, &name, &desc, &category); err != nil {
			s.dbError(w, err, "CWE")
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "description": desc, "category": category})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleRecentIntel(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	_ = ac
	limit := queryInt(r, "limit", 20)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(r.Context(), `SELECT cve_id, payload, fetched_at FROM cve_cache ORDER BY fetched_at DESC LIMIT $1`, limit)
	if err != nil {
		s.dbError(w, err, "vulnerability intelligence")
		return
	}
	defer rows.Close()
	items := []intelResult{}
	for rows.Next() {
		var id string
		var raw []byte
		var fetched time.Time
		if err := rows.Scan(&id, &raw, &fetched); err != nil {
			continue
		}
		res := normalizeCVE(id, raw)
		res.Cached = true
		res.FetchedAt = fetched.UTC().Format(time.RFC3339)
		items = append(items, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
