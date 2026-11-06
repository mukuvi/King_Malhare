package api

import (
	"fmt"
	"net/http"
	"time"
)

// handleMetrics exposes aggregate operational metrics on the internal listener
// only. It deliberately contains no tenant-identifying labels.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var assets, findingsOpen, scansActive, scans24h, scansFailed24h, scansCompleted int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM assets WHERE status='active'`).Scan(&assets)
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM findings WHERE status NOT IN ('fixed','false_positive','accepted_risk')`).Scan(&findingsOpen)
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM scans WHERE status IN ('pending','queued','initializing','running')`).Scan(&scansActive)
	_ = s.db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status='failed') FROM scans WHERE created_at > now() - interval '24 hours'`).Scan(&scans24h, &scansFailed24h)
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM scans WHERE status='completed'`).Scan(&scansCompleted)
	depth, _ := s.queue.QueueDepth(ctx)
	heartbeats, _ := s.queue.Heartbeats(ctx)
	workerOnline := 0
	for _, hb := range heartbeats {
		if at, ok := hb["at"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, at); err == nil && time.Since(parsed) < 90*time.Second {
				workerOnline = 1
				break
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "# HELP km_api_up API process liveness.\n# TYPE km_api_up gauge\nkm_api_up 1\n")
	fmt.Fprintf(w, "# HELP km_api_uptime_seconds API process uptime.\n# TYPE km_api_uptime_seconds gauge\nkm_api_uptime_seconds %.0f\n", time.Since(s.start).Seconds())
	fmt.Fprintf(w, "# HELP km_assets_active Active registered assets across all organizations.\n# TYPE km_assets_active gauge\nkm_assets_active %d\n", assets)
	fmt.Fprintf(w, "# HELP km_findings_open Open findings across all organizations.\n# TYPE km_findings_open gauge\nkm_findings_open %d\n", findingsOpen)
	fmt.Fprintf(w, "# HELP km_scans_active Assessments queued or running.\n# TYPE km_scans_active gauge\nkm_scans_active %d\n", scansActive)
	fmt.Fprintf(w, "# HELP km_scans_total_24h Assessments created in the last 24 hours.\n# TYPE km_scans_total_24h gauge\nkm_scans_total_24h %d\n", scans24h)
	fmt.Fprintf(w, "# HELP km_scans_failed_24h Assessments failed in the last 24 hours.\n# TYPE km_scans_failed_24h gauge\nkm_scans_failed_24h %d\n", scansFailed24h)
	fmt.Fprintf(w, "# HELP km_scans_completed_total Completed assessments.\n# TYPE km_scans_completed_total counter\nkm_scans_completed_total %d\n", scansCompleted)
	fmt.Fprintf(w, "# HELP km_scan_queue_depth Jobs waiting in the scan queue.\n# TYPE km_scan_queue_depth gauge\nkm_scan_queue_depth %d\n", depth)
	fmt.Fprintf(w, "# HELP km_worker_online Whether a scanner worker heartbeat is fresh.\n# TYPE km_worker_online gauge\nkm_worker_online %d\n", workerOnline)
}
