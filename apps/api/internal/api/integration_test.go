package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kingmalhare/api/internal/config"
	"github.com/kingmalhare/api/internal/db"
	"github.com/kingmalhare/api/internal/scanner"
	"github.com/kingmalhare/api/internal/security"
	"github.com/kingmalhare/api/internal/storage"
	"github.com/redis/go-redis/v9"
)

// TestEndToEndTenantIsolation exercises the real HTTP stack against PostgreSQL
// and Redis. It is skipped unless TEST_DATABASE_URL is set to a disposable
// database. The test truncates tenants, so never point it at real data.
func TestEndToEndTenantIsolation(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		t.Skip("set TEST_DATABASE_URL and TEST_REDIS_URL to run the API integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer pool.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := db.Migrate(ctx, pool, logger); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE organizations, users CASCADE`); err != nil {
		t.Fatalf("clean test data: %v", err)
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("redis url: %v", err)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()
	cipher, err := security.NewCredentialCipher("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.New("local", t.TempDir(), "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Env: "test", AppOrigin: "http://localhost:5173", SessionPepper: "test-pepper",
		SessionTTL: time.Hour, CredentialKey: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		WorkerToken: "test-worker", QueueKey: "km:test:jobs:" + time.Now().Format("150405.000000"),
		EventsChan: "km:test:events", ScanStale: 30 * time.Minute, RegistrationEnabled: true,
		AllowPrivateTargets: true,
		StorageDriver:       "local", DataRetention: 365,
	}
	queue := scanner.NewQueue(rdb, cfg.QueueKey, cfg.EventsChan)
	srv := NewServer(cfg, pool, rdb, queue, store, cipher, logger)
	ts := httptest.NewServer(srv.PublicRouter())
	defer ts.Close()

	clientA := newTestClient(t)
	clientB := newTestClient(t)

	status, meA := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/auth/register", map[string]any{
		"org_name": "Org A", "name": "Analyst A", "email": "a@example.test", "password": "CorrectHorse9Battery",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("register A status = %d", status)
	}
	csrfA := stringField(meA, "csrf_token")
	if csrfA == "" {
		t.Fatal("registration did not return a CSRF token")
	}
	orgA := meA["org"].(map[string]any)
	if orgA["name"] != "Org A" {
		t.Fatalf("unexpected organization: %v", orgA)
	}

	// CSRF is mandatory for cookie-authenticated mutations.
	status, _ = doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/assets", map[string]any{
		"name": "No CSRF", "type": "website", "target": "http://127.0.0.1:9",
	}, "")
	if status != http.StatusForbidden {
		t.Fatalf("mutation without CSRF returned %d, want 403", status)
	}

	status, assetBody := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/assets", map[string]any{
		"name": "Local lab", "type": "website", "target": "http://127.0.0.1:9", "environment": "lab",
	}, csrfA)
	if status != http.StatusCreated {
		t.Fatalf("create asset status = %d body=%v", status, assetBody)
	}
	assetID := stringField(assetBody, "id")

	// Scan without an authorization is rejected.
	status, scanBody := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/scans", map[string]any{
		"asset_id": assetID, "authorization_id": "11111111-2222-3333-4444-555555555555",
		"scanner": "http-baseline", "category": "web",
	}, csrfA)
	if status != http.StatusForbidden {
		t.Fatalf("scan without authorization status = %d body=%v", status, scanBody)
	}

	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	status, authBody := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/assets/"+assetID+"/authorizations", map[string]any{
		"reference": "TEST-AUTH-1", "approved_by_name": "Owner A", "expires_at": expires, "allow_private": true,
	}, csrfA)
	if status != http.StatusCreated {
		t.Fatalf("create authorization status = %d body=%v", status, authBody)
	}
	authID := stringField(authBody, "id")

	status, scanBody = doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/scans", map[string]any{
		"asset_id": assetID, "authorization_id": authID, "scanner": "http-baseline", "category": "web",
	}, csrfA)
	if status != http.StatusAccepted {
		t.Fatalf("queue scan status = %d body=%v", status, scanBody)
	}
	scanID := stringField(scanBody, "id")

	status, detail := doJSON(t, clientA, http.MethodGet, ts.URL+"/api/v1/scans/"+scanID, nil, "")
	if status != http.StatusOK {
		t.Fatalf("get scan status = %d", status)
	}
	if detail["status"] != "queued" {
		t.Fatalf("scan status = %v, want queued", detail["status"])
	}

	// API keys provide scoped bearer automation without CSRF.
	status, keyBody := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/api-keys", map[string]any{
		"name": "Automation", "scopes": []string{"assets:read", "assets:write", "scans:read", "scans:write", "findings:read"},
	}, csrfA)
	if status != http.StatusCreated {
		t.Fatalf("create api key status = %d body=%v", status, keyBody)
	}
	apiToken := stringField(keyBody, "token")
	if apiToken == "" {
		t.Fatal("api key response did not include a token")
	}
	bearer := &http.Client{Timeout: 30 * time.Second}
	status, bearerAssets := doJSONBearer(t, bearer, http.MethodGet, ts.URL+"/api/v1/assets", nil, apiToken)
	if status != http.StatusOK {
		t.Fatalf("bearer asset list status = %d body=%v", status, bearerAssets)
	}
	status, bearerScan := doJSONBearer(t, bearer, http.MethodPost, ts.URL+"/api/v1/scans", map[string]any{
		"asset_id": assetID, "authorization_id": authID, "scanner": "http-baseline", "category": "web",
	}, apiToken)
	if status != http.StatusAccepted {
		t.Fatalf("bearer scan status = %d body=%v", status, bearerScan)
	}
	bearerScanID := stringField(bearerScan, "id")
	status, bearerDetail := doJSONBearer(t, bearer, http.MethodGet, ts.URL+"/api/v1/scans/"+bearerScanID, nil, apiToken)
	if status != http.StatusOK || bearerDetail["status"] != "queued" {
		t.Fatalf("bearer scan detail status = %d body=%v", status, bearerDetail)
	}

	// A read-only key cannot perform a write.
	status, readKeyBody := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/api-keys", map[string]any{
		"name": "Read only", "scopes": []string{"assets:read"},
	}, csrfA)
	if status != http.StatusCreated {
		t.Fatalf("create read-only key status = %d body=%v", status, readKeyBody)
	}
	status, _ = doJSONBearer(t, bearer, http.MethodPost, ts.URL+"/api/v1/assets", map[string]any{
		"name": "Forbidden write", "type": "website", "target": "http://127.0.0.1:9",
	}, stringField(readKeyBody, "token"))
	if status != http.StatusForbidden {
		t.Fatalf("read-only key write status = %d, want 403", status)
	}

	// Tenant B cannot read tenant A's asset or scan.
	status, meB := doJSON(t, clientB, http.MethodPost, ts.URL+"/api/v1/auth/register", map[string]any{
		"org_name": "Org B", "name": "Analyst B", "email": "b@example.test", "password": "CorrectHorse9Battery",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("register B status = %d body=%v", status, meB)
	}
	csrfB := stringField(meB, "csrf_token")
	status, _ = doJSON(t, clientB, http.MethodGet, ts.URL+"/api/v1/assets/"+assetID, nil, "")
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant asset read status = %d, want 404", status)
	}
	status, _ = doJSON(t, clientB, http.MethodGet, ts.URL+"/api/v1/scans/"+scanID, nil, "")
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant scan read status = %d, want 404", status)
	}
	status, listB := doJSON(t, clientB, http.MethodGet, ts.URL+"/api/v1/assets", nil, "")
	if status != http.StatusOK {
		t.Fatalf("tenant B asset list status = %d", status)
	}
	items, _ := listB["items"].([]any)
	if len(items) != 0 {
		t.Fatalf("tenant B sees %d assets", len(items))
	}
	_ = csrfB

	// Revoking the authorization blocks new scans.
	status, _ = doJSON(t, clientA, http.MethodPatch, ts.URL+"/api/v1/authorizations/"+authID, map[string]any{"status": "revoked"}, csrfA)
	if status != http.StatusOK {
		t.Fatalf("revoke authorization status = %d", status)
	}
	status, revokedScan := doJSON(t, clientA, http.MethodGet, ts.URL+"/api/v1/scans/"+scanID, nil, "")
	if status != http.StatusOK || revokedScan["status"] != "cancelled" {
		t.Fatalf("queued scan should be cancelled after revocation, status=%d body=%v", status, revokedScan["status"])
	}
	status, body := doJSON(t, clientA, http.MethodPost, ts.URL+"/api/v1/scans", map[string]any{
		"asset_id": assetID, "authorization_id": authID, "scanner": "http-baseline", "category": "web",
	}, csrfA)
	if status != http.StatusForbidden {
		t.Fatalf("scan with revoked authorization status = %d body=%v", status, body)
	}

	// The queued job is a real Redis job.
	if depth, err := queue.QueueDepth(ctx); err != nil || depth < 1 {
		t.Fatalf("expected queued job in Redis, depth=%d err=%v", depth, err)
	}
	if _, err := rdb.Del(ctx, cfg.QueueKey).Result(); err != nil {
		t.Logf("cleanup queue: %v", err)
	}
}

func newTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any, csrf string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var decoded map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return resp.StatusCode, decoded
}

func doJSONBearer(t *testing.T, client *http.Client, method, url string, body any, token string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var decoded map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return resp.StatusCode, decoded
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
