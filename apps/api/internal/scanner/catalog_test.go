package scanner

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestNormalizeTargetWeb(t *testing.T) {
	got, err := NormalizeTarget("web_app", "example.com/path?q=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/path?q=1" {
		t.Fatalf("unexpected normalization: %s", got)
	}
	if _, err := NormalizeTarget("api", "http://user:pass@example.com"); err == nil {
		t.Fatal("URL with credentials accepted")
	}
	if _, err := NormalizeTarget("api", "ftp://example.com"); err == nil {
		t.Fatal("non-HTTP scheme accepted")
	}
}

func TestMetadataTargetsAlwaysRejected(t *testing.T) {
	for _, target := range []string{"169.254.169.254", "http://169.254.169.254/latest/meta-data", "http://metadata.google.internal/"} {
		assetType := "ip"
		if strings.HasPrefix(target, "http") {
			assetType = "web_app"
		}
		if _, err := NormalizeTarget(assetType, target); err == nil {
			t.Errorf("metadata target accepted: %s", target)
		}
	}
	for _, cidr := range []string{"169.254.0.0/16", "0.0.0.0/0"} {
		if _, err := NormalizeTarget("network", cidr); err == nil {
			t.Errorf("network %s should be rejected", cidr)
		}
	}
}

func TestResolvePrivatePolicy(t *testing.T) {
	if _, err := ResolveAndAuthorize(context.Background(), "ip", "127.0.0.1", false); err == nil {
		t.Fatal("loopback allowed without private permission")
	}
	ips, err := ResolveAndAuthorize(context.Background(), "ip", "127.0.0.1", true)
	if err != nil {
		t.Fatalf("loopback rejected with permission: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("unexpected resolution: %v", ips)
	}
	if _, err := ResolveAndAuthorize(context.Background(), "ip", "169.254.169.254", true); err == nil {
		t.Fatal("metadata IP allowed even with private permission")
	}
}

func TestValidateParamsAllowlist(t *testing.T) {
	config, err := ValidateParams("nuclei", map[string]any{
		"severity":   []any{"high", "critical"},
		"rate_limit": float64(30),
	})
	if err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	if config["rate_limit"] != float64(30) {
		t.Fatalf("rate limit not preserved: %v", config["rate_limit"])
	}
	if _, err := ValidateParams("nuclei", map[string]any{"template_path": "/tmp/evil"}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
	if _, err := ValidateParams("nuclei", map[string]any{"rate_limit": float64(9999)}); err == nil {
		t.Fatal("out-of-range parameter accepted")
	}
	if _, err := ValidateParams("nmap", map[string]any{"ports": "everything"}); err == nil {
		t.Fatal("invalid enum accepted")
	}
	if _, err := ValidateParams("sqlmap", map[string]any{"dump": true}); err == nil {
		t.Fatal("data dump option accepted")
	}
}

func TestIntrusiveClassification(t *testing.T) {
	if !IsIntrusive("sqlmap", nil) {
		t.Fatal("sqlmap should be intrusive")
	}
	if !IsIntrusive("auth-baseline", nil) {
		t.Fatal("auth-baseline should be intrusive")
	}
	if IsIntrusive("nuclei", nil) {
		t.Fatal("nuclei default profile should be non-intrusive")
	}
	if !IsIntrusive("zap", map[string]any{"mode": "active"}) {
		t.Fatal("zap active mode should be intrusive")
	}
	if !IsIntrusive("burp", map[string]any{"mode": "audit"}) {
		t.Fatal("burp audit mode should be intrusive")
	}
	if IsIntrusive("burp", map[string]any{"mode": "crawl"}) {
		t.Fatal("burp crawl mode should be non-intrusive")
	}
	if !IsIntrusive("schemathesis", nil) {
		t.Fatal("schemathesis should require intrusive approval")
	}
}

func TestExpandedScannerCatalog(t *testing.T) {
	for _, name := range []string{"burp", "ffuf", "whatweb", "wafw00f", "httpx", "subfinder", "sslyze", "grype", "semgrep", "gitleaks", "tfsec", "syft", "schemathesis"} {
		meta, ok := Find(name)
		if !ok {
			t.Fatalf("scanner %s missing from catalog", name)
		}
		if meta.Label == "" || meta.Category == "" || meta.Description == "" {
			t.Fatalf("scanner %s has incomplete metadata", name)
		}
	}
	params, err := ValidateParams("ffuf", map[string]any{"wordlist": "small", "threads": float64(4)})
	if err != nil {
		t.Fatalf("valid ffuf params rejected: %v", err)
	}
	if params["wordlist"] != "small" {
		t.Fatalf("ffuf wordlist not preserved: %v", params["wordlist"])
	}
	if _, err := ValidateParams("grype", map[string]any{"severity": []any{"critical", "unknown"}}); err == nil {
		t.Fatal("invalid grype severity accepted")
	}
}

func TestNetworkTargetValidation(t *testing.T) {
	if err := ValidateNetworkPolicy("10.0.0.0/16", false); err == nil {
		t.Fatal("private network accepted without permission")
	}
	if err := ValidateNetworkPolicy("10.0.0.0/16", true); err != nil {
		t.Fatalf("private network rejected with permission: %v", err)
	}
	if err := ValidateNetworkPolicy("169.254.0.0/16", true); err == nil {
		t.Fatal("metadata network accepted")
	}
	if err := ValidateNetworkPolicy("8.8.8.8", false); err != nil {
		t.Fatalf("public IP rejected: %v", err)
	}
	if err := ValidateNetworkPolicy("0.0.0.0/0", false); err == nil {
		t.Fatal("default route accepted")
	}
}
