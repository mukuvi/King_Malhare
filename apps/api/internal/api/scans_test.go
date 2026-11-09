package api

import "testing"

func TestAssetSupportsExpandedScanners(t *testing.T) {
	cases := []struct {
		asset   string
		scanner string
		want    bool
	}{
		{"website", "ffuf", true},
		{"web_app", "whatweb", true},
		{"api", "schemathesis", true},
		{"graphql_api", "httpx", true},
		{"website", "burp", true},
		{"website", "sslyze", true},
		{"server", "sslyze", true},
		{"container", "grype", true},
		{"server", "syft", true},
		{"internal", "semgrep", true},
		{"container", "gitleaks", true},
		{"server", "tfsec", true},
		{"ip", "ffuf", false},
		{"cloud", "grype", false},
		{"container", "httpx", false},
	}
	for _, tc := range cases {
		if got := assetSupportsScanner(tc.asset, tc.scanner); got != tc.want {
			t.Errorf("assetSupportsScanner(%q, %q) = %v, want %v", tc.asset, tc.scanner, got, tc.want)
		}
	}
}
