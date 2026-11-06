package api

import "testing"

func TestPostureScore(t *testing.T) {
	if got := postureScore(map[string]int{}, 0); got != 100 {
		t.Fatalf("empty organization score = %d, want 100", got)
	}
	if got := postureScore(map[string]int{"critical": 1}, 1); got != 88 {
		t.Fatalf("one critical score = %d, want 88", got)
	}
	if got := postureScore(map[string]int{"critical": 20}, 1); got != 0 {
		t.Fatalf("score should floor at 0, got %d", got)
	}
}

func TestUUIDValidation(t *testing.T) {
	if !validUUID("11111111-2222-3333-4444-555555555555") {
		t.Fatal("valid UUID rejected")
	}
	for _, bad := range []string{"", "not-a-uuid", "11111111-2222-3333-4444-55555555555", "gggggggg-2222-3333-4444-555555555555"} {
		if validUUID(bad) {
			t.Errorf("invalid UUID accepted: %s", bad)
		}
	}
}

func TestStatusAllowlists(t *testing.T) {
	if !validSeverity("critical") || validSeverity("urgent") {
		t.Fatal("severity allowlist incorrect")
	}
	if !validFindingStatus("accepted_risk") || validFindingStatus("deleted") {
		t.Fatal("finding status allowlist incorrect")
	}
}

func TestFingerprintStable(t *testing.T) {
	a := fingerprint("nuclei", "Exposed .env", "https://x/.env", "", "CWE-538")
	b := fingerprint("nuclei", "Exposed .env", "https://x/.env", "", "CWE-538")
	c := fingerprint("nuclei", "Exposed .env", "https://x/.env", "", "CWE-200")
	if a != b {
		t.Fatal("fingerprint is not stable")
	}
	if a == c {
		t.Fatal("fingerprint does not include CWE")
	}
	if len(a) != 64 {
		t.Fatalf("fingerprint length = %d", len(a))
	}
}
