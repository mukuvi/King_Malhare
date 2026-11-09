package report

import (
	"bytes"
	"strings"
	"testing"
)

func sampleData() *Data {
	cvss := 9.8
	return &Data{
		ID:           "11111111-1111-1111-1111-111111111111",
		Title:        "Q3 External Assessment",
		ClientName:   "Acme Security",
		AssessorName: "Alex Mwangi",
		OrgName:      "King Malhare",
		Scope:        []ScopeItem{{Name: "Portal", Target: "https://portal.example.com", Type: "web_app", Environment: "production", AuthRef: "SEC-2026-01", Approver: "Jane Doe", Expires: "31 December 2026"}},
		Scan:         &ScanInfo{ID: "scan-1", Scanner: "http-baseline", Category: "web", Target: "https://portal.example.com", AssetName: "Portal", Status: "completed", AuthRef: "SEC-2026-01", Approver: "Jane Doe", AuthExpires: "31 December 2026"},
		Findings: []Finding{
			{
				ID: "f1", Fingerprint: "abc123", Title: "Security header missing: Content-Security-Policy",
				Severity: "medium", Confidence: "certain", CWE: "CWE-693", CVSS: &cvss,
				Endpoint: "https://portal.example.com", Description: "CSP is missing.",
				Reproduction: "Request the homepage.", Remediation: "Add a CSP.",
				References: []string{"https://example.com/advisory"}, Status: "open",
				Evidence: map[string]any{"header": "Content-Security-Policy"},
			},
			{
				ID: "f2", Fingerprint: "def456", Title: "SQL injection in parameter q",
				Severity: "critical", Confidence: "certain", CVE: "CVE-2026-0001", CWE: "CWE-89",
				Endpoint: "https://portal.example.com/search?q=1", Description: "Boolean injection confirmed.",
				Status: "confirmed",
				EvidenceFiles: []EvidenceFile{{
					Filename: "proof.png", ContentType: "image/png", SizeBytes: 68,
					SHA256:  "431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
					DataURI: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
				}},
			},
		},
		Tools: []string{"HTTP baseline"},
	}
}

func TestBuildHTMLContainsRequiredSections(t *testing.T) {
	data := sampleData()
	out, err := BuildHTML(data)
	if err != nil {
		t.Fatalf("BuildHTML: %v", err)
	}
	text := string(out)
	for _, want := range []string{
		"Executive summary", "Assessment objectives", "Scope and authorized targets",
		"Methodology", "Tools used", "Assessment timeline", "Vulnerability summary",
		"Detailed technical findings", "Evidence and screenshots", "Risk analysis",
		"Remediation recommendations", "Conclusion", "Appendix", "Q3 External Assessment",
		"CVE-2026-0001", "SEC-2026-01",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if strings.Contains(text, "<script") {
		t.Fatal("report HTML contains script tags")
	}
}

func TestBuildHTMLHasNoLongDashes(t *testing.T) {
	out, err := BuildHTML(sampleData())
	if err != nil {
		t.Fatalf("BuildHTML: %v", err)
	}
	for _, code := range []rune{0x2012, 0x2013, 0x2014, 0x2015, 0x2011, 0x2212} {
		if bytes.ContainsRune(out, code) {
			t.Fatalf("report HTML contains a long dash (U+%04X)", code)
		}
	}
	for _, entity := range []string{"&" + "mdash;", "&" + "ndash;", "&#" + "8212;", "&#" + "8211;"} {
		if bytes.Contains(out, []byte(entity)) {
			t.Fatalf("report HTML contains long-dash entity %s", entity)
		}
	}
}

func TestBuildHTMLEscapesContent(t *testing.T) {
	data := sampleData()
	data.Findings[0].Title = `<script>alert(1)</script>`
	out, err := BuildHTML(data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("<script>alert(1)</script>")) {
		t.Fatal("finding title was not escaped")
	}
	if !bytes.Contains(out, []byte("&lt;script&gt;")) {
		t.Fatal("expected escaped title")
	}
}

func TestBuildPDFProducesValidHeader(t *testing.T) {
	out, err := BuildPDF(sampleData())
	if err != nil {
		t.Fatalf("BuildPDF: %v", err)
	}
	if len(out) < 1000 {
		t.Fatalf("PDF suspiciously small: %d bytes", len(out))
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Logf("len=%d first bytes: %q pdf_index=%d", len(out), out[:min(40, len(out))], bytes.Index(out, []byte("%PDF-")))
		t.Fatal("output does not start with %PDF-")
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Fatal("PDF is missing EOF marker")
	}
	if !bytes.Contains(out, []byte("/Subtype /Image")) {
		t.Fatal("embedded evidence image missing from PDF")
	}
}
