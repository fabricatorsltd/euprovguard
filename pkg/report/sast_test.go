package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
)

func TestReportsKeepAcceptedSASTReasons(t *testing.T) {
	bom := sbom.Generate(nil, sbom.GeneratorOptions{ProjectName: "fixture"})
	sbom.AddSASTFinding(bom, "SAST-001", "native", "MEM-001", "Bounded copy", "crt/string.c", 12, "critical", []int{120})
	bom.Vulnerabilities[0].Properties = append(bom.Vulnerabilities[0].Properties, sbom.Property{Name: "euprovguard:sast:status", Value: "accepted"})
	bom.Vulnerabilities[0].Analysis.Detail = "buffer holds <64> bytes & source is fixed"
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "report.html")
	if preview := os.Getenv("EUPROVGUARD_REPORT_PREVIEW"); preview != "" {
		htmlPath = preview
	}
	data := ReportData{
		ProjectName: "fixture", BOM: bom, ToolVersion: "1.3.0",
		SASTMetadata:   SASTMetadata{Enabled: true},
		SuppressedSAST: []scanner.Finding{{RuleID: "MEM-001", File: "crt/string.c", Line: 12, Suppressed: bom.Vulnerabilities[0].Analysis.Detail}},
	}
	if err := WriteHTMLReport(data, htmlPath); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Accepted SAST findings: 1", "No critical/high issues", "buffer holds &lt;64&gt; bytes &amp; source is fixed", "crt/string.c"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	textPath := filepath.Join(dir, "report.txt")
	if err := WriteTextReport(bom, nil, "fixture", "1", "1.3.0", false, nil, textPath); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[ACCEPTED] SAST-001", "Reason: buffer holds <64> bytes & source is fixed", "SAST open: 0 | Accepted: 1"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("text missing %q", want)
		}
	}
}
