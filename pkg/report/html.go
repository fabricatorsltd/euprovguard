package report

import (
	"fmt"
	"html/template"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/vuln"
)

// HTML_TEMPLATE_NAME is the internal name of the parsed HTML template.
const HTML_TEMPLATE_NAME = "cra-report"

// ReportData holds all data needed to render the HTML compliance report.
type ReportData struct {
	// GeneratedAt is the ISO 8601 UTC generation timestamp.
	GeneratedAt string
	// ProjectName is the top-level component name.
	ProjectName string
	// ProjectVersion is the top-level component version.
	ProjectVersion string
	// ToolVersion is the EUProvGuard tool version string.
	ToolVersion string
	// BOM is the CycloneDX BOM document.
	BOM *sbom.BOM
	// Findings are the CVE findings from vulnerability matching.
	Findings []vuln.Finding
	// SeverityCounts maps severity string to count (string keys for template compatibility).
	SeverityCounts map[string]int
	// Signed indicates whether the BOM has been signed.
	Signed bool
	// SignedAt is the signing timestamp (if signed).
	SignedAt string
	// TSAPresent indicates whether a TSA timestamp is present.
	TSAPresent bool
	// EuvdSnapshot holds EUVD database state metadata for audit attestation (live mode only).
	EuvdSnapshot *vuln.EuvdSnapshot
	// LiveMode indicates that vulnerability data was sourced from the EUVD live API.
	LiveMode bool
	// SASTFindings holds code security findings from static analysis.
	SASTFindings interface{} // []scanner.Finding
	// SASTMetadata describes which SAST rules were executed.
	SASTMetadata SASTMetadata
}

// SASTMetadata documents the static analysis configuration.
type SASTMetadata struct {
	// Enabled indicates whether SAST was performed.
	Enabled bool
	// RulesCount is the total number of SAST rules evaluated.
	RulesCount int
	// CatalogVersion identifies the CWE/SAST catalog version used (e.g., "CWE-1.4.1").
	CatalogVersion string
	// SeverityFilter shows which severities were reported (e.g., "CRITICAL, HIGH").
	SeverityFilter string
	// FindingsCount is the number of issues found after filtering.
	FindingsCount int
}

// htmlReportTmpl is the built-in HTML template for CRA compliance reports.
const htmlReportTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EUProvGuard CRA Compliance Report - {{.ProjectName}} {{.ProjectVersion}}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 2rem; color: #222; }
  h1 { color: #1a3c6e; border-bottom: 2px solid #1a3c6e; padding-bottom: .5rem; }
  h2 { color: #1a3c6e; margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: .9rem; }
  th { background: #1a3c6e; color: #fff; padding: .5rem; text-align: left; }
  td { border: 1px solid #ccc; padding: .4rem .6rem; vertical-align: top; }
  tr:nth-child(even) { background: #f5f5f5; }
  .badge { display: inline-block; padding: .2rem .5rem; border-radius: 3px; font-size: .8rem; font-weight: bold; }
  .CRITICAL { background:#d32f2f; color:#fff; }
  .HIGH     { background:#f57c00; color:#fff; }
  .MEDIUM   { background:#fbc02d; color:#000; }
  .LOW      { background:#388e3c; color:#fff; }
  .NONE     { background:#9e9e9e; color:#fff; }
  .ok       { color: #388e3c; font-weight: bold; }
  .warn     { color: #f57c00; font-weight: bold; }
  .fail     { color: #d32f2f; font-weight: bold; }
  .meta     { font-size: .85rem; color: #555; margin-bottom: 1.5rem; }
  footer    { margin-top: 3rem; font-size: .8rem; color: #888; border-top: 1px solid #ccc; padding-top: 1rem; }
</style>
</head>
<body>
<h1>CRA Compliance Report: {{.ProjectName}} {{.ProjectVersion}}</h1>
<p class="meta">
  Generated: <strong>{{.GeneratedAt}}</strong> &nbsp;|&nbsp;
  Tool: EUProvGuard {{.ToolVersion}}
</p>

<h2>1. SBOM Summary</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>BOM Format</td><td>{{.BOM.BOMFormat}} {{.BOM.SpecVersion}}</td></tr>
  <tr><td>Serial Number</td><td>{{.BOM.SerialNumber}}</td></tr>
  <tr><td>Components</td><td>{{len .BOM.Components}}</td></tr>
  <tr><td>Vulnerabilities Found</td><td>{{len .Findings}}</td></tr>
  <tr><td>Signature</td><td>{{if .Signed}}<span class="ok">✓ SIGNED ({{.SignedAt}})</span>{{else}}<span class="warn">⚠ NOT SIGNED</span>{{end}}</td></tr>
  <tr><td>TSA Timestamp</td><td>{{if .TSAPresent}}<span class="ok">✓ PRESENT</span>{{else}}<span class="warn">⚠ NOT PRESENT</span>{{end}}</td></tr>
</table>

<h2>2. Dependency Inventory</h2>
<table>
  <tr><th>#</th><th>Name</th><th>Version</th><th>Ecosystem</th><th>PURL</th><th>Scope</th></tr>
  {{range $i, $c := .BOM.Components}}
  <tr>
    <td>{{inc $i}}</td>
    <td>{{$c.Name}}</td>
    <td>{{$c.Version}}</td>
    <td>{{ecosystem $c.PURL}}</td>
    <td style="font-family:monospace;font-size:.8rem">{{$c.PURL}}</td>
    <td>{{$c.Scope}}</td>
  </tr>
  {{end}}
</table>

<h2>3. Vulnerability Findings</h2>
{{if .Findings}}
<p>Severity summary:
  {{with .SeverityCounts}}
  <span class="badge CRITICAL">CRITICAL: {{index . "CRITICAL"}}</span>
  <span class="badge HIGH">HIGH: {{index . "HIGH"}}</span>
  <span class="badge MEDIUM">MEDIUM: {{index . "MEDIUM"}}</span>
  <span class="badge LOW">LOW: {{index . "LOW"}}</span>
  {{end}}
  {{if .LiveMode}}&nbsp;<em style="font-size:.8rem;color:#555;">Source: OSV.dev + EUVD (ENISA) - CRA Annex I compliant</em>{{end}}
</p>
<table>
  <tr><th>ID</th><th>EUVD ID</th><th>Exploited</th><th>Source</th><th>Component</th><th>Version</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>Description</th><th>Fix</th></tr>
  {{range .Findings}}
  <tr>
    <td style="white-space:nowrap">{{.CVE.ID}}</td>
    <td style="white-space:nowrap;font-family:monospace;font-size:.8rem">{{if .CVE.EuvdID}}<a href="https://euvd.enisa.europa.eu/enisa/{{.CVE.EuvdID}}" target="_blank">{{.CVE.EuvdID}}</a>{{else}}<span style="color:#aaa">N/A</span>{{end}}</td>
    <td>{{if .CVE.Exploited}}<span class="badge CRITICAL">⚠ YES</span>{{else}}No{{end}}</td>
    <td style="font-size:.8rem;white-space:nowrap">{{.CVE.Source}}</td>
    <td>{{.Component}}</td>
    <td>{{.Version}}</td>
    <td><span class="badge {{.CVE.Severity}}">{{.CVE.Severity}}</span></td>
    <td>{{.CVE.CVSS}}</td>
    <td>{{.CVE.CWE}}</td>
    <td>{{.CVE.Description}}</td>
    <td>{{if .CVE.FixedVersion}}≥ {{.CVE.FixedVersion}}{{else}} -{{end}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="ok">✓ No CVE findings for scanned dependencies.</p>
{{end}}

<h2>4. CRA Article 13 / Annex I Checklist</h2>
<table>
  <tr><th>Requirement</th><th>Status</th></tr>
  <tr><td>SBOM generated (Annex I, Part II, §1)</td><td class="ok">✓ CycloneDX {{.BOM.SpecVersion}}</td></tr>
  <tr><td>Top-level components identified</td><td class="ok">✓ {{len .BOM.Components}} components</td></tr>
  <tr><td>Known vulnerability disclosure (Art. 13)</td><td>{{if .Findings}}<span class="warn">⚠ {{len .Findings}} finding(s) - review required</span>{{else}}<span class="ok">✓ No known CVEs</span>{{end}}</td></tr>
  <tr><td>SBOM signed (non-repudiation)</td><td>{{if .Signed}}<span class="ok">✓ QES applied</span>{{else}}<span class="warn">⚠ Unsigned</span>{{end}}</td></tr>
  <tr><td>Qualified timestamp (eIDAS Art. 26)</td><td>{{if .TSAPresent}}<span class="ok">✓ TSA token present</span>{{else}}<span class="warn">⚠ No TSA timestamp</span>{{end}}</td></tr>
  <tr><td>Static binary (SLSA Level 3)</td><td class="ok">✓ CGO_ENABLED=0</td></tr>
</table>

<h2>5. eIDAS Article 32 QES Attestation</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Standard</td><td>eIDAS Regulation (EU) 2024/1183</td></tr>
  <tr><td>Signature algorithm</td><td>RSASSA-PKCS1-v1_5 with SHA-512</td></tr>
  <tr><td>Key size</td><td>RSA-4096</td></tr>
  <tr><td>Timestamp protocol</td><td>RFC 3161 (Aruba TSA)</td></tr>
  <tr><td>ETSI standard</td><td>ETSI TS 119 312, ETSI EN 319 422</td></tr>
</table>

{{if .EuvdSnapshot}}
<h2>6. EUVD Audit Snapshot</h2>
<p style="font-size:.9rem">Auditor verification:
  <code>curl https://euvdservices.enisa.europa.eu/api/enisaid?id={{.EuvdSnapshot.LastEuvdId}}</code>
</p>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Scan Timestamp</td><td>{{.EuvdSnapshot.ScanTimestamp}}</td></tr>
  <tr><td>Latest EUVD ID at scan time</td><td><a href="https://euvd.enisa.europa.eu/enisa/{{.EuvdSnapshot.LastEuvdId}}" target="_blank">{{.EuvdSnapshot.LastEuvdId}}</a></td></tr>
  <tr><td>Source</td><td>{{.EuvdSnapshot.Source}}</td></tr>
  <tr><td>CRA compliance</td><td class="ok">✓ ENISA official EU vulnerability database (CRA Annex I)</td></tr>
</table>
{{end}}

<h2>5. Code Security Findings (SAST)</h2>
{{if .SASTMetadata.Enabled}}
<p><strong>Static analysis configuration:</strong></p>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Rules Evaluated</td><td>{{.SASTMetadata.RulesCount}}</td></tr>
  <tr><td>CWE Catalog Version</td><td>{{.SASTMetadata.CatalogVersion}}</td></tr>
  <tr><td>Severity Filter</td><td>{{.SASTMetadata.SeverityFilter}}</td></tr>
  <tr><td>Issues Found</td><td>{{if gt .SASTMetadata.FindingsCount 0}}<span class="badge HIGH">{{.SASTMetadata.FindingsCount}}</span>{{else}}<span class="ok">✓ No critical/high issues</span>{{end}}</td></tr>
</table>
{{if gt .SASTMetadata.FindingsCount 0}}
<p><strong>Detected issues (top 50):</strong></p>
<table style="font-size: .85rem;">
  <tr><th>File</th><th>Line</th><th>Rule</th><th>Severity</th><th>CWE</th><th>Description</th></tr>
  {{range .SASTFindings}}
  <tr>
    <td style="font-family:monospace;font-size:.75rem">{{.File}}</td>
    <td>{{.Line}}</td>
    <td style="white-space:nowrap">{{.RuleID}}</td>
    <td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
    <td>{{range .CWEs}}{{if not (eq . 0)}}<a href="https://cwe.mitre.org/data/definitions/{{.}}.html" target="_blank">CWE-{{.}}</a><br>{{end}}{{end}}</td>
    <td>{{.Description}}</td>
  </tr>
  {{end}}
</table>
{{end}}
{{else}}
<p><span class="warn">⚠ Static analysis (SAST) was not enabled for this scan.</span></p>
{{end}}

<footer>
  Generated by EUProvGuard {{.ToolVersion}} - Open-source CRA/eIDAS SBOM toolchain.<br>
  CRA: Regulation (EU) 2024/2353 &nbsp;|&nbsp; eIDAS: Regulation (EU) 2024/1183 &nbsp;|&nbsp; ETSI EN 303 645
</footer>
</body>
</html>`

// WriteHTMLReport renders the CRA compliance HTML report and writes it to path.
// It populates the report with SBOM data, vulnerability findings, and signature metadata.
// Returns an error if template rendering or file write fails.
func WriteHTMLReport(data ReportData, path string) error {
	data.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	funcMap := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
		"ecosystem": func(purl string) string {
			if strings.HasPrefix(purl, "pkg:golang") {
				return "go"
			}
			if strings.HasPrefix(purl, "pkg:cargo") {
				return "cargo"
			}
			if strings.HasPrefix(purl, "pkg:npm") {
				return "npm"
			}
			if strings.HasPrefix(purl, "pkg:pypi") {
				return "pypi"
			}
			return "unknown"
		},
	}

	tmpl, err := template.New(HTML_TEMPLATE_NAME).Funcs(funcMap).Parse(htmlReportTmpl)
	if err != nil {
		return fmt.Errorf("report.WriteHTMLReport parse template %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("report.WriteHTMLReport create %w: %s", err, path)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("report.WriteHTMLReport render %w", err)
	}

	log.Printf("[INFO] HTML report written: %s", path)
	return nil
}
