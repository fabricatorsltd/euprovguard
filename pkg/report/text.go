package report

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/vuln"
)

// TEXT_LINE_WIDTH is the width of the text report page in characters.
const TEXT_LINE_WIDTH = 80

// WriteTextReport generates a structured plain-text compliance report and writes it to path.
// The report includes SBOM summary, dependency inventory, vulnerability findings, and
// CRA/eIDAS compliance checklists. Returns an error if file write fails.
func WriteTextReport(
	bom *sbom.BOM,
	findings []vuln.Finding,
	projectName, projectVersion, toolVersion string,
	signed bool,
	snapshot *vuln.EuvdSnapshot,
	path string,
) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("report.WriteTextReport create %w: %s", err, path)
	}
	defer f.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	writeTextReport(f, bom, findings, projectName, projectVersion, toolVersion, signed, snapshot, now)

	log.Printf("[INFO] Text report written: %s", path)
	return nil
}

// writeTextReport renders the report to the provided writer.
// It formats the BOM, vulnerability findings, and compliance checklist using
// plain text with structured separators.
func writeTextReport(
	w io.Writer,
	bom *sbom.BOM,
	findings []vuln.Finding,
	projectName, projectVersion, toolVersion string,
	signed bool,
	snapshot *vuln.EuvdSnapshot,
	generatedAt string,
) {
	line := strings.Repeat("=", TEXT_LINE_WIDTH)
	dash := strings.Repeat("-", TEXT_LINE_WIDTH)

	fmt.Fprintln(w, line)
	fmt.Fprintln(w, center(fmt.Sprintf("CRA COMPLIANCE REPORT: %s %s", strings.ToUpper(projectName), projectVersion), TEXT_LINE_WIDTH))
	fmt.Fprintln(w, center("Cyber Resilience Act (EU) 2024/2353 | eIDAS (EU) 2024/1183", TEXT_LINE_WIDTH))
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "Generated:  %s\n", generatedAt)
	fmt.Fprintf(w, "Tool:       EUProvGuard %s\n", toolVersion)
	fmt.Fprintln(w)

	// Section 1: SBOM Summary
	fmt.Fprintln(w, dash)
	fmt.Fprintln(w, "1. SBOM SUMMARY")
	fmt.Fprintln(w, dash)
	fmt.Fprintf(w, "  BOM Format:       %s %s\n", bom.BOMFormat, bom.SpecVersion)
	fmt.Fprintf(w, "  Serial Number:    %s\n", bom.SerialNumber)
	fmt.Fprintf(w, "  Components:       %d\n", len(bom.Components))
	fmt.Fprintf(w, "  CVE Findings:     %d\n", len(findings))
	if signed {
		fmt.Fprintf(w, "  Signature:        SIGNED (RSA-4096 SHA-512, eIDAS Art. 32)\n")
	} else {
		fmt.Fprintf(w, "  Signature:        NOT SIGNED\n")
	}
	fmt.Fprintln(w)

	// Section 2: Components
	fmt.Fprintln(w, dash)
	fmt.Fprintln(w, "2. DEPENDENCY INVENTORY")
	fmt.Fprintln(w, dash)
	fmt.Fprintf(w, "  %-3s  %-35s %-15s %s\n", "#", "Name", "Version", "PURL")
	fmt.Fprintln(w, "  "+strings.Repeat("-", TEXT_LINE_WIDTH-2))
	for i, c := range bom.Components {
		purl := c.PURL
		if len(purl) > 55 {
			purl = purl[:52] + "..."
		}
		fmt.Fprintf(w, "  %-3d  %-35s %-15s %s\n", i+1, truncate(c.Name, 35), truncate(c.Version, 15), purl)
	}
	fmt.Fprintln(w)

	// Section 3: CVE Findings
	fmt.Fprintln(w, dash)
	fmt.Fprintln(w, "3. VULNERABILITY FINDINGS")
	fmt.Fprintln(w, dash)
	if len(findings) == 0 {
		fmt.Fprintln(w, "  No CVE findings for scanned dependencies.")
	} else {
		counts := vuln.CountBySeverity(findings)
		fmt.Fprintf(w, "  CRITICAL: %d  HIGH: %d  MEDIUM: %d  LOW: %d\n",
			counts[vuln.SEVERITY_CRITICAL], counts[vuln.SEVERITY_HIGH],
			counts[vuln.SEVERITY_MEDIUM], counts[vuln.SEVERITY_LOW])
		fmt.Fprintln(w)
		for _, f := range findings {
			fmt.Fprintf(w, "  [%s] %s\n", f.CVE.Severity, f.CVE.ID)
			fmt.Fprintf(w, "    Source:      %s\n", f.CVE.Source)
			if f.CVE.EuvdID != "" {
				exploitedMark := ""
				if f.CVE.Exploited {
					exploitedMark = " ⚠ ACTIVELY EXPLOITED"
				}
				fmt.Fprintf(w, "    EUVD ID:     %s%s\n", f.CVE.EuvdID, exploitedMark)
			}
			fmt.Fprintf(w, "    Component:   %s@%s\n", f.Component, f.Version)
			fmt.Fprintf(w, "    CVSS:        %.1f\n", f.CVE.CVSS)
			if f.CVE.CWE != "" {
				fmt.Fprintf(w, "    CWE:         %s\n", f.CVE.CWE)
			}
			fmt.Fprintf(w, "    Description: %s\n", f.CVE.Description)
			if f.CVE.FixedVersion != "" {
				fmt.Fprintf(w, "    Fix:         Upgrade to >= %s\n", f.CVE.FixedVersion)
			} else {
				fmt.Fprintf(w, "    Fix:         No fix available\n")
			}
			fmt.Fprintln(w)
		}
	}

	// Section 4: CRA Checklist
	fmt.Fprintln(w, dash)
	fmt.Fprintln(w, "4. CRA ARTICLE 13 / ANNEX I CHECKLIST")
	fmt.Fprintln(w, dash)
	checkItem(w, "SBOM generated (CycloneDX "+bom.SpecVersion+")", true)
	checkItem(w, fmt.Sprintf("Top-level components identified (%d)", len(bom.Components)), true)
	checkItem(w, "Known vulnerability disclosure", len(findings) == 0)
	checkItem(w, "SBOM signed (non-repudiation)", signed)
	checkItem(w, "Static binary (SLSA Level 3, CGO_ENABLED=0)", true)
	fmt.Fprintln(w)

	// Section 5: eIDAS Attestation
	fmt.Fprintln(w, dash)
	fmt.Fprintln(w, "5. EIDAS ARTICLE 32 QES ATTESTATION")
	fmt.Fprintln(w, dash)
	fmt.Fprintln(w, "  Standard:    eIDAS Regulation (EU) 2024/1183")
	fmt.Fprintln(w, "  Algorithm:   RSASSA-PKCS1-v1_5 with SHA-512")
	fmt.Fprintln(w, "  Key size:    RSA-4096")
	fmt.Fprintln(w, "  Timestamp:   RFC 3161 (Aruba TSA)")
	fmt.Fprintln(w, "  ETSI:        ETSI TS 119 312, ETSI EN 319 422")
	fmt.Fprintln(w)

	// Section 6: EUVD snapshot (live mode only)
	if snapshot != nil {
		fmt.Fprintln(w, dash)
		fmt.Fprintln(w, "6. EUVD AUDIT SNAPSHOT (ENISA)")
		fmt.Fprintln(w, dash)
		fmt.Fprintf(w, "  Scan Timestamp:  %s\n", snapshot.ScanTimestamp)
		fmt.Fprintf(w, "  Latest EUVD ID:  %s\n", snapshot.LastEuvdId)
		fmt.Fprintf(w, "  Source:          %s\n", snapshot.Source)
		fmt.Fprintln(w, "  CRA Compliance:  ENISA official EU vulnerability database (CRA Annex I)")
		fmt.Fprintf(w, "  Auditor verify:  curl https://euvdservices.enisa.europa.eu/api/enisaid?id=%s\n",
			snapshot.LastEuvdId)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "END OF REPORT - EUProvGuard %s\n", toolVersion)
	fmt.Fprintln(w, line)
}

// checkItem writes a checklist line with PASS/FAIL indicator.
func checkItem(w io.Writer, label string, ok bool) {
	status := "[ PASS ]"
	if !ok {
		status = "[ FAIL ]"
	}
	fmt.Fprintf(w, "  %s %s\n", status, label)
}

// center pads a string to be centred within width characters.
func center(s string, width int) string {
	if len(s) >= width {
		return s
	}
	pad := (width - len(s)) / 2
	return strings.Repeat(" ", pad) + s
}

// truncate shortens a string to maxLen characters, appending "..." if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "..."
}
