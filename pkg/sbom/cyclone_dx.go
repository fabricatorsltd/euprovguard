package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
)

// CYCLONEDX_SPEC_VERSION is the CycloneDX specification version implemented.
const CYCLONEDX_SPEC_VERSION = "1.6"

// CYCLONEDX_BOM_FORMAT is the required bomFormat field value.
const CYCLONEDX_BOM_FORMAT = "CycloneDX"

// BOM represents a [CycloneDX 1.6] Bill of Materials document.
type BOM struct {
	// BOMFormat must be "CycloneDX".
	BOMFormat string `json:"bomFormat"`
	// SpecVersion is the CycloneDX spec version, e.g. "1.6".
	SpecVersion string `json:"specVersion"`
	// SerialNumber is a URN UUID uniquely identifying this BOM instance.
	SerialNumber string `json:"serialNumber"`
	// Version is the BOM document version (increments on update).
	Version int `json:"version"`
	// Metadata contains BOM-level metadata.
	Metadata Metadata `json:"metadata"`
	// Provenance tracks the source of security databases (CWE, CRS, EUVD).
	Provenance []CatalogInfo `json:"provenance,omitempty"`
	// Components is the list of software components.
	Components []Component `json:"components"`
	// Vulnerabilities lists known CVE findings.
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// CatalogInfo holds the source information for a security catalog.
type CatalogInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Date      string `json:"date"`
	Signature string `json:"signature_sha256"`
	Fetched   string `json:"fetched_at"`
}

// Metadata holds BOM-level metadata including timestamp and tool information.
type Metadata struct {
	// Timestamp is the ISO 8601 UTC timestamp of BOM generation.
	Timestamp string `json:"timestamp"`
	// Tools lists the tools used to create this BOM.
	Tools []Tool `json:"tools"`
	// Component is the top-level component this BOM describes.
	Component *Component `json:"component,omitempty"`
}

// Tool describes a software tool used to produce the BOM.
type Tool struct {
	// Vendor is the tool author or organization.
	Vendor string `json:"vendor"`
	// Name is the tool name.
	Name string `json:"name"`
	// Version is the tool version.
	Version string `json:"version"`
}

// Component represents a single software component in the BOM.
type Component struct {
	// Type is the component type: "library", "application", "framework".
	Type string `json:"type"`
	// BOMRef is a unique reference identifier within this BOM.
	BOMRef string `json:"bom-ref"`
	// Name is the component name.
	Name string `json:"name"`
	// Version is the component version.
	Version string `json:"version"`
	// PURL is the Package URL per https://github.com/package-url/purl-spec.
	PURL string `json:"purl,omitempty"`
	// Licenses lists declared licenses for this component.
	Licenses []LicenseChoice `json:"licenses,omitempty"`
	// Scope is "required" or "optional".
	Scope string `json:"scope,omitempty"`
}

// LicenseChoice wraps a single license expression for [CycloneDX].
type LicenseChoice struct {
	License License `json:"license"`
}

// License holds an SPDX license identifier.
type License struct {
	// ID is the SPDX license identifier, e.g. "MIT".
	ID string `json:"id"`
}

// Vulnerability represents a CVE finding associated with a component.
type Vulnerability struct {
	// BOMRef is the vulnerability's unique BOM reference.
	BOMRef string `json:"bom-ref"`
	// ID is the identifier, e.g. "CVE-2024-12345" or "ORG-SEC-001".
	ID string `json:"id"`
	// Source contains information about the source of the vulnerability.
	Source *VulnSource `json:"source,omitempty"`
	// Ratings contains CVSS scoring information.
	Ratings []VulnRating `json:"ratings,omitempty"`
	// CWEs lists the Common Weakness Enumeration identifiers.
	CWEs []int `json:"cwes,omitempty"`
	// Description is a human-readable description.
	Description string `json:"description,omitempty"`
	// Detail is a more verbose description of the vulnerability.
	Detail string `json:"detail,omitempty"`
	// Analysis contains VEX (Vulnerability Exploitability eXchange) information.
	Analysis *VulnAnalysis `json:"analysis,omitempty"`
	// Affects links the vulnerability to specific BOM components.
	Affects []VulnAffect `json:"affects,omitempty"`
}

// VulnSource describes the origin of the vulnerability information.
type VulnSource struct {
	// Name is the name of the source (e.g., "NVD", "GitHub Advisories", "Internal").
	Name string `json:"name,omitempty"`
	// URL is the web link to the vulnerability record.
	URL string `json:"url,omitempty"`
}

// VulnAnalysis provides VEX information about the exploitability of the vulnerability.
type VulnAnalysis struct {
	// State is one of "resolved", "resolved_with_mitigation", "not_affected", "in_triage", "exploitable".
	State string `json:"state,omitempty"`
	// Justification is the VEX justification for the state (e.g. "code_not_reachable").
	Justification string `json:"justification,omitempty"`
	// Response is the response action (e.g. "can_not_fix", "will_not_fix", "update").
	Response []string `json:"response,omitempty"`
	// Detail is a detailed explanation of the analysis.
	Detail string `json:"detail,omitempty"`
}

// VulnRating holds CVSS score and severity for a vulnerability.
type VulnRating struct {
	// Score is the CVSS base score (0.0 - 10.0).
	Score float64 `json:"score"`
	// Severity is one of "critical", "high", "medium", "low", "none".
	Severity string `json:"severity"`
	// Method is the scoring method, e.g. "CVSSv31".
	Method string `json:"method"`
}

// VulnAffect links a vulnerability to a BOM component reference.
type VulnAffect struct {
	// Ref is the bom-ref of the affected component.
	Ref string `json:"ref"`
}

// GeneratorOptions configures BOM generation behaviour.
type GeneratorOptions struct {
	// ProjectName is the top-level component name.
	ProjectName string
	// ProjectVersion is the top-level component version.
	ProjectVersion string
	// ToolVersion is the version of EUProvGuard generating this BOM.
	ToolVersion string
}

// Generate creates a [CycloneDX 1.6] BOM from a list of scanned dependencies.
// It assigns BOM references, constructs Package URLs ([PURL]), and sets scope based
// on dependency type (dev vs. runtime). Returns the populated BOM document.
func Generate(deps []scanner.Dependency, opts GeneratorOptions) *BOM {
	bom := &BOM{
		BOMFormat:    CYCLONEDX_BOM_FORMAT,
		SpecVersion:  CYCLONEDX_SPEC_VERSION,
		SerialNumber: newURN(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{
					Vendor:  "EUProvGuard",
					Name:    "euprovguard",
					Version: opts.ToolVersion,
				},
			},
		},
	}

	if opts.ProjectName != "" {
		bom.Metadata.Component = &Component{
			Type:    "application",
			BOMRef:  "project",
			Name:    opts.ProjectName,
			Version: opts.ProjectVersion,
		}
	}

	for i, dep := range deps {
		comp := Component{
			Type:    "library",
			BOMRef:  fmt.Sprintf("comp-%d", i+1),
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    dep.PURL,
			Scope:   scopeFromDev(dep.Dev),
		}
		if dep.License != "" {
			comp.Licenses = []LicenseChoice{
				{License: License{ID: dep.License}},
			}
		}
		bom.Components = append(bom.Components, comp)
	}

	log.Printf("[INFO] BOM generated: %d components, serial=%s", len(bom.Components), bom.SerialNumber)
	return bom
}

// AddVulnerability appends a CVE finding to the BOM vulnerability list.
// The severity parameter should be lowercase (e.g., "critical", "high").
// If scoreMethod is empty, it defaults to "CVSSv31".
func AddVulnerability(bom *BOM, id, description string, score float64, severity, scoreMethod, bomRef string) {
	if scoreMethod == "" {
		scoreMethod = "CVSSv31"
	}
	v := Vulnerability{
		BOMRef: fmt.Sprintf("vuln-%s", id),
		ID:     id,
		Source: &VulnSource{Name: "External"},
		Ratings: []VulnRating{
			{Score: score, Severity: severity, Method: scoreMethod},
		},
		Description: description,
		Affects:     []VulnAffect{{Ref: bomRef}},
	}
	bom.Vulnerabilities = append(bom.Vulnerabilities, v)
}

// AddSASTFinding appends a SAST finding (proprietary code) to the BOM.
// It maps tool findings to CWEs and file locations as required by CRA.
func AddSASTFinding(bom *BOM, id, tool, rule, description, file string, line int, severity string, cwes []int) {
	v := Vulnerability{
		BOMRef: fmt.Sprintf("sast-%s", id),
		ID:     id,
		Source: &VulnSource{Name: tool},
		Ratings: []VulnRating{
			{Severity: strings.ToLower(severity)},
		},
		CWEs:        cwes,
		Description: description,
		Detail:      fmt.Sprintf("Rule: %s\nLocation: %s:%d", rule, file, line),
		Analysis: &VulnAnalysis{
			State: "in_triage",
		},
		Affects: []VulnAffect{{Ref: "project"}},
	}
	bom.Vulnerabilities = append(bom.Vulnerabilities, v)
}

// WriteJSON serialises a BOM to a JSON file at the given path.
// Returns an error if file creation or marshalling fails.
func WriteJSON(bom *BOM, path string) error {
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("sbom.WriteJSON marshal %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("sbom.WriteJSON write %w: %s", err, path)
	}
	log.Printf("[INFO] SBOM written: %s (%d bytes)", path, len(data))
	return nil
}

// ReadJSON deserialises a CycloneDX BOM from a JSON file.
// Returns the BOM or an error if reading or parsing fails.
func ReadJSON(path string) (*BOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sbom.ReadJSON read %w: %s", err, path)
	}
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("sbom.ReadJSON parse %w", err)
	}
	return &bom, nil
}

// newURN generates a random UUID v4 formatted as a URN (urn:uuid:...).
func newURN() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// scopeFromDirect converts a boolean direct flag to a CycloneDX scope string.
// Returns "required" for direct dependencies, "optional" for transitive.
func scopeFromDirect(direct bool) string {
	if direct {
		return "required"
	}
	return "optional"
}

// scopeFromDev converts a boolean dev flag to a CycloneDX scope string.
// Runtime transitive dependencies are "required"; development/test-only dependencies are "optional".
func scopeFromDev(dev bool) string {
	if dev {
		return "optional"
	}
	return "required"
}
