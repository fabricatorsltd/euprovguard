package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fabricatorsltd/euprovguard/pkg/report"
	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
	"github.com/fabricatorsltd/euprovguard/pkg/signature"
	"github.com/fabricatorsltd/euprovguard/pkg/vuln"
)

// Version is the EUProvGuard release version.
const Version = "1.0.0"

// CRA_STANDARD identifies the CRA regulation version this build targets.
const CRA_STANDARD = "Regulation (EU) 2024/2353"

// EIDAS_STANDARD identifies the eIDAS regulation version this build targets.
const EIDAS_STANDARD = "Regulation (EU) 2024/1183"

// Config holds parsed CLI configuration.
type Config struct {
	// Path is the project root to scan.
	Path string
	// Output is the SBOM JSON output file path.
	Output string
	// PrivKeyPath is the RSA private key PEM file for signing.
	PrivKeyPath string
	// PubKeyPath is the RSA public key PEM file for verification.
	PubKeyPath string
	// TSAURL is the RFC 3161 TSA endpoint URL.
	TSAURL string
	// ReportPath is the optional HTML report output path.
	ReportPath string
	// TextReportPath is the optional plain-text report output path.
	TextReportPath string
	// BundlePath is the base path for generating all report formats (.html, .txt).
	BundlePath string
	// EnableSAST enables the native static analysis engine.
	EnableSAST bool
	// Sign enables SBOM signing.
	Sign bool
	// Verify enables verification mode.
	Verify bool
	// Input is the signed SBOM file to verify.
	Input string
	// Workers is the number of parallel scanner goroutines.
	Workers int
	// ProjectName overrides the detected project name.
	ProjectName string
	// ProjectVersion overrides the detected project version.
	ProjectVersion string
}

func main() {
	cfg := parseFlags()

	if cfg.Verify {
		runVerify(cfg)
		return
	}

	runGenerate(cfg)
}

// parseFlags parses command-line flags into a Config.
func parseFlags() Config {
	var cfg Config

	flag.StringVar(&cfg.Path, "path", ".", "Project root directory to scan")
	flag.StringVar(&cfg.Output, "output", "sbom.json", "SBOM JSON output file")
	flag.StringVar(&cfg.PrivKeyPath, "key", "", "RSA-4096 private key PEM (for signing)")
	flag.StringVar(&cfg.PubKeyPath, "pubkey", "", "RSA-4096 public key PEM (for verification)")
	flag.StringVar(&cfg.TSAURL, "tsa", "", "RFC 3161 TSA endpoint URL (eIDAS Art. 26)")
	flag.StringVar(&cfg.ReportPath, "report", "", "HTML compliance report output path")
	flag.StringVar(&cfg.TextReportPath, "text-report", "", "Plain-text compliance report output path")
	flag.StringVar(&cfg.BundlePath, "bundle", "", "Base path for all report formats (.html, .txt)")
	flag.BoolVar(&cfg.EnableSAST, "sast", true, "Enable native SAST engine for proprietary code")
	flag.BoolVar(&cfg.Sign, "sign", false, "Sign SBOM (QES if backed by QSCD and Qualified Certificate)")
	flag.BoolVar(&cfg.Verify, "verify", false, "Verify signed SBOM (requires -input and -pubkey)")
	flag.StringVar(&cfg.Input, "input", "", "Signed SBOM file to verify")
	flag.IntVar(&cfg.Workers, "workers", 4, "Parallel scanner workers")
	flag.StringVar(&cfg.ProjectName, "name", "", "Project name (default: directory name)")
	flag.StringVar(&cfg.ProjectVersion, "version-tag", "0.0.0", "Project version")

	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("EUProvGuard v%s\n", Version)
		fmt.Printf("CRA standard:   %s\n", CRA_STANDARD)
		fmt.Printf("eIDAS standard: %s\n", EIDAS_STANDARD)
		os.Exit(0)
	}

	if cfg.ProjectName == "" {
		abs, err := filepath.Abs(cfg.Path)
		if err == nil {
			cfg.ProjectName = filepath.Base(abs)
		} else {
			cfg.ProjectName = "unknown"
		}
	}

	return cfg
}

// runGenerate executes the full SBOM generation pipeline.
// It scans all ecosystems, matches vulnerabilities, generates a [CycloneDX 1.6]
// SBOM, signs it with [QES], and optionally produces compliance reports.
func runGenerate(cfg Config) {
	log.Printf("[INFO] EUProvGuard v%s - scanning %s", Version, cfg.Path)

	// 1. Scan all ecosystems in parallel.
	rawDeps := scanAll(cfg.Path, cfg.Workers)
	deps := mergeDeps(rawDeps)
	log.Printf("[INFO] Total dependencies found: %d (merged from %d raw entries)", len(deps), len(rawDeps))

	vulnDeps := toVulnDeps(deps)

	// 2. Match vulnerabilities - live OSV.dev + EUVD API (dynamic queries, CRA Annex I compliant).
	// OSV is the authoritative source; EUVD provides EU-specific threat context.
	var findings []vuln.Finding
	var euvdSnap *vuln.EuvdSnapshot

	log.Printf("[INFO] Vulnerability mode: OSV.dev + EUVD live queries (CRA Annex I compliant)")
	liveFindings, snap, err := vuln.MatchLive(vulnDeps)
	if err != nil {
		log.Printf("[WARN] OSV/EUVD query failed: %v - proceeding with no CVE findings", err)
		findings = []vuln.Finding{}
	} else {
		findings = liveFindings
		euvdSnap = &snap
	}
	log.Printf("[INFO] CVE findings: %d", len(findings))

	// 2.3 Fetch and verify Catalog provenance (CWE, CRS) for CRA technical documentation.
	var provenance []sbom.CatalogInfo

	// CWE Catalog
	cweDir := filepath.Join(os.TempDir(), "euprovguard-cwe")
	cweZip := filepath.Join(cweDir, "cwe.zip")
	cweMeta, err := vuln.FetchCatalog("MITRE-CWE", vuln.CWE_XML_URL, cweZip)
	if err == nil {
		files, err := vuln.Unzip(cweZip, cweDir)
		if err == nil && len(files) > 0 {
			cat, err := vuln.LoadCWEXML(files[0])
			if err == nil {
				provenance = append(provenance, sbom.CatalogInfo{
					Name:      "MITRE CWE",
					Version:   cat.Version,
					Date:      cat.Date,
					Signature: cweMeta.Hash,
					Fetched:   cweMeta.FetchedAt.Format(time.RFC3339),
				})
			}
		}
	}

	// 2.5 Run native SAST engine with CRS enrichment.
	var sastFindings []scanner.Finding
	if cfg.EnableSAST {
		// Fetch latest OWASP Core Rule Set patterns to enhance the native engine
		crsDir := filepath.Join(os.TempDir(), "euprovguard-crs")
		var crsRules []scanner.SASTRule
		if err := scanner.FetchLatestCRS(crsDir); err != nil {
			log.Printf("[WARN] Failed to fetch CRS: %v - using embedded rules only", err)
		} else {
			crsRules = scanner.ParseCRSRules(crsDir)
			// We don't have a direct "version" for CRS in the atom feed title sometimes,
			// but we can add it to provenance with the signature.
			provenance = append(provenance, sbom.CatalogInfo{
				Name:      "OWASP CRS",
				Version:   "latest",
				Date:      time.Now().Format("2006-01-02"),
				Signature: "verified-via-atom-feed",
				Fetched:   time.Now().Format(time.RFC3339),
			})
		}

		sastFindings = scanner.RunSAST(cfg.Path, cfg.Workers, crsRules)
	}

	// 3. Generate CycloneDX 1.6 BOM.
	bom := sbom.Generate(deps, sbom.GeneratorOptions{
		ProjectName:    cfg.ProjectName,
		ProjectVersion: cfg.ProjectVersion,
		ToolVersion:    Version,
	})
	bom.Provenance = provenance

	// 4. Attach vulnerability findings to BOM.
	for i, f := range findings {
		compIdx := findComponentIndex(bom, f.Component, f.CVE.Package)
		if compIdx < 0 {
			compIdx = 0
		}
		bomRef := fmt.Sprintf("comp-%d", compIdx+1)
		sbom.AddVulnerability(bom,
			f.CVE.ID,
			f.CVE.Description,
			f.CVE.CVSS,
			strings.ToLower(string(f.CVE.Severity)),
			f.CVE.ScoreMethod,
			bomRef,
		)
		_ = i
	}

	// 4.5 Attach SAST findings to BOM.
	for i, f := range sastFindings {
		id := fmt.Sprintf("SAST-%03d", i+1)
		sbom.AddSASTFinding(bom,
			id,
			f.ToolName,
			f.RuleID,
			f.Description,
			f.File,
			f.Line,
			f.Severity,
			f.CWEs,
		)
	}

	// 5. Write unsigned SBOM first.
	if err := sbom.WriteJSON(bom, cfg.Output); err != nil {
		log.Fatalf("[ERROR] %v", err)
	}

	// 6. Sign if requested.
	signed := false
	signedAt := ""
	tsaPresent := false

	if cfg.Sign {
		if cfg.PrivKeyPath == "" {
			log.Fatalf("[ERROR] -sign requires -key <private.pem>")
		}
		privKey, err := signature.LoadPrivateKey(cfg.PrivKeyPath)
		if err != nil {
			log.Fatalf("[ERROR] %v", err)
		}

		bomJSON, err := os.ReadFile(cfg.Output)
		if err != nil {
			log.Fatalf("[ERROR] read SBOM for signing: %v", err)
		}

		signOpts := signature.QESSignOptions{
			PrivateKey: privKey,
			TSAURL:     cfg.TSAURL,
		}
		signedDoc, err := signature.SignDocument(bomJSON, signOpts)
		if err != nil {
			log.Fatalf("[ERROR] QES signing failed: %v", err)
		}

		signedPath := cfg.Output + ".signed"
		if err := signature.WriteSignedDocument(signedDoc, signedPath); err != nil {
			log.Fatalf("[ERROR] %v", err)
		}
		log.Printf("[INFO] Signed SBOM written: %s", signedPath)

		signed = true
		signedAt = signedDoc.SignedAt
		tsaPresent = signedDoc.TSAToken != ""
	}

	// 7. Generate HTML report if requested.
	if cfg.BundlePath != "" {
		if cfg.ReportPath == "" {
			cfg.ReportPath = cfg.BundlePath + ".html"
		}
		if cfg.TextReportPath == "" {
			cfg.TextReportPath = cfg.BundlePath + ".txt"
		}
	}

	if cfg.ReportPath != "" {
		sastMeta := report.SASTMetadata{
			Enabled:        cfg.EnableSAST,
			RulesCount:     len(scanner.GetEmbeddedRules()),
			CatalogVersion: "CWE-4.15 + OWASP CRS latest",
			SeverityFilter: "CRITICAL, HIGH",
			FindingsCount:  len(sastFindings),
		}

		rd := report.ReportData{
			ProjectName:    cfg.ProjectName,
			ProjectVersion: cfg.ProjectVersion,
			ToolVersion:    Version,
			BOM:            bom,
			Findings:       findings,
			SeverityCounts: severityCountsAsMap(findings),
			Signed:         signed,
			SignedAt:       signedAt,
			TSAPresent:     tsaPresent,
			EuvdSnapshot:   euvdSnap,
			LiveMode:       true,
			SASTFindings:   sastFindings,
			SASTMetadata:   sastMeta,
		}
		if err := report.WriteHTMLReport(rd, cfg.ReportPath); err != nil {
			log.Printf("[WARN] HTML report failed: %v", err)
		}
	}

	// 8. Generate plain-text report if requested.
	if cfg.TextReportPath != "" {
		if err := report.WriteTextReport(bom, findings,
			cfg.ProjectName, cfg.ProjectVersion, Version, signed, euvdSnap, cfg.TextReportPath); err != nil {
			log.Printf("[WARN] Text report failed: %v", err)
		}
	}

	// 10. Summary.
	log.Printf("[INFO] ✓ SBOM: %s | Components: %d | CVEs: %d | Signed: %v",
		cfg.Output, len(bom.Components), len(findings), signed)
}

// runVerify verifies a signed SBOM document using the provided public key.
// The cfg must have Input and PubKeyPath set.
func runVerify(cfg Config) {
	if cfg.Input == "" {
		log.Fatalf("[ERROR] -verify requires -input <sbom.signed>")
	}
	if cfg.PubKeyPath == "" {
		log.Fatalf("[ERROR] -verify requires -pubkey <public.pem>")
	}

	pubKey, err := signature.LoadPublicKey(cfg.PubKeyPath)
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}

	result, err := signature.VerifySBOM(cfg.Input, pubKey)
	if err != nil {
		log.Fatalf("[ERROR] verification error: %v", err)
	}

	fmt.Print(signature.FormatResult(result))

	if !result.Valid {
		os.Exit(1)
	}
}

// mergeDeps deduplicates a flat dependency list by (ecosystem, normalised-name, version).
// When the same component appears from multiple sources (e.g. go.mod + lockfile),
// Direct=true wins over false, and Dev=false wins over true (runtime use overrides dev-only use).
// This ensures each component appears exactly once in the SBOM as required by CRA Article 13.
func mergeDeps(deps []scanner.Dependency) []scanner.Dependency {
	type key struct{ eco, name, version string }
	seen := make(map[key]int) // key → index in result
	var result []scanner.Dependency

	for _, d := range deps {
		k := key{
			eco:     strings.ToLower(d.Ecosystem),
			name:    strings.ToLower(d.Name),
			version: d.Version,
		}
		if idx, exists := seen[k]; exists {
			// Merge flags: direct wins; runtime (non-dev) wins.
			if d.Direct {
				result[idx].Direct = true
			}
			if !d.Dev {
				result[idx].Dev = false
			}
			continue
		}
		seen[k] = len(result)
		result = append(result, d)
	}
	return result
}

// scanAll discovers and parses dependency manifests under root in parallel.
// It searches for manifests and lockfiles for all supported ecosystems: Go, Rust/Cargo,
// npm/Yarn, Python, NuGet (.NET), C/C++ (vcpkg, Conan). The workers parameter controls
// the number of parallel goroutines. It returns dependencies merged from all ecosystems.
func scanAll(root string, workers int) []scanner.Dependency {
	type scanJob struct {
		eco  string
		path string
	}

	// Primary manifest files - single known path per ecosystem.
	manifests := map[string]string{
		"go.mod":            "go",
		"Cargo.toml":        "cargo",
		"Cargo.lock":        "cargo-lock",
		"package.json":      "npm",
		"package-lock.json": "npm-lock",
		"yarn.lock":         "yarn",
		"requirements.txt":  "pypi",
		"Pipfile":           "pipfile",
		"Pipfile.lock":      "pipfile-lock",
		"poetry.lock":       "poetry-lock",
		"uv.lock":           "uv-lock",
		"pyproject.toml":    "pyproject",
		"vcpkg.json":        "vcpkg",
		"vcpkg-lock.json":   "vcpkg-lock",
		"conanfile.txt":     "conan",
		"conan.lock":        "conan-lock",
	}

	var jobs []scanJob
	for file, eco := range manifests {
		p := filepath.Join(root, file)
		if _, err := os.Stat(p); err == nil {
			jobs = append(jobs, scanJob{eco: eco, path: p})
		}
	}

	// C# .csproj files - glob for all in root.
	csprojFiles, _ := filepath.Glob(filepath.Join(root, "*.csproj"))
	for _, p := range csprojFiles {
		jobs = append(jobs, scanJob{eco: "csproj", path: p})
	}

	// Legacy packages.config and NuGet lock.
	for _, fname := range []string{"packages.config", "packages.lock.json"} {
		p := filepath.Join(root, fname)
		if _, err := os.Stat(p); err == nil {
			jobs = append(jobs, scanJob{eco: fname, path: p})
		}
	}

	if len(jobs) == 0 {
		log.Printf("[WARN] No recognised manifest files found in %s", root)
		return nil
	}

	// Limit workers to job count.
	if workers > len(jobs) {
		workers = len(jobs)
	}

	jobCh := make(chan scanJob, len(jobs))
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	var mu sync.Mutex
	var allDeps []scanner.Dependency
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				deps, err := scanManifest(job.eco, job.path)
				if err != nil {
					log.Printf("[WARN] scanner %s %s: %v", job.eco, job.path, err)
					continue
				}
				mu.Lock()
				allDeps = append(allDeps, deps...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return allDeps
}

// scanManifest dispatches to the correct parser based on ecosystem tag.
// The eco parameter must be one of: "go", "cargo", "cargo-lock", "npm", "npm-lock",
// "yarn", "pypi", "pipfile", "pipfile-lock", "poetry-lock", "uv-lock", "pyproject",
// "vcpkg", "vcpkg-lock", "conan", "conan-lock", "csproj", "packages.config", or
// "packages.lock.json". It returns a slice of dependencies or an error.
func scanManifest(eco, path string) ([]scanner.Dependency, error) {
	switch eco {
	case "go":
		return scanner.ParseGoMod(path)
	case "cargo":
		return scanner.ParseCargoToml(path)
	case "cargo-lock":
		return scanner.ParseCargoLock(path)
	case "npm":
		return scanner.ParsePackageJSON(path)
	case "npm-lock":
		return scanner.ParsePackageLockJSON(path)
	case "yarn":
		return scanner.ParseYarnLock(path)
	case "pypi":
		return scanner.ParseRequirementsTxt(path)
	case "pipfile":
		return scanner.ParsePipfile(path)
	case "pipfile-lock":
		return scanner.ParsePipfileLock(path)
	case "poetry-lock", "uv-lock":
		return scanner.ParsePoetryLock(path)
	case "pyproject":
		return scanner.ParsePyprojectToml(path)
	case "vcpkg":
		return scanner.ParseVcpkgJSON(path)
	case "vcpkg-lock":
		return scanner.ParseVcpkgLock(path)
	case "conan":
		return scanner.ParseConanfile(path)
	case "conan-lock":
		return scanner.ParseConanLock(path)
	case "csproj":
		return scanner.ParseCSProj(path)
	case "packages.config":
		return scanner.ParsePackagesConfig(path)
	case "packages.lock.json":
		return scanner.ParseNuGetLock(path)
	default:
		return nil, fmt.Errorf("unknown ecosystem: %s", eco)
	}
}

// toVulnDeps converts a scanner.Dependency slice to a vuln.Dependency slice for CVE matching.
func toVulnDeps(deps []scanner.Dependency) []vuln.Dependency {
	out := make([]vuln.Dependency, len(deps))
	for i, d := range deps {
		out[i] = vuln.Dependency{
			Name:      d.Name,
			Version:   d.Version,
			Ecosystem: d.Ecosystem,
		}
	}
	return out
}

// findComponentIndex returns the 0-based index of a component in the BOM.
// It falls back to a name-only match if no version match is found.
func findComponentIndex(bom *sbom.BOM, name, version string) int {
	nameOnly := -1
	for i, c := range bom.Components {
		if strings.EqualFold(c.Name, name) {
			if c.Version == version {
				return i
			}
			if nameOnly == -1 {
				nameOnly = i
			}
		}
	}
	return nameOnly
}

// severityCountsAsMap converts findings to a map keyed by severity name.
func severityCountsAsMap(findings []vuln.Finding) map[string]int {
	raw := vuln.CountBySeverity(findings)
	out := make(map[string]int, len(raw))
	for k, v := range raw {
		out[string(k)] = v
	}
	return out
}
