// Package engine runs the EUProvGuard pipeline in process.
//
// The CLI is one caller of this package, not its owner: everything the scan
// needs is here, so another tool can produce the same SBOM and the same
// findings without shelling out to a binary it has to locate, version, and
// trust.
//
// The pipeline is deliberately honest about degradation. Vulnerability
// matching, the CWE catalogue, and the OWASP rule set all need the network, and
// a scan that could not reach them is not a clean scan: it is an incomplete one.
// Those cases are recorded in Result.Degraded rather than reduced to a log line,
// so a caller can refuse to treat an empty finding list as an all clear.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
	"github.com/fabricatorsltd/euprovguard/pkg/vuln"
)

// DefaultWorkers is the parallelism used when Options.Workers is not set.
const DefaultWorkers = 4

// Options configures a scan.
type Options struct {
	// Path is the project root to scan. Defaults to the working directory.
	Path string
	// ProjectName defaults to the base name of Path.
	ProjectName string
	// ProjectVersion is recorded in the SBOM metadata.
	ProjectVersion string
	// ToolVersion identifies the caller in the SBOM metadata.
	ToolVersion string
	// Workers bounds the parallel manifest scanners and SAST workers.
	Workers int
	// DisableSAST skips the native static analysis pass.
	DisableSAST bool
	// Offline skips every network step: no OSV or EUVD queries, no CWE
	// catalogue, no OWASP rule set. The result is marked degraded, because
	// an offline scan cannot report vulnerabilities disclosed since the
	// binary was built.
	Offline bool
	// Logf receives progress messages as they happen. Nil discards them,
	// which is the right default for a library. The wording of these
	// messages is a compatibility surface: pipelines grep it, so it stays
	// as the command line tool has always emitted it.
	Logf func(format string, args ...any)
	// Warnf receives degradation notices as they happen. The same text is
	// also collected in Result.Degraded, so a caller can react after the
	// fact instead of watching the stream. Nil discards them.
	Warnf func(format string, args ...any)
}

// Result is everything one scan produced.
type Result struct {
	// BOM is the CycloneDX document, with vulnerabilities and SAST findings
	// already attached.
	BOM *sbom.BOM
	// Dependencies are the merged dependencies of every ecosystem found.
	Dependencies []scanner.Dependency
	// RawDependencies is the count before merging duplicates.
	RawDependencies int
	// Vulnerabilities are the CVE matches for those dependencies.
	Vulnerabilities []vuln.Finding
	// SAST holds the native static analysis findings.
	SAST []scanner.Finding
	// SeverityCounts summarises Vulnerabilities by severity name.
	SeverityCounts map[string]int
	// EUVD is the ENISA snapshot used, when the query succeeded.
	EUVD *vuln.EuvdSnapshot
	// Provenance records the catalogues consulted, for CRA documentation.
	Provenance []sbom.CatalogInfo
	// Degraded lists the reasons this scan is less than complete. A result
	// with no findings and a non-empty Degraded is not an all clear.
	Degraded []string
}

// Total returns the number of findings of any kind.
func (r *Result) Total() int {
	return len(r.Vulnerabilities) + len(r.SAST)
}

// Clean reports whether the scan found nothing and ran without degradation.
// A caller that gates a build on the scan should use this rather than counting
// findings, because an empty list from a scan that could not reach the
// vulnerability databases means nothing.
func (r *Result) Clean() bool {
	return r.Total() == 0 && len(r.Degraded) == 0
}

// Run executes the pipeline: discover manifests, merge dependencies, match
// vulnerabilities, consult the catalogues, run static analysis, and build the
// SBOM. Writing the SBOM or a report is left to the caller; see sbom.WriteJSON
// and the report package.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Path == "" {
		opts.Path = "."
	}
	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("euprovguard: resolve %q: %w", opts.Path, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("euprovguard: %q is not reachable: %w", opts.Path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("euprovguard: %q is not a directory", opts.Path)
	}
	if opts.ProjectName == "" {
		opts.ProjectName = filepath.Base(root)
	}
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}
	result := &Result{}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	warnf := opts.Warnf
	if warnf == nil {
		warnf = func(string, ...any) {}
	}
	degrade := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		result.Degraded = append(result.Degraded, message)
		warnf("%s", message)
	}

	// 1. Discover and parse every manifest under the root.
	raw, warnings := scanAll(root, opts.Workers)
	for _, warning := range warnings {
		warnf("scanner %s", warning)
	}
	result.RawDependencies = len(raw)
	result.Dependencies = mergeDependencies(raw)
	logf("Total dependencies found: %d (merged from %d raw entries)", len(result.Dependencies), len(raw))

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 2. Match the dependencies against the live vulnerability databases.
	if opts.Offline {
		degrade("offline mode: vulnerabilities were not matched, so an empty finding list means nothing")
	} else {
		logf("Vulnerability mode: OSV.dev + EUVD live queries (CRA Annex I compliant)")
		findings, snapshot, err := vuln.MatchLive(toVulnerabilityDeps(result.Dependencies))
		if err != nil {
			degrade("OSV/EUVD query failed: %v - proceeding with no CVE findings", err)
		} else {
			result.Vulnerabilities = findings
			result.EUVD = &snapshot
		}
	}
	logf("CVE findings: %d", len(result.Vulnerabilities))
	result.SeverityCounts = severityCounts(result.Vulnerabilities)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 3. Consult the CWE catalogue, for the provenance record.
	if !opts.Offline {
		if entry, err := fetchCWECatalogue(); err != nil {
			degrade("CWE catalogue unavailable: %v", err)
		} else {
			result.Provenance = append(result.Provenance, *entry)
		}
	}

	// 4. Static analysis, enriched with the OWASP rule set when reachable.
	if !opts.DisableSAST {
		var extraRules []scanner.SASTRule
		if !opts.Offline {
			crsDir := filepath.Join(os.TempDir(), "euprovguard-crs")
			if err := scanner.FetchLatestCRS(crsDir); err != nil {
				degrade("Failed to fetch CRS: %v - using embedded rules only", err)
			} else {
				extraRules = scanner.ParseCRSRules(crsDir)
				result.Provenance = append(result.Provenance, sbom.CatalogInfo{
					Name:      "OWASP CRS",
					Version:   "latest",
					Date:      time.Now().Format("2006-01-02"),
					Signature: "verified-via-atom-feed",
					Fetched:   time.Now().Format(time.RFC3339),
				})
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result.SAST = scanner.RunSAST(root, opts.Workers, extraRules)
	}

	// 5. Build the document and attach everything found to it.
	result.BOM = sbom.Generate(result.Dependencies, sbom.GeneratorOptions{
		ProjectName:    opts.ProjectName,
		ProjectVersion: opts.ProjectVersion,
		ToolVersion:    opts.ToolVersion,
	})
	result.BOM.Provenance = result.Provenance
	attachFindings(result)
	return result, nil
}

func attachFindings(result *Result) {
	for _, finding := range result.Vulnerabilities {
		index := findComponentIndex(result.BOM, finding.Component, finding.CVE.Package)
		if index < 0 {
			index = 0
		}
		sbom.AddVulnerability(result.BOM,
			finding.CVE.ID,
			finding.CVE.Description,
			finding.CVE.CVSS,
			strings.ToLower(string(finding.CVE.Severity)),
			finding.CVE.ScoreMethod,
			fmt.Sprintf("comp-%d", index+1),
		)
	}
	for index, finding := range result.SAST {
		sbom.AddSASTFinding(result.BOM,
			fmt.Sprintf("SAST-%03d", index+1),
			finding.ToolName,
			finding.RuleID,
			finding.Description,
			finding.File,
			finding.Line,
			finding.Severity,
			finding.CWEs,
		)
	}
}

func fetchCWECatalogue() (*sbom.CatalogInfo, error) {
	dir := filepath.Join(os.TempDir(), "euprovguard-cwe")
	archive := filepath.Join(dir, "cwe.zip")

	meta, err := vuln.FetchCatalog("MITRE-CWE", vuln.CWE_XML_URL, archive)
	if err != nil {
		return nil, err
	}
	files, err := vuln.Unzip(archive, dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("the catalogue archive was empty")
	}
	catalogue, err := vuln.LoadCWEXML(files[0])
	if err != nil {
		return nil, err
	}
	return &sbom.CatalogInfo{
		Name:      "MITRE CWE",
		Version:   catalogue.Version,
		Date:      catalogue.Date,
		Signature: meta.Hash,
		Fetched:   meta.FetchedAt.Format(time.RFC3339),
	}, nil
}

// mergeDependencies collapses duplicates reported by several manifests of the
// same ecosystem. Direct wins over transitive, and runtime wins over dev.
func mergeDependencies(deps []scanner.Dependency) []scanner.Dependency {
	type key struct{ ecosystem, name, version string }

	seen := make(map[key]int, len(deps))
	var merged []scanner.Dependency
	for _, dep := range deps {
		identity := key{
			ecosystem: strings.ToLower(dep.Ecosystem),
			name:      strings.ToLower(dep.Name),
			version:   dep.Version,
		}
		if index, exists := seen[identity]; exists {
			if dep.Direct {
				merged[index].Direct = true
			}
			if !dep.Dev {
				merged[index].Dev = false
			}
			continue
		}
		seen[identity] = len(merged)
		merged = append(merged, dep)
	}
	return merged
}

// manifests maps a file name to the ecosystem parser that understands it.
var manifests = map[string]string{
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

// scanAll discovers and parses the manifests under root in parallel. Warnings
// are returned rather than logged, so the caller decides where they go.
func scanAll(root string, workers int) ([]scanner.Dependency, []string) {
	type job struct{ ecosystem, path string }

	var jobs []job
	for file, ecosystem := range manifests {
		path := filepath.Join(root, file)
		if _, err := os.Stat(path); err == nil {
			jobs = append(jobs, job{ecosystem: ecosystem, path: path})
		}
	}
	projects, _ := filepath.Glob(filepath.Join(root, "*.csproj"))
	for _, path := range projects {
		jobs = append(jobs, job{ecosystem: "csproj", path: path})
	}
	for _, file := range []string{"packages.config", "packages.lock.json"} {
		path := filepath.Join(root, file)
		if _, err := os.Stat(path); err == nil {
			jobs = append(jobs, job{ecosystem: file, path: path})
		}
	}

	if len(jobs) == 0 {
		return nil, []string{fmt.Sprintf("no recognised manifest found in %s", root)}
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}

	queue := make(chan job, len(jobs))
	for _, entry := range jobs {
		queue <- entry
	}
	close(queue)

	var (
		mutex    sync.Mutex
		found    []scanner.Dependency
		warnings []string
		group    sync.WaitGroup
	)
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for entry := range queue {
				deps, err := ScanManifest(entry.ecosystem, entry.path)
				mutex.Lock()
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s %s: %v", entry.ecosystem, entry.path, err))
				} else {
					found = append(found, deps...)
				}
				mutex.Unlock()
			}
		}()
	}
	group.Wait()
	return found, warnings
}

// ScanManifest parses one manifest with the parser for its ecosystem. It is
// exported for callers that already know which file they want to read.
func ScanManifest(ecosystem, path string) ([]scanner.Dependency, error) {
	switch ecosystem {
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
		return nil, fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}
}

func toVulnerabilityDeps(deps []scanner.Dependency) []vuln.Dependency {
	converted := make([]vuln.Dependency, len(deps))
	for index, dep := range deps {
		converted[index] = vuln.Dependency{
			Name:      dep.Name,
			Version:   dep.Version,
			Ecosystem: dep.Ecosystem,
		}
	}
	return converted
}

// findComponentIndex returns the position of a component in the document,
// falling back to a name-only match when the version does not line up.
func findComponentIndex(bom *sbom.BOM, name, version string) int {
	nameOnly := -1
	for index, component := range bom.Components {
		if !strings.EqualFold(component.Name, name) {
			continue
		}
		if component.Version == version {
			return index
		}
		if nameOnly == -1 {
			nameOnly = index
		}
	}
	return nameOnly
}

func severityCounts(findings []vuln.Finding) map[string]int {
	raw := vuln.CountBySeverity(findings)
	counts := make(map[string]int, len(raw))
	for severity, count := range raw {
		counts[string(severity)] = count
	}
	return counts
}
