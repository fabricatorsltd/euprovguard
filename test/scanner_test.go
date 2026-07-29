package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
	"github.com/fabricatorsltd/euprovguard/pkg/signature"
	"github.com/fabricatorsltd/euprovguard/pkg/vuln"
)

// testdataDir is the path to the internal test fixtures.
const testdataDir = "../internal/testdata"

// go.mod

// TestParseGoMod_BasicDeps verifies that go.mod parsing returns expected packages.
func TestParseGoMod_BasicDeps(t *testing.T) {
	deps, err := scanner.ParseGoMod(filepath.Join(testdataDir, "test-go.mod"))
	if err != nil {
		t.Fatalf("ParseGoMod error: %v", err)
	}
	if len(deps) == 0 {
		t.Fatal("expected at least one dependency, got zero")
	}

	names := depNames(deps)
	assertContains(t, names, "github.com/gin-gonic/gin")
	assertContains(t, names, "golang.org/x/text")
}

// TestParseGoMod_Ecosystem verifies all returned deps have ecosystem="go".
func TestParseGoMod_Ecosystem(t *testing.T) {
	deps, err := scanner.ParseGoMod(filepath.Join(testdataDir, "test-go.mod"))
	if err != nil {
		t.Fatalf("ParseGoMod error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != "go" {
			t.Errorf("expected ecosystem=go, got %q for %s", d.Ecosystem, d.Name)
		}
	}
}

// TestParseGoMod_PURL verifies that PURL values are well-formed pkg:golang/... strings.
func TestParseGoMod_PURL(t *testing.T) {
	deps, err := scanner.ParseGoMod(filepath.Join(testdataDir, "test-go.mod"))
	if err != nil {
		t.Fatalf("ParseGoMod error: %v", err)
	}
	for _, d := range deps {
		if !strings.HasPrefix(d.PURL, "pkg:golang/") {
			t.Errorf("bad PURL for %s: %q", d.Name, d.PURL)
		}
	}
}

// TestParseGoMod_NotFound verifies an error is returned for missing files.
func TestParseGoMod_NotFound(t *testing.T) {
	_, err := scanner.ParseGoMod("/nonexistent/go.mod")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// Cargo.toml

// TestParseCargoToml_BasicDeps verifies that Cargo.toml parsing returns expected crates.
func TestParseCargoToml_BasicDeps(t *testing.T) {
	deps, err := scanner.ParseCargoToml(filepath.Join(testdataDir, "test-cargo.toml"))
	if err != nil {
		t.Fatalf("ParseCargoToml error: %v", err)
	}
	if len(deps) == 0 {
		t.Fatal("expected at least one dependency")
	}

	names := depNames(deps)
	assertContains(t, names, "serde")
	assertContains(t, names, "tokio")
	assertContains(t, names, "hyper")
}

// TestParseCargoToml_Ecosystem verifies all deps have ecosystem="cargo".
func TestParseCargoToml_Ecosystem(t *testing.T) {
	deps, err := scanner.ParseCargoToml(filepath.Join(testdataDir, "test-cargo.toml"))
	if err != nil {
		t.Fatalf("ParseCargoToml error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != "cargo" {
			t.Errorf("expected ecosystem=cargo, got %q for %s", d.Ecosystem, d.Name)
		}
	}
}

// TestParseCargoToml_PURL verifies pkg:cargo/... PURL format.
func TestParseCargoToml_PURL(t *testing.T) {
	deps, err := scanner.ParseCargoToml(filepath.Join(testdataDir, "test-cargo.toml"))
	if err != nil {
		t.Fatalf("ParseCargoToml error: %v", err)
	}
	for _, d := range deps {
		if !strings.HasPrefix(d.PURL, "pkg:cargo/") {
			t.Errorf("bad PURL for %s: %q", d.Name, d.PURL)
		}
	}
}

// package.json

// TestParsePackageJSON_BasicDeps verifies package.json parsing returns expected packages.
func TestParsePackageJSON_BasicDeps(t *testing.T) {
	deps, err := scanner.ParsePackageJSON(filepath.Join(testdataDir, "test-package.json"))
	if err != nil {
		t.Fatalf("ParsePackageJSON error: %v", err)
	}
	if len(deps) == 0 {
		t.Fatal("expected at least one dependency")
	}
}

// TestParsePackageJSON_Ecosystem verifies all deps have ecosystem="npm".
func TestParsePackageJSON_Ecosystem(t *testing.T) {
	deps, err := scanner.ParsePackageJSON(filepath.Join(testdataDir, "test-package.json"))
	if err != nil {
		t.Fatalf("ParsePackageJSON error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != "npm" {
			t.Errorf("expected ecosystem=npm, got %q for %s", d.Ecosystem, d.Name)
		}
	}
}

// TestParsePackageJSON_VersionStripped verifies semver range chars are stripped.
func TestParsePackageJSON_VersionStripped(t *testing.T) {
	deps, err := scanner.ParsePackageJSON(filepath.Join(testdataDir, "test-package.json"))
	if err != nil {
		t.Fatalf("ParsePackageJSON error: %v", err)
	}
	for _, d := range deps {
		if strings.ContainsAny(d.Version, "^~>=<") {
			t.Errorf("version not stripped for %s: %q", d.Name, d.Version)
		}
	}
}

// BuildPURL

// TestBuildPURL_AllEcosystems verifies PURL construction for all supported ecosystems.
func TestBuildPURL_AllEcosystems(t *testing.T) {
	cases := []struct {
		eco, name, ver, want string
	}{
		{"go", "github.com/foo/bar", "v1.0.0", "pkg:golang/github.com/foo/bar@v1.0.0"},
		{"cargo", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"},
		{"npm", "express", "4.18.2", "pkg:npm/express@4.18.2"},
		{"pypi", "Requests", "2.28.0", "pkg:pypi/requests@2.28.0"},
		{"unknown", "foo", "1.0", "pkg:generic/foo@1.0"},
	}
	for _, c := range cases {
		got := scanner.BuildPURL(c.eco, c.name, c.ver)
		if got != c.want {
			t.Errorf("BuildPURL(%q,%q,%q) = %q, want %q", c.eco, c.name, c.ver, got, c.want)
		}
	}
}

// SBOM: CycloneDX generation

// TestGenerateBOM_Fields verifies that generated BOM has correct top-level fields.
func TestGenerateBOM_Fields(t *testing.T) {
	deps := []scanner.Dependency{
		{Name: "foo", Version: "1.0.0", Ecosystem: "go", PURL: "pkg:golang/foo@1.0.0", Direct: true},
		{Name: "bar", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/bar@2.0.0", Direct: false},
	}
	bom := sbom.Generate(deps, sbom.GeneratorOptions{
		ProjectName:    "myproject",
		ProjectVersion: "0.1.0",
		ToolVersion:    "1.0.0",
	})

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.6" {
		t.Errorf("SpecVersion = %q, want 1.6", bom.SpecVersion)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("SerialNumber missing urn:uuid: prefix: %q", bom.SerialNumber)
	}
	if len(bom.Components) != 2 {
		t.Errorf("expected 2 components, got %d", len(bom.Components))
	}
	if bom.Metadata.Component == nil {
		t.Error("Metadata.Component should not be nil when ProjectName is set")
	}
}

// TestGenerateBOM_ComponentScope verifies scope assignment based on Dev flag.
// CRA compliance: runtime transitive deps are "required"; dev-only deps are "optional".
func TestGenerateBOM_ComponentScope(t *testing.T) {
	deps := []scanner.Dependency{
		{Name: "a", Ecosystem: "go", Direct: true, Dev: false},  // runtime direct → required
		{Name: "b", Ecosystem: "go", Direct: false, Dev: false}, // runtime transitive → required
		{Name: "c", Ecosystem: "go", Direct: false, Dev: true},  // dev-only → optional
	}
	bom := sbom.Generate(deps, sbom.GeneratorOptions{ToolVersion: "1.0.0"})
	if bom.Components[0].Scope != "required" {
		t.Errorf("direct dep scope = %q, want required", bom.Components[0].Scope)
	}
	if bom.Components[1].Scope != "required" {
		t.Errorf("transitive runtime dep scope = %q, want required", bom.Components[1].Scope)
	}
	if bom.Components[2].Scope != "optional" {
		t.Errorf("dev dep scope = %q, want optional", bom.Components[2].Scope)
	}
}

// TestWriteReadBOM_RoundTrip verifies JSON serialisation/deserialisation round-trip.
func TestWriteReadBOM_RoundTrip(t *testing.T) {
	deps := []scanner.Dependency{
		{Name: "round-trip-pkg", Version: "3.0.0", Ecosystem: "npm",
			PURL: "pkg:npm/round-trip-pkg@3.0.0", Direct: true},
	}
	bom := sbom.Generate(deps, sbom.GeneratorOptions{ToolVersion: "1.0.0"})

	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := sbom.WriteJSON(bom, tmp); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	loaded, err := sbom.ReadJSON(tmp)
	if err != nil {
		t.Fatalf("ReadJSON error: %v", err)
	}
	if loaded.SerialNumber != bom.SerialNumber {
		t.Errorf("SerialNumber mismatch: got %q want %q", loaded.SerialNumber, bom.SerialNumber)
	}
	if len(loaded.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(loaded.Components))
	}
}

// TestWriteReadBOM_ValidJSON verifies the output file is valid JSON.
func TestWriteReadBOM_ValidJSON(t *testing.T) {
	bom := sbom.Generate(nil, sbom.GeneratorOptions{ToolVersion: "1.0.0"})
	tmp := filepath.Join(t.TempDir(), "sbom.json")
	if err := sbom.WriteJSON(bom, tmp); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	data, _ := os.ReadFile(tmp)
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}
}

// Embedded CVE matcher tests have been removed.
// All vulnerability matching is now performed via live OSV.dev and EUVD queries.
// Use MatchLive for integration testing instead.

// TestCountBySeverity_Counts verifies severity counting logic.
func TestCountBySeverity_Counts(t *testing.T) {
	findings := []vuln.Finding{
		{CVE: vuln.CVEEntry{Severity: vuln.SEVERITY_CRITICAL}},
		{CVE: vuln.CVEEntry{Severity: vuln.SEVERITY_CRITICAL}},
		{CVE: vuln.CVEEntry{Severity: vuln.SEVERITY_HIGH}},
		{CVE: vuln.CVEEntry{Severity: vuln.SEVERITY_LOW}},
	}
	counts := vuln.CountBySeverity(findings)
	if counts[vuln.SEVERITY_CRITICAL] != 2 {
		t.Errorf("CRITICAL count = %d, want 2", counts[vuln.SEVERITY_CRITICAL])
	}
	if counts[vuln.SEVERITY_HIGH] != 1 {
		t.Errorf("HIGH count = %d, want 1", counts[vuln.SEVERITY_HIGH])
	}
}

// Signature: RSA-4096

// TestRSASignVerify_RoundTrip verifies that Sign/Verify round-trip succeeds.
func TestRSASignVerify_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	if err := signature.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}

	priv, err := signature.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey error: %v", err)
	}
	pub, err := signature.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey error: %v", err)
	}

	data := []byte(`{"test":"data","value":42}`)
	sig, err := signature.Sign(priv, data)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if err := signature.Verify(pub, data, sig); err != nil {
		t.Errorf("Verify error: %v", err)
	}
}

// TestRSAVerify_TamperedData verifies that verification fails on modified data.
func TestRSAVerify_TamperedData(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	if err := signature.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, _ := signature.LoadPrivateKey(privPath)
	pub, _ := signature.LoadPublicKey(pubPath)

	data := []byte("original data")
	sig, _ := signature.Sign(priv, data)

	tampered := []byte("tampered data")
	if err := signature.Verify(pub, tampered, sig); err == nil {
		t.Error("Verify should fail on tampered data, but returned nil")
	}
}

// TestQESSignVerify_Document verifies the QES envelope sign/verify cycle.
func TestQESSignVerify_Document(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	if err := signature.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, _ := signature.LoadPrivateKey(privPath)
	pub, _ := signature.LoadPublicKey(pubPath)

	payload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	doc, err := signature.SignDocument(payload, signature.QESSignOptions{
		PrivateKey: priv,
	})
	if err != nil {
		t.Fatalf("SignDocument error: %v", err)
	}
	if doc.Algorithm != signature.QES_SIGNATURE_ALGORITHM {
		t.Errorf("Algorithm = %q, want %q", doc.Algorithm, signature.QES_SIGNATURE_ALGORITHM)
	}

	if err := signature.VerifyDocument(doc, pub); err != nil {
		t.Errorf("VerifyDocument error: %v", err)
	}
}

// TestQESSignedDocument_WriteRead verifies round-trip file serialisation.
func TestQESSignedDocument_WriteRead(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	if err := signature.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, _ := signature.LoadPrivateKey(privPath)
	pub, _ := signature.LoadPublicKey(pubPath)

	payload := []byte(`{"test":true}`)
	doc, _ := signature.SignDocument(payload, signature.QESSignOptions{PrivateKey: priv})

	outPath := filepath.Join(dir, "signed.json")
	if err := signature.WriteSignedDocument(doc, outPath); err != nil {
		t.Fatalf("WriteSignedDocument: %v", err)
	}

	loaded, err := signature.ReadSignedDocument(outPath)
	if err != nil {
		t.Fatalf("ReadSignedDocument: %v", err)
	}
	if err := signature.VerifyDocument(loaded, pub); err != nil {
		t.Errorf("VerifyDocument after reload: %v", err)
	}
}

// Signature: VerifySBOM

// TestVerifySBOM_ValidDocument verifies that VerifySBOM returns Valid=true for correct input.
func TestVerifySBOM_ValidDocument(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	if err := signature.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, _ := signature.LoadPrivateKey(privPath)
	pub, _ := signature.LoadPublicKey(pubPath)

	payload := []byte(`{"bomFormat":"CycloneDX"}`)
	doc, _ := signature.SignDocument(payload, signature.QESSignOptions{PrivateKey: priv})
	signedPath := filepath.Join(dir, "sbom.json.signed")
	signature.WriteSignedDocument(doc, signedPath)

	result, err := signature.VerifySBOM(signedPath, pub)
	if err != nil {
		t.Fatalf("VerifySBOM error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected Valid=true, got false. Errors: %v", result.Errors)
	}
}

// depNames returns a slice of dependency names for assertion helpers.
func depNames(deps []scanner.Dependency) []string {
	out := make([]string, len(deps))
	for i, d := range deps {
		out[i] = d.Name
	}
	return out
}

// assertContains fails the test if needle is not in haystack.
func assertContains(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, s := range haystack {
		if s == needle {
			return
		}
	}
	t.Errorf("expected %q in list, not found.\nList: %v", needle, haystack)
}

// EUVD Client (unit tests, no network)

// TestNormalizeCVSS_Thresholds verifies CVSS score to Severity mapping.
func TestNormalizeCVSS_Thresholds(t *testing.T) {
	cases := []struct {
		score    float64
		expected vuln.Severity
	}{
		{9.8, vuln.SEVERITY_CRITICAL},
		{9.0, vuln.SEVERITY_CRITICAL},
		{8.9, vuln.SEVERITY_HIGH},
		{7.0, vuln.SEVERITY_HIGH},
		{6.9, vuln.SEVERITY_MEDIUM},
		{4.0, vuln.SEVERITY_MEDIUM},
		{3.9, vuln.SEVERITY_LOW},
		{0.1, vuln.SEVERITY_LOW},
		{0.0, vuln.SEVERITY_NONE},
	}
	for _, tc := range cases {
		got := vuln.NormalizeCVSS(tc.score)
		if got != tc.expected {
			t.Errorf("NormalizeCVSS(%.1f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

// TestExtractCVEAlias_PrefersCVE verifies CVE alias extraction from newline-separated aliases.
func TestExtractCVEAlias_PrefersCVE(t *testing.T) {
	aliases := "GHSA-xxxx-yyyy-zzzz\nCVE-2025-99999\nGHSA-aaaa-bbbb-cccc\n"
	got := vuln.ExtractCVEAlias(aliases, "EUVD-2025-12345")
	if got != "CVE-2025-99999" {
		t.Errorf("ExtractCVEAlias = %q, want CVE-2025-99999", got)
	}
}

// TestExtractCVEAlias_FallbackToEUVD verifies fallback to EUVD ID when no CVE alias present.
func TestExtractCVEAlias_FallbackToEUVD(t *testing.T) {
	aliases := "GHSA-xxxx-yyyy-zzzz\n"
	got := vuln.ExtractCVEAlias(aliases, "EUVD-2026-99999")
	if got != "EUVD-2026-99999" {
		t.Errorf("ExtractCVEAlias = %q, want EUVD-2026-99999", got)
	}
}

// TestEuvdItemToEntry_MatchesExact verifies that product name exact match returns entry.
func TestEuvdItemToEntry_MatchesExact(t *testing.T) {
	entry, ok := vuln.EuvdItemToEntryTest("openssl", "openssl", 9.8, "3.1", "CVE-2024-1234\n", "EUVD-2024-1234", "")
	if !ok {
		t.Fatal("expected match for exact product name, got false")
	}
	if entry.CVSS != 9.8 {
		t.Errorf("CVSS = %.1f, want 9.8", entry.CVSS)
	}
	if entry.Severity != vuln.SEVERITY_CRITICAL {
		t.Errorf("Severity = %q, want CRITICAL", entry.Severity)
	}
	if entry.ID != "CVE-2024-1234" {
		t.Errorf("ID = %q, want CVE-2024-1234", entry.ID)
	}
	if entry.EuvdID != "EUVD-2024-1234" {
		t.Errorf("EuvdID = %q, want EUVD-2024-1234", entry.EuvdID)
	}
	if entry.ScoreMethod != "CVSSv31" {
		t.Errorf("ScoreMethod = %q, want CVSSv31", entry.ScoreMethod)
	}
}

// TestEuvdItemToEntry_NoMatch verifies that mismatched product name returns false.
func TestEuvdItemToEntry_NoMatch(t *testing.T) {
	_, ok := vuln.EuvdItemToEntryTest("openssl", "nginx", 9.8, "3.1", "", "EUVD-2024-9999", "")
	if ok {
		t.Error("expected no match for different product name, got true")
	}
}

// TestEuvdItemToEntry_CVSS40Method verifies that CVSS 4.0 entries use CVSSv40 method.
func TestEuvdItemToEntry_CVSS40Method(t *testing.T) {
	entry, ok := vuln.EuvdItemToEntryTest("mlflow", "MLflow", 5.1, "4.0", "CVE-2026-1234\n", "EUVD-2026-1234", "")
	if !ok {
		t.Fatal("expected match")
	}
	if entry.ScoreMethod != "CVSSv40" {
		t.Errorf("ScoreMethod = %q, want CVSSv40", entry.ScoreMethod)
	}
}

// TestEuvdItemToEntry_ExploitedFlag verifies exploitedSince presence sets Exploited=true.
func TestEuvdItemToEntry_ExploitedFlag(t *testing.T) {
	entry, ok := vuln.EuvdItemToEntryTest("FortiClientEMS", "FortiClientEMS", 9.1, "3.1",
		"CVE-2026-35616\n", "EUVD-2026-18963", "Apr 6, 2026, 12:00:00 AM")
	if !ok {
		t.Fatal("expected match")
	}
	if !entry.Exploited {
		t.Error("expected Exploited=true when exploitedSince is set")
	}
}

// TestEuvdItemToEntry_CaseInsensitive verifies case-insensitive product name matching.
func TestEuvdItemToEntry_CaseInsensitive(t *testing.T) {
	_, ok := vuln.EuvdItemToEntryTest("OpenSSL", "openssl", 7.5, "3.1", "", "EUVD-2024-0001", "")
	if !ok {
		t.Error("expected case-insensitive match, got false")
	}
}
