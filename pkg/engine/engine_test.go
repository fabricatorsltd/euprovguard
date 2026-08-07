package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
)

func writeModule(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	manifest := `module example.com/sample

go 1.22

require (
	github.com/example/one v1.2.3
	github.com/example/two v0.4.0
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRunOfflineIsNotAnAllClear is the property that matters to a caller gating
// a build: a scan that could not consult the vulnerability databases reports
// zero findings, and saying so without saying why would be a lie.
func TestRunOfflineIsNotAnAllClear(t *testing.T) {
	result, err := Run(context.Background(), Options{
		Path:        writeModule(t),
		Offline:     true,
		DisableSAST: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Dependencies) != 2 {
		t.Fatalf("dependencies = %d, want 2", len(result.Dependencies))
	}
	if result.BOM == nil || len(result.BOM.Components) != 2 {
		t.Fatalf("the document does not describe the dependencies: %+v", result.BOM)
	}
	if len(result.Vulnerabilities) != 0 {
		t.Fatalf("offline mode reported vulnerabilities: %+v", result.Vulnerabilities)
	}
	if len(result.Degraded) == 0 {
		t.Fatal("an offline scan must record that it is incomplete")
	}
	if result.Clean() {
		t.Fatal("Clean() must be false when the scan was degraded")
	}
	if result.Total() != 0 {
		t.Fatalf("Total() = %d, want 0", result.Total())
	}
}

func TestRunReportsProgressAndDegradation(t *testing.T) {
	var progress, warnings []string
	_, err := Run(context.Background(), Options{
		Path:        writeModule(t),
		Offline:     true,
		DisableSAST: true,
		Logf:        func(format string, args ...any) { progress = append(progress, format) },
		Warnf:       func(format string, args ...any) { warnings = append(warnings, format) },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(progress) == 0 {
		t.Error("no progress was reported")
	}
	if len(warnings) == 0 {
		t.Error("degradation was recorded but never reported as it happened")
	}
}

func TestRunRejectsAnUnusablePath(t *testing.T) {
	if _, err := Run(context.Background(), Options{Path: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("a missing directory must be an error, not an empty scan")
	}

	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{Path: file}); err == nil {
		t.Fatal("a file is not a project root")
	}
}

func TestRunHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Run(ctx, Options{Path: writeModule(t), Offline: true, DisableSAST: true}); err == nil {
		t.Fatal("a cancelled context must stop the scan")
	}
}

func TestMergeDependenciesKeepsTheStrongerClaim(t *testing.T) {
	merged := mergeDependencies([]scanner.Dependency{
		{Ecosystem: "go", Name: "example.com/one", Version: "1.0.0", Direct: false, Dev: true},
		{Ecosystem: "go", Name: "Example.com/One", Version: "1.0.0", Direct: true, Dev: true},
		{Ecosystem: "go", Name: "example.com/one", Version: "1.0.0", Direct: false, Dev: false},
		{Ecosystem: "go", Name: "example.com/two", Version: "2.0.0"},
	})

	if len(merged) != 2 {
		t.Fatalf("merged = %d entries, want 2", len(merged))
	}
	if !merged[0].Direct {
		t.Error("a direct dependency reported once must stay direct")
	}
	if merged[0].Dev {
		t.Error("a runtime dependency reported once must not stay a dev dependency")
	}
}

func TestScanManifestRejectsAnUnknownEcosystem(t *testing.T) {
	if _, err := ScanManifest("brainfuck", "go.mod"); err == nil {
		t.Fatal("an unknown ecosystem must be an error")
	}
}
