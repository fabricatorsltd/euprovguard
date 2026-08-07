package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/fabricatorsltd/euprovguard/pkg/engine"
	"github.com/fabricatorsltd/euprovguard/pkg/report"
	"github.com/fabricatorsltd/euprovguard/pkg/sbom"
	"github.com/fabricatorsltd/euprovguard/pkg/scanner"
	"github.com/fabricatorsltd/euprovguard/pkg/signature"
)

// Version is the EUProvGuard release version.
const Version = "1.2.1"

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

	// The pipeline lives in pkg/engine so that other tools can run exactly
	// this scan in process. The CLI keeps its own reporting: the lines below
	// are the contract other pipelines grep for.
	result, err := engine.Run(context.Background(), engine.Options{
		Path:           cfg.Path,
		ProjectName:    cfg.ProjectName,
		ProjectVersion: cfg.ProjectVersion,
		ToolVersion:    Version,
		Workers:        cfg.Workers,
		DisableSAST:    !cfg.EnableSAST,
		Logf:           func(format string, args ...any) { log.Printf("[INFO] "+format, args...) },
		Warnf:          func(format string, args ...any) { log.Printf("[WARN] "+format, args...) },
	})
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}

	bom := result.BOM
	findings := result.Vulnerabilities
	sastFindings := result.SAST
	euvdSnap := result.EUVD

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
			SeverityCounts: result.SeverityCounts,
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
