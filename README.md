# EUProvGuard

EU-compliant Software Bill of Materials (SBOM) generator with Qualified Electronic Signature (QES) support.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8)](go.mod)

**Note on CRA Annex I:** EUProvGuard provides the technical artifacts required for compliance (SBOM generation and disclosure of known vulnerabilities). The manufacturer remains legally responsible for establishing a **Coordinated Vulnerability Disclosure (CVD) policy** and the actual delivery of security updates.

## Quick Start

### Build

```bash
make build

# Cross-compile for all platforms
make build-all
```

### Generate SBOM

```bash
# Scan a Go project and generate CycloneDX 1.6 SBOM
./dist/euprovguard -path /path/to/project -output sbom.json

# Sign with RSA-4096 key
./dist/euprovguard -path /path/to/project -output sbom.json \
    -sign -key /path/to/private.pem

# Sign + timestamp via Aruba TSA (eIDAS Article 26)
./dist/euprovguard -path /path/to/project -output sbom.json \
    -sign -key /path/to/private.pem \
    -tsa https://tsa.aruba.it/tsa

# Generate full compliance reports
./dist/euprovguard -path /path/to/project \
    -report report.html -text-report report.txt

# Verify signed SBOM
./dist/euprovguard -verify -input sbom.json.signed -pubkey /path/to/public.pem
```

### Flags

| Flag             | Default      | Description                                          |
|------------------|--------------|------------------------------------------------------|
| `-path`          | `.`          | Project root to scan                                 |
| `-output`        | `sbom.json`  | SBOM output file                                     |
| `-name`          | `(dir name)` | Override project name in SBOM                        |
| `-version-tag`   | `0.0.0`      | Project version                                      |
| `-sign`          | `false`      | Sign SBOM (QES if backed by QSCD + Qual. Cert)       |
| `-key`           | ``           | Path to private key (PEM)                            |
| `-pubkey`        | ``           | Path to public key (PEM)                             |
| `-tsa`           | ``           | TSA endpoint URL (RFC 3161)                          |
| `-report`        | ``           | HTML compliance report path                          |
| `-text-report`   | ``           | Plain-text report path                               |
| `-bundle`        | ``           | Base path for all report formats (.html, .txt)       |
| `-sast`          | `true`       | Enable native SAST engine (CRS-enhanced)             |
| `-verify`        | `false`      | Verify mode (requires `-input`, `-pubkey`)           |
| `-input`         | ``           | Signed SBOM to verify                                |
| `-workers`       | `4`          | Parallel scanner workers                             |
| `-version`       |              | Print version and exit                               |

## Use as a library

The whole pipeline is importable, so a build tool can produce the same SBOM and
the same findings in process, without locating, versioning and trusting a
separate binary.

```go
import "github.com/fabricatorsltd/euprovguard/pkg/engine"

result, err := engine.Run(ctx, engine.Options{
    Path:           "./",
    ProjectName:    "my-service",
    ProjectVersion: "1.4.0",
    ToolVersion:    "my-tool/2.1",
})
if err != nil {
    return err
}

if !result.Clean() {
    // result.Vulnerabilities, result.SAST and result.Degraded say what happened.
}
```

`Result.Clean()` is the check to gate a build on, and it is deliberately stricter
than counting findings. Vulnerability matching, the CWE catalogue and the OWASP
rule set all need the network, and a scan that could not reach them reports zero
findings for a reason that is not "nothing is wrong". Those cases land in
`Result.Degraded`, so an incomplete scan cannot be mistaken for a clean one.

`Options.Offline` skips every network step and always marks the result degraded.
`Options.Logf` and `Options.Warnf` receive progress and degradation as they
happen; the CLI wires them to its own output.

Writing files is left to the caller: `sbom.WriteJSON` and the `report` package
take the document from `Result.BOM`.

## Supported Ecosystems

| Language  | Manifests                                                                                 | PURL Type                        |
|-----------|-------------------------------------------------------------------------------------------|----------------------------------|
| Go        | `go.mod`                                                                                  | `pkg:golang`                     |
| Rust      | `Cargo.toml`, `Cargo.lock`                                                                | `pkg:cargo`                      |
| Node.js   | `package.json`, `package-lock.json`, `yarn.lock`                                          | `pkg:npm`                        |
| Python    | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pyproject.toml` | `pkg:pypi`                       |
| C# / .NET | `*.csproj`, `packages.config`, `packages.lock.json`                                       | `pkg:nuget`                      |
| C / C++   | `vcpkg.json`, `vcpkg-lock.json`, `conanfile.txt`, `conan.lock`                            | `pkg:conan`, `pkg:generic/vcpkg` |

Transitive dependencies are resolved from lockfiles where available (CRA Art. 13 Annex I - full supply
chain visibility).

## Native SAST & Proprietary Code

EUProvGuard includes an **optimized native SAST engine** designed for performance on large codebases. 
Unlike generic scanners, it uses a selective scanning logic that ignores build artifacts, binary data, and 
heavy dependency folders (node_modules, venv, target, etc.).

It integrates directly with:
- **OWASP Core Rule Set (CRS):** Dynamically fetched patterns for enterprise-grade security checks.
- **MITRE CWE:** Findings are mapped to the Common Weakness Enumeration for CRA technical documentation.

## eIDAS QES & Legal Attribution

EUProvGuard provides the technical implementation for signing SBOMs with RSA-4096. However, under 
**eIDAS (EU) 2024/1183**, a signature is only "Qualified" (QES) if it is:
1.  Created by a **Qualified Signature Creation Device (QSCD)** (e.g., YubiKey 5, Nitrokey HSM).
2.  Based on a **Qualified Certificate** issued by a **Qualified Trust Service Provider (QTSP)**.

**Important:** EUProvGuard is *not* a QTSP. It acts as the signature creation application that 
integrates with your existing qualified infrastructure. The legal qualification of the signature 
depends entirely on the certificate and the hardware (QSCD) used, not on the software binary itself.

```bash
# Generate RSA-4096 key (development/testing only)
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

## Vulnerability Detection

EUProvGuard queries [OSV.dev](https://osv.dev) for accurate, real-time CVE matching across all scanned ecosystems. 
Vulnerabilities are cross-referenced with the [EUVD](https://euvd.enisa.europa.eu/) (ENISA EU Vulnerability Database) 
for CRA Art. 13 compliance.

## The "Offline" Risk: Compliance Gaps

While EUProvGuard will function without an internet connection, **offline mode is typically insufficient for strict CRA/eIDAS alignment**:

1.  **CRA Article 13 & Annex I:** You are required to disclose "known vulnerabilities." If your tool is offline and misses a critical zero-day publically disclosed yesterday, your SBOM is technically non-compliant as it fails to "identify and remediate without delay."
2.  **eIDAS Article 26:** Qualified Timestamping (TSA) requires reaching a Trusted Service Provider (TSP) over RFC 3161. An offline signature lacks the "Qualified" status for legal non-repudiation in EU courts.
3.  **SAST Freshness:** The engine cannot fetch the latest OWASP CRS security patterns, potentially missing new attack vectors.

**Auditable Trail:** EUProvGuard creates an auditable chain of evidence (query timestamps and cryptographically hashed catalog provenance) required for regulatory review.

## FAQ

### Why does this look paranoid?

Because when it comes to legal compliance in the EU, paranoid is the correct baseline. CRA and eIDAS
carry real penalties. An SBOM that can't prove its own integrity in court is just a list.

### Why embed the CVE database anymore?

EUProvGuard removed the embedded CVE database because accuracy is paramount for CRA. Embedded snapshots 
become stale within weeks and fail the regulatory requirement for real-time risk management.

## Useful Links

- [Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2353/oj)
- [eIDAS Regulation](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)
- [CycloneDX (v1.6)](https://cyclonedx.org/)

## License

MIT - see [LICENSE](LICENSE).

## AI Assistance Notice

Created with the help of AI (Perplexity) for legal compliance review and documentation drafting. 
All claims reviewed and validated by maintainer.

If you are a legal expert or security researcher, please feel free to contribute improvements or raise issues!
