package scanner

import (
	"regexp"
)

// GetEmbeddedRules returns the static analysis rules mapped to CRA and CWE standards.
// These rules are inspired by enterprise open-source linters (Gitleaks, Bandit, Flawfinder).
func GetEmbeddedRules() []SASTRule {
	return []SASTRule{
		// Secrets: only high-confidence patterns to avoid false positives
		// Skip generic password/secret patterns - too many false positives in comments/docs

		// CWE-798: Use of Hard-coded Credentials
		{
			ID:          "SEC-001",
			Name:        "Hardcoded AWS Access Key",
			Description: "Detected a hardcoded AWS Access Key ID (AKIA*), which can lead to cloud infrastructure compromise.",
			Severity:    "critical",
			CWEs:        []int{798},
			Extensions:  []string{"*"},
			Pattern:     regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
		},
		{
			ID:          "SEC-002",
			Name:        "Hardcoded GitHub Token",
			Description: "Detected a hardcoded GitHub personal access token (ghp_*), which grants full account access.",
			Severity:    "critical",
			CWEs:        []int{798},
			Extensions:  []string{"*"},
			Pattern:     regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36})\b`),
		},
		{
			ID:          "SEC-003",
			Name:        "Hardcoded Private Key",
			Description: "Detected a private key (RSA/ECDSA/ED25519) in source code, which compromises all security.",
			Severity:    "critical",
			CWEs:        []int{798},
			Extensions:  []string{".go", ".py", ".js", ".ts", ".sh", ".bash", ".c", ".cpp", ".java", ".cs"},
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA|EC|ED25519|OPENSSH) PRIVATE KEY-----`),
		},

		// ---------------------------------------------------------------------
		// CWE-119 / CWE-120: Buffer Overflow / Memory Safety (C/C++)
		// CRA specifically highlights memory safety risks.
		// ---------------------------------------------------------------------
		{
			ID:          "MEM-001",
			Name:        "Dangerous Function: strcpy",
			Description: "Use of 'strcpy' does not check buffer bounds and can lead to buffer overflow. Use 'strncpy' or 'strlcpy' instead.",
			Severity:    "critical",
			CWEs:        []int{120, 119},
			Extensions:  []string{".c", ".cpp", ".h", ".hpp"},
			Pattern:     regexp.MustCompile(`\bstrcpy\s*\(`),
			Accept:      acceptCall,
		},
		{
			ID:          "MEM-002",
			Name:        "Dangerous Function: sprintf",
			Description: "Use of 'sprintf' can lead to buffer overflows. Use 'snprintf' instead.",
			Severity:    "high",
			CWEs:        []int{120, 119},
			Extensions:  []string{".c", ".cpp", ".h", ".hpp"},
			Pattern:     regexp.MustCompile(`\bsprintf\s*\(`),
			Accept:      acceptCall,
		},
		{
			ID:          "MEM-003",
			Name:        "Dangerous Function: gets",
			Description: "The 'gets' function is inherently unsafe and often leads to buffer overflows.",
			Severity:    "critical",
			CWEs:        []int{242, 119},
			Extensions:  []string{".c", ".cpp", ".h", ".hpp"},
			Pattern:     regexp.MustCompile(`\bgets\s*\(`),
		},

		// ---------------------------------------------------------------------
		// CWE-78: OS Command Injection (Go, Python, Bash)
		{
			ID:          "CMD-001",
			Name:        "Subprocess Execution with Shell (Python)",
			Description: "Using subprocess with shell=True allows OS command injection if input is untrusted.",
			Severity:    "high",
			CWEs:        []int{78},
			Extensions:  []string{".py"},
			Pattern:     regexp.MustCompile(`\bsubprocess\.(Popen|run|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True`),
		},
		{
			ID:          "CMD-002",
			Name:        "Unsafe Command Execution (Python os.system)",
			Description: "Using os.system allows command injection if input is untrusted. Use subprocess.run without shell=True.",
			Severity:    "high",
			CWEs:        []int{78},
			Extensions:  []string{".py"},
			Pattern:     regexp.MustCompile(`\bos\.system\s*\(`),
		},

		// CWE-94: Improper Control of Generation of Code (Code Injection)
		{
			ID:          "INJ-001",
			Name:        "Code Injection: Python eval()",
			Description: "Use of eval() on untrusted input enables arbitrary code execution.",
			Severity:    "critical",
			CWEs:        []int{94},
			Extensions:  []string{".py"},
			Pattern:     regexp.MustCompile(`\b(eval|exec|compile)\s*\([^)]*\)`),
			Accept:      acceptPythonBuiltin,
		},
	}
}
