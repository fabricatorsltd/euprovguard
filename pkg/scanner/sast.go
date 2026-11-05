package scanner

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// SASTRule represents a static analysis pattern.
type SASTRule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	CWEs        []int
	Extensions  []string // e.g., ".go", ".c", ".sh", or "*" for all
	Pattern     *regexp.Regexp
	// Accept, when set, decides whether one match of Pattern is a finding.
	// match holds the submatch indexes of that match in line, and local
	// names the functions the file defines or imports itself.
	Accept func(line string, match []int, local map[string]bool) bool
}

// Finding represents a vulnerability found in the codebase.
type Finding struct {
	ID          string
	ToolName    string
	RuleID      string
	Description string
	File        string
	Line        int
	Severity    string
	CWEs        []int
	// Text is the trimmed source line, which a baseline entry matches.
	Text string
	// Suppressed is the reason given for an accepted finding, empty for an
	// open one.
	Suppressed string
}

// RunSAST scans the root directory for security vulnerabilities.
// It skips binaries, hidden files, and patterns in .gitignore.
func RunSAST(root string, workers int, extraRules []SASTRule) []Finding {
	findings, _ := ScanSAST(root, workers, extraRules, nil)
	return findings
}

// ScanSAST is RunSAST with suppressions: a finding whose line carries an
// "euprovguard:ignore RULE reason" comment, or follows a comment line that
// carries one, or that a baseline entry matches, comes back in suppressed instead of findings.
// File paths are relative to root, with forward slashes.
func ScanSAST(root string, workers int, extraRules []SASTRule, baseline []Suppression) (findings, suppressed []Finding) {
	log.Printf("[INFO] Starting native SAST engine...")
	rules := GetEmbeddedRules()
	if len(extraRules) > 0 {
		rules = append(rules, extraRules...)
	}

	extRules := make(map[string][]SASTRule)
	var anyRules []SASTRule
	for _, r := range rules {
		for _, ext := range r.Extensions {
			if ext == "*" {
				anyRules = append(anyRules, r)
			} else {
				extRules[ext] = append(extRules[ext], r)
			}
		}
	}

	// Load .gitignore patterns
	ignorePatterns := loadGitignore(root)

	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Check if path should be ignored
		relPath, _ := filepath.Rel(root, path)
		if shouldIgnorePath(relPath, ignorePatterns) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		name := info.Name()
		if info.IsDir() {
			// Skip hidden directories
			if strings.HasPrefix(name, ".") && name != "." && name != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			return nil
		}

		// Skip large files (> 5MB)
		if info.Size() > 5*1024*1024 {
			return nil
		}

		// Skip known binary extensions
		ext := strings.ToLower(filepath.Ext(name))
		if isBinaryExt(ext) {
			return nil
		}

		// For wildcard rules, only scan interesting text files
		if len(anyRules) > 0 {
			if isInterestingTextFile(ext) {
				files = append(files, path)
				return nil
			}
		}

		if len(extRules[ext]) > 0 {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		log.Printf("[WARN] SAST walk failed: %v", err)
	}

	totalFiles := len(files)
	log.Printf("[INFO] SAST: found %d source files", totalFiles)

	jobCh := make(chan string, totalFiles)
	for _, f := range files {
		jobCh <- f
	}
	close(jobCh)

	var mu sync.Mutex
	var wg sync.WaitGroup
	var scanned int

	if workers < 1 {
		workers = 12
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobCh {
				ext := filepath.Ext(path)
				activeRules := append([]SASTRule{}, anyRules...)
				activeRules = append(activeRules, extRules[ext]...)

				if len(activeRules) == 0 {
					continue
				}

				fileFindings := scanFile(path, activeRules)
				relative, err := filepath.Rel(root, path)
				if err != nil {
					relative = path
				}
				for i := range fileFindings {
					fileFindings[i].File = filepath.ToSlash(relative)
				}

				mu.Lock()
				scanned++
				if scanned%100 == 0 || scanned == totalFiles {
					log.Printf("[INFO] SAST progress: %d/%d files scanned", scanned, totalFiles)
				}
				for _, finding := range fileFindings {
					if finding.Suppressed == "" {
						finding.Suppressed = matchBaseline(baseline, finding)
					}
					if finding.Suppressed != "" {
						suppressed = append(suppressed, finding)
					} else {
						findings = append(findings, finding)
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sortFindings(findings)
	sortFindings(suppressed)
	log.Printf("[INFO] Native SAST completed: found %d issues", len(findings))
	if len(suppressed) > 0 {
		log.Printf("[INFO] SAST: %d findings suppressed", len(suppressed))
	}
	return findings, suppressed
}

// sortFindings orders findings by file, line and rule, so that two scans of
// the same tree number them the same way whatever the worker scheduling.
func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

func scanFile(path string, rules []SASTRule) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 6*1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	local := localDefinitions(path, lines)

	var findings []Finding
	for index, line := range lines {
		if len(line) > 2048 { // Skip minified/huge lines to prevent regex lockup
			continue
		}

		// Skip comment-only lines to reduce false positives
		trimmed := strings.TrimSpace(line)
		if isCommentLine(trimmed, path) {
			continue
		}

		for _, rule := range rules {
			// Only report CRITICAL and HIGH severity to avoid false positive noise
			if rule.Severity != "critical" && rule.Severity != "high" {
				continue
			}
			if !ruleMatches(rule, line, local) {
				continue
			}
			finding := Finding{
				ToolName:    "EUProvGuard-Native-SAST",
				RuleID:      rule.ID,
				Description: rule.Name + ": " + rule.Description,
				File:        path,
				Line:        index + 1,
				Severity:    rule.Severity,
				CWEs:        rule.CWEs,
				Text:        trimmed,
			}
			finding.Suppressed = inlineSuppression(line, rule.ID)
			// A comment of its own on the line above covers this line too.
			if finding.Suppressed == "" && index > 0 {
				if previous := strings.TrimSpace(lines[index-1]); previous != "" && isCommentLine(previous, path) {
					finding.Suppressed = inlineSuppression(previous, rule.ID)
				}
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

// ruleMatches reports whether any match of the rule in line is a finding.
func ruleMatches(rule SASTRule, line string, local map[string]bool) bool {
	if rule.Accept == nil {
		return rule.Pattern.MatchString(line)
	}
	for _, match := range rule.Pattern.FindAllStringSubmatchIndex(line, -1) {
		if rule.Accept(line, match, local) {
			return true
		}
	}
	return false
}

var (
	pythonDefinition = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)\s*\(`)
	pythonImport     = regexp.MustCompile(`^\s*from\s+\S+\s+import\s+\(?([\w\s,]+)\)?`)
	pythonAlias      = regexp.MustCompile(`^(\w+)(?:\s+as\s+(\w+))?$`)
)

// localDefinitions names the functions a Python file defines or imports
// itself, which shadow the builtins of the same name.
func localDefinitions(path string, lines []string) map[string]bool {
	if strings.ToLower(filepath.Ext(path)) != ".py" {
		return nil
	}
	local := make(map[string]bool)
	for _, line := range lines {
		if match := pythonDefinition.FindStringSubmatch(line); match != nil {
			local[match[1]] = true
		} else if match := pythonImport.FindStringSubmatch(line); match != nil {
			for _, name := range strings.Split(match[1], ",") {
				if alias := pythonAlias.FindStringSubmatch(strings.TrimSpace(name)); alias != nil {
					if alias[2] != "" {
						local[alias[2]] = true
					} else {
						local[alias[1]] = true
					}
				}
			}
		}
	}
	return local
}

// acceptPythonBuiltin takes a call of eval, exec or compile only when it is
// the builtin: not a method such as re.compile, not the definition of a
// function of that name, and not a call of a local function that shadows it.
func acceptPythonBuiltin(line string, match []int, local map[string]bool) bool {
	start := match[0]
	name := line[match[2]:match[3]]
	before := strings.TrimRight(line[:start], " \t")
	if strings.HasSuffix(before, ".") {
		return false
	}
	if before == "def" || strings.HasSuffix(before, " def") || strings.HasSuffix(before, "\tdef") {
		return false
	}
	return !local[name]
}

// acceptCall takes a C function name followed by a parenthesis only when it
// is a call: the declaration or definition of the function itself, as in a C
// runtime that implements it, puts a type right before the name.
func acceptCall(line string, match []int, _ map[string]bool) bool {
	before := strings.TrimRight(line[:match[0]], " \t")
	if before == "" {
		return true
	}
	last := before[len(before)-1]
	if last == '*' {
		// "char *strcpy(" declares; "a * sprintf(" multiplies, which C does not do with an int and a call result often enough to matter.
		return false
	}
	if !(last == '_' || (last >= 'a' && last <= 'z') || (last >= 'A' && last <= 'Z') || (last >= '0' && last <= '9')) {
		return true
	}
	word := before
	if space := strings.LastIndexAny(before, " \t(),;=!&|?:{}"); space >= 0 {
		word = before[space+1:]
	}
	switch word {
	case "return", "else", "do", "case", "sizeof", "typeof", "throw", "co_return", "co_yield":
		return true
	}
	return false
}

var inlineIgnore = regexp.MustCompile(`euprovguard:ignore\s+([A-Za-z0-9_,\-]+)\s*(.*)`)

// inlineSuppression returns the reason an "euprovguard:ignore RULE reason"
// comment in line gives for the rule, empty when it gives none. RULE may be a
// comma separated list, or "all".
func inlineSuppression(line, rule string) string {
	match := inlineIgnore.FindStringSubmatch(line)
	if match == nil {
		return ""
	}
	for _, name := range strings.Split(match[1], ",") {
		if strings.EqualFold(name, rule) || strings.EqualFold(name, "all") {
			reason := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(match[2]), "*/"))
			if reason == "" {
				reason = "suppressed inline"
			}
			return reason
		}
	}
	return ""
}

// isCommentLine checks if a line is a comment.
func isCommentLine(line, path string) bool {
	if line == "" {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))

	// Go, C, C++, Java, C#, TypeScript, JavaScript
	if ext == ".go" || ext == ".c" || ext == ".cpp" || ext == ".h" ||
		ext == ".hpp" || ext == ".java" || ext == ".cs" || ext == ".js" ||
		ext == ".ts" || ext == ".tsx" || ext == ".jsx" {
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			return true
		}
	}

	// Python, Bash, Shell
	if ext == ".py" || ext == ".sh" || ext == ".bash" || ext == ".zsh" {
		if strings.HasPrefix(line, "#") {
			return true
		}
	}

	return false
}

// loadGitignore reads the .gitignore file.
func loadGitignore(root string) map[string]bool {
	patterns := make(map[string]bool)

	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return patterns
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns[line] = true
	}

	return patterns
}

// shouldIgnorePath checks if a relative path matches gitignore patterns.
func shouldIgnorePath(relPath string, patterns map[string]bool) bool {
	if len(patterns) == 0 {
		return false
	}

	relPath = filepath.ToSlash(relPath)
	parts := strings.Split(relPath, "/")

	for pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		pattern = strings.TrimSuffix(pattern, "/")

		// Exact match at first level
		if pattern == parts[0] {
			return true
		}

		// Match as directory segment
		for _, part := range parts {
			if part == pattern {
				return true
			}
		}

		// Glob match
		if strings.Contains(pattern, "*") {
			if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
				return true
			}
		}
	}

	return false
}

func isBinaryExt(ext string) bool {
	binaries := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".obj": true, ".o": true, ".a": true,
		".lib": true, ".pyc": true, ".pyo": true, ".pyd": true,
		".class": true, ".jar": true, ".war": true, ".ear": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true, ".bz2": true, ".xz": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".tiff": true, ".bmp": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
		".odt": true, ".ods": true, ".odp": true,
		".mp3": true, ".mp4": true, ".wav": true, ".mov": true, ".avi": true, ".mkv": true, ".webm": true,
		".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
		".wasm": true, ".db": true, ".sqlite": true, ".sqlite3": true,
	}
	return binaries[ext]
}

func isInterestingTextFile(ext string) bool {
	// If no extension, could be a script or a README, etc.
	if ext == "" {
		return true
	}
	textExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".c": true, ".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".java": true,
		".rb": true, ".php": true, ".sh": true, ".bash": true, ".zsh": true, ".ps1": true,
		".env": true, ".yml": true, ".yaml": true, ".json": true, ".xml": true,
		".txt": true, ".md": true, ".sql": true, ".ini": true, ".conf": true, ".toml": true,
		".dockerfile": true, ".makefile": true, ".gradle": true, ".properties": true,
		".html": true, ".htm": true, ".xhtml": true,
	}
	return textExts[ext]
}
