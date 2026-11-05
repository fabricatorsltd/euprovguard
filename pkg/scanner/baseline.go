package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BaselineFile is the name of the baseline a project keeps at its root.
const BaselineFile = ".euprovguard-baseline.json"

// Suppression accepts one SAST finding, with the reason it was accepted.
// It matches on the rule, the file and the text of the line rather than the
// line number, so it survives edits elsewhere in the file.
type Suppression struct {
	// Rule is the rule identifier, e.g. "MEM-001".
	Rule string `json:"rule"`
	// File is the path relative to the project root, with forward slashes.
	File string `json:"file"`
	// Line is the trimmed text of the source line. Empty accepts every
	// finding of the rule in the file.
	Line string `json:"line,omitempty"`
	// Reason says why the finding is accepted. It is required.
	Reason string `json:"reason"`
}

// Baseline is the document stored in BaselineFile.
type Baseline struct {
	SAST []Suppression `json:"sast"`
}

// LoadBaseline reads a baseline document. Every entry needs a rule, a file
// and a reason.
func LoadBaseline(path string) ([]Suppression, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	for index, entry := range baseline.SAST {
		if entry.Rule == "" || entry.File == "" || strings.TrimSpace(entry.Reason) == "" {
			return nil, fmt.Errorf("baseline %s: entry %d needs a rule, a file and a reason", path, index+1)
		}
		baseline.SAST[index].File = filepath.ToSlash(entry.File)
		baseline.SAST[index].Line = strings.TrimSpace(entry.Line)
	}
	return baseline.SAST, nil
}

// matchBaseline returns the reason of the first entry that accepts the
// finding, empty when none does.
func matchBaseline(baseline []Suppression, finding Finding) string {
	for _, entry := range baseline {
		if !strings.EqualFold(entry.Rule, finding.RuleID) || entry.File != finding.File {
			continue
		}
		if entry.Line == "" || entry.Line == finding.Text {
			return entry.Reason
		}
	}
	return ""
}
