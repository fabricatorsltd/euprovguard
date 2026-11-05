package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func locations(findings []Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.RuleID+" "+f.File+":"+strconv.Itoa(f.Line))
	}
	sort.Strings(out)
	return out
}

func TestScanSAST_PythonBuiltinsOnly(t *testing.T) {
	root := writeTree(t, map[string]string{
		"tool/a.py": strings.Join([]string{
			"import re",
			"PATTERN = re.compile(r'x+')",
			"value = eval(text)",
			"exec(code)",
			"obj . compile(x)",
		}, "\n"),
		"tool/b.py": strings.Join([]string{
			"def compile(sources):",
			"    return sources",
			"compile(['a.c'])",
		}, "\n"),
		"tool/c.py": strings.Join([]string{
			"from builder import compile as build, eval",
			"eval(x)",
			"compile(y)",
		}, "\n"),
	})
	findings, _ := ScanSAST(root, 2, nil, nil)
	got := strings.Join(locations(findings), ", ")
	want := "INJ-001 tool/a.py:3, INJ-001 tool/a.py:4, INJ-001 tool/c.py:3"
	if got != want {
		t.Fatalf("findings %q, want %q", got, want)
	}
}

func TestScanSAST_CDefinitionsAreNotCalls(t *testing.T) {
	root := writeTree(t, map[string]string{
		"crt/string.c": strings.Join([]string{
			"char *strcpy(char *to, const char *from)",
			"CRT int sprintf(char *buffer, const char *format, ...)",
			"#define sprintf(b, ...) my_sprintf(b, __VA_ARGS__)",
			"int use(char *a) {",
			"\tstrcpy(a, \"x\");",
			"\treturn sprintf(a, \"%d\", 1);",
			"\tn = (int)sprintf(a, \"y\");",
			"}",
		}, "\n"),
	})
	findings, _ := ScanSAST(root, 1, nil, nil)
	got := strings.Join(locations(findings), ", ")
	want := "MEM-001 crt/string.c:5, MEM-002 crt/string.c:6, MEM-002 crt/string.c:7"
	if got != want {
		t.Fatalf("findings %q, want %q", got, want)
	}
}

func TestScanSAST_Suppressions(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/a.c": strings.Join([]string{
			"void f(char *a) {",
			"\tstrcpy(a, \"x\"); // euprovguard:ignore MEM-001 the buffer holds 64 bytes",
			"\t/* euprovguard:ignore MEM-002 fixed text into a sized buffer */",
			"\tsprintf(a, \"y\");",
			"\tsprintf(a, \"z\"); // euprovguard:ignore MEM-001 wrong rule",
			"\tstrcpy(a, b);",
			"}",
		}, "\n"),
	})
	baseline := []Suppression{{Rule: "MEM-001", File: "src/a.c", Line: "strcpy(a, b);", Reason: "reviewed"}}
	findings, suppressed := ScanSAST(root, 1, nil, baseline)
	if got := strings.Join(locations(findings), ", "); got != "MEM-002 src/a.c:5" {
		t.Fatalf("open findings %q", got)
	}
	if len(suppressed) != 3 {
		t.Fatalf("suppressed %d findings, want 3", len(suppressed))
	}
	reasons := map[int]string{}
	for _, f := range suppressed {
		reasons[f.Line] = f.Suppressed
	}
	if reasons[2] != "the buffer holds 64 bytes" || reasons[4] != "fixed text into a sized buffer" || reasons[6] != "reviewed" {
		t.Fatalf("reasons %v", reasons)
	}
}

func TestScanSAST_RelativePaths(t *testing.T) {
	root := writeTree(t, map[string]string{"deep/dir/x.c": "\tstrcpy(a, b);\n"})
	findings := RunSAST(root, 1, nil)
	if len(findings) != 1 || findings[0].File != "deep/dir/x.c" {
		t.Fatalf("findings %+v", findings)
	}
}

func TestLoadBaseline_RequiresReason(t *testing.T) {
	root := writeTree(t, map[string]string{
		"good.json": `{"sast":[{"rule":"MEM-001","file":"a.c","line":"  strcpy(a, b);  ","reason":"ok"}]}`,
		"bad.json":  `{"sast":[{"rule":"MEM-001","file":"a.c"}]}`,
	})
	entries, err := LoadBaseline(filepath.Join(root, "good.json"))
	if err != nil || len(entries) != 1 || entries[0].Line != "strcpy(a, b);" {
		t.Fatalf("entries %+v, err %v", entries, err)
	}
	if _, err := LoadBaseline(filepath.Join(root, "bad.json")); err == nil {
		t.Fatal("a baseline entry without a reason was accepted")
	}
}
