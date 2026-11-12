package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// Swallowing an error is a reliability defect (CWE-703), not an exploitable
// flaw: Bandit rates `except: pass` (B110) and gosec rates unchecked errors
// (G104) LOW. Reporting them as HIGH put them next to XSS, and when the core
// finding was merged with Bandit's LOW one the higher severity won.
func TestEngine_ErrorSwallowingRulesAreLow(t *testing.T) {
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{"FAST-LAZY-EXC": false, "GO-ERR-BLANK": false}
	for _, rule := range eng.Rules {
		if _, ok := found[rule.ID]; !ok {
			continue
		}
		found[rule.ID] = true
		if rule.Severity != "LOW" {
			t.Errorf("%s severity = %q; want LOW", rule.ID, rule.Severity)
		}
		if strings.HasPrefix(rule.Suggestion, "HIGH") {
			t.Errorf("%s suggestion still carries the old severity: %q", rule.ID, rule.Suggestion)
		}
	}
	for id, ok := range found {
		if !ok {
			t.Errorf("rule %s is missing from the catalog", id)
		}
	}
}

func TestEngine_LazyExceptionIsReportedAsLow(t *testing.T) {
	tmpDir := t.TempDir()
	src := "from fastapi import FastAPI\n\napp = FastAPI()\n\n\ndef load():\n    try:\n        return open('settings.toml').read()\n    except Exception:\n        pass\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}

	results := eng.Run(&core.ProjectContext{RootPath: tmpDir, Files: ws.Files, Stack: "fastapi", Config: ws.Config})

	reported := false
	for _, result := range results {
		if result.ID != "FAST-LAZY-EXC" {
			continue
		}
		reported = true
		if result.Severity != "LOW" || result.Line != 9 {
			t.Errorf("FAST-LAZY-EXC reported as %s at line %d; want LOW at line 9", result.Severity, result.Line)
		}
	}
	if !reported {
		t.Error("except Exception: pass was not reported")
	}
}
