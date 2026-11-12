package graph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
)

// identityOf enriches one finding of rule at file:line against project and
// returns it with its stable id, display id and snippet set.
func identityOf(t *testing.T, project, rule, file string, line int) EnrichedFinding {
	t.Helper()
	f := EnrichedFinding{ID: rule, Type: "core", Source: "aitriage", Severity: "HIGH", File: file, Line: line, Message: rule + ": flagged"}
	f.Snippet = extractFullContext(project, f.File, f.Line)
	findings := []EnrichedFinding{f}
	assignStableIDs(project, findings)
	assignVulnIDs(findings)
	return findings[0]
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	guardedPython   = "import os\n\ndef read(path):\n    if is_safe(path):\n        log(path)\n        data = open(path).read()\n    return None\n"
	dedentedPython  = "import os\n\ndef read(path):\n    if is_safe(path):\n        log(path)\n    data = open(path).read()\n    return None\n"
	compactGo       = "package app\n\nfunc read(path string) {\n\tif isSafe(path) {\n\t\tdata, _ := os.ReadFile(path)\n\t\t_ = data\n\t}\n}\n"
	reformattedGo   = "package app\n\nfunc read(path string) {\n    if isSafe(path) {\n        data, _ :=   os.ReadFile(path)\n        _ = data\n    }\n}\n"
	nestedYAML      = "spec:\n  containers:\n    - name: app\n      securityContext:\n        runAsUser: 0\n"
	dedentedYAML    = "spec:\n  containers:\n    - name: app\n      securityContext:\n      runAsUser: 0\n"
	pathTraversalID = "FAST-PATH-TRAVERSAL"
)

// In Python and YAML the indentation of the flagged line is part of its
// identity: dedenting open() out of its `if is_safe(path):` block changes
// what the code does, so neither the stable id nor the verdict cache key may
// stay the same. In brace languages reformatting keeps both.
func TestLineIdentityKeepsIndentationWhereItIsCode(t *testing.T) {
	cases := []struct {
		name, file, before, after string
		line                      int
		wantSame                  bool
	}{
		{"python dedent out of the guard", "app.py", guardedPython, dedentedPython, 6, false},
		{"yaml dedent out of the mapping", "k8s/pod.yaml", nestedYAML, dedentedYAML, 5, false},
		{"go re-indented and spaced", "app.go", compactGo, reformattedGo, 5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			writeFile(t, filepath.Join(project, tc.file), tc.before)
			before := identityOf(t, project, pathTraversalID, tc.file, tc.line)
			writeFile(t, filepath.Join(project, tc.file), tc.after)
			after := identityOf(t, project, pathTraversalID, tc.file, tc.line)

			if same := before.StableID == after.StableID; same != tc.wantSame {
				t.Errorf("stable id same = %v, want %v (%s vs %s)", same, tc.wantSame, before.StableID, after.StableID)
			}
			if same := verdictCacheKey(before) == verdictCacheKey(after); same != tc.wantSame {
				t.Errorf("verdict cache key same = %v, want %v", same, tc.wantSame)
			}
		})
	}
}

// End to end: a False Positive cached while open() ran inside the guard is not
// reused once open() is dedented out of it; the model is asked again.
func TestVerdictCacheIsNotReusedAfterADedentOutOfTheGuard(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_CACHE_DIR", t.TempDir())
	t.Setenv("AITRIAGE_LLM_MODEL", "model-a")
	project := t.TempDir()
	build := func(source string) []EnrichedFinding {
		writeFile(t, filepath.Join(project, "app.py"), source)
		return []EnrichedFinding{identityOf(t, project, pathTraversalID, "app.py", 6)}
	}
	classify := func(findings []EnrichedFinding, client llm.Client) FindingDisposition {
		t.Helper()
		var usage llm.Usage
		_, disps, _, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, client, &usage, 40)
		if err != nil {
			t.Fatal(err)
		}
		return disps[0]
	}

	dismiss := &fakeLLM{t: t, classifyHandler: func(_ int, batch []EnrichedFinding) (string, error) {
		var entries []string
		for i := range batch {
			entries = append(entries, fmt.Sprintf(`{"finding_index":%d,"disposition":"False Positive","confidence":"high","rationale":"guarded by is_safe","evidence":{"basis":"code_mitigation","file":"app.py","line":4,"observed":"is_safe(path)"}}`, i))
		}
		return `{"finding_dispositions":[` + strings.Join(entries, ",") + `]}`, nil
	}}
	if d := classify(build(guardedPython), dismiss); d.Disposition != "False Positive" || d.DispositionSource != dispositionSourceLLM {
		t.Fatalf("guarded run = %+v, want the model's False Positive accepted", d)
	}

	again := &fakeLLM{t: t}
	d := classify(build(dedentedPython), again)
	if d.DispositionSource == dispositionSourceCache || again.classifyCalls != 1 {
		t.Fatalf("dedented run = %+v (classify calls %d), want the model asked again instead of the cached False Positive", d, again.classifyCalls)
	}
}

// Two reports of one unclassified rule on one line are told apart by what they
// report. Adding a third report never moves an existing report's id to
// another one, and identical reports still get distinct ids.
func TestStableIDsOfReportsOnOneLineDoNotMove(t *testing.T) {
	root := writeProjectFiles(t, map[string]string{"cfg.py": "A = 'k1'; B = 'k2'; C = 'k3'\n"})
	run := func(evidence ...string) map[string]string {
		state := &AgentState{ProjectPath: root}
		for _, ev := range evidence {
			state.CoreFindings = append(state.CoreFindings, core.CheckResult{
				ID: "ENTR-12", Name: "High entropy string", Status: core.Absent, Severity: "MEDIUM", File: "cfg.py", Line: 1, Evidence: ev,
			})
		}
		enrichFindings(state)
		ids := map[string]string{}
		for _, f := range state.EnrichedFindings {
			ids[f.Message] = f.StableID + " " + f.VulnID
		}
		return ids
	}
	before := run("token k2", "token k3")
	after := run("token k1", "token k2", "token k3")
	for message, id := range before {
		if after[message] != id {
			t.Errorf("%q: id %s became %s after an unrelated report was added", message, id, after[message])
		}
	}
	if len(after) != 3 {
		t.Fatalf("ids = %v, want three distinct reports", after)
	}

	findings := []EnrichedFinding{
		{ID: "ENTR-12", Type: "core", Source: "aitriage", File: "cfg.py", Line: 1, Message: "same"},
		{ID: "ENTR-12", Type: "core", Source: "aitriage", File: "cfg.py", Line: 1, Message: "same"},
	}
	assignStableIDs(root, findings)
	if findings[0].StableID == findings[1].StableID {
		t.Fatal("identical reports share a stable id")
	}
}
