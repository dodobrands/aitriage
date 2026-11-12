package remedy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
)

func TestIsSecretRule(t *testing.T) {
	for _, id := range engine.SecretRuleIDs() {
		if !IsSecretRule(id) {
			t.Errorf("IsSecretRule(%q) = false for an id the detector emits", id)
		}
	}
	for id, want := range map[string]bool{
		"ENTROPY-SECRET": true, "ENTROPY-SECRET-LEAK": true, "secret-assign": true,
		"ENTR-17": false, "DJANGO-SECRET": false, "FLASK-SECRET-HARDCODED": false, "ENTR-SLOP-01": false, "": false,
	} {
		if got := IsSecretRule(id); got != want {
			t.Errorf("IsSecretRule(%q) = %v, want %v", id, got, want)
		}
	}
}

// The engine emits SECRET-* ids; the fixer used to wait for ENTROPY-SECRET,
// which it never emits, so no secret was ever fixed.
func TestAutoFixHandlesDetectorSecretIDs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	value := strings.Join([]string{"AornV2XN", "pMtoaEI9", "V7Pxp6rv"}, "")
	src := "package main\n\nfunc main() {\n\tapiKey := \"" + value + "\"\n\t_ = apiKey\n}\n"
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"SECRET-ASSIGN", "SECRET-LEAK-LOG", "ENTROPY-SECRET"} {
		t.Run(id, func(t *testing.T) {
			report := scanner.ScanReport{Results: []core.CheckResult{{ID: id, Status: core.Absent, File: file, Line: 4}}}
			got := AutoFix(report, false)
			if len(got) != 1 {
				t.Fatalf("AutoFix returned %d results for %s, want 1", len(got), id)
			}
			if got[0].Err != nil {
				t.Fatalf("fix failed: %v", got[0].Err)
			}
			// A short variable declaration must stay one: `apiKey = os.Getenv`
			// would not compile.
			if !strings.Contains(got[0].Description, `apiKey := os.Getenv("APIKEY")`) {
				t.Errorf("diff does not keep the := declaration: %q", got[0].Description)
			}
		})
	}

	report := scanner.ScanReport{Results: []core.CheckResult{{ID: "ENTR-SLOP-01", Status: core.Absent, File: file, Line: 4}}}
	if got := AutoFix(report, false); len(got) != 0 {
		t.Errorf("a non-secret finding was routed to a fixer: %+v", got)
	}
}

func TestSecretTemplateCoversDetectorIDs(t *testing.T) {
	for _, id := range append(engine.SecretRuleIDs(), "ENTROPY-SECRET", "ENTROPY-SECRET-LEAK") {
		plan := GenerateFixPlan([]core.CheckResult{{ID: id, Severity: "HIGH", File: "app.py", Line: 3}})
		if len(plan.HighActions) != 1 {
			t.Fatalf("%s: no action in the plan: %+v", id, plan)
		}
		item := plan.HighActions[0]
		if !strings.Contains(item.FixPrompt, "app.py line 3") || !strings.Contains(item.FixPrompt, "environment") {
			t.Errorf("%s: secret template not applied, prompt = %q", id, item.FixPrompt)
		}
	}
}
