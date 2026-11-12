package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
)

// One call with nothing but a rule id recorded a dismissal that covers the rule
// in every file of the project, and the summary did not say so. Adding now
// needs the file unless the caller asks for that reach with rule_wide.
func TestSuppressToolNeedsAFileOrAnExplicitRuleWideScope(t *testing.T) {
	root, _ := containerWorkspace(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})

	for _, args := range []map[string]any{
		{"action": "add", "rule_id": "SECRET-ASSIGN"},
		{"action": "add", "rule_id": "SECRET-ASSIGN", "source": "core", "reason": "false_positive"},
		{"action": "add", "rule_id": "SECRET-ASSIGN", "evidence": "CLIENT_SECRET = '...'"},
		{"action": "add", "rule_id": "SECRET-ASSIGN", "file": "   "},
	} {
		msg := toolErrorText(t, cs, "aitriage_suppress", args)
		if !strings.Contains(msg, "file is required") || !strings.Contains(msg, "rule_wide") {
			t.Errorf("add %v failed with %q, want it to ask for a file or rule_wide", args, msg)
		}
	}
	if msg := toolErrorText(t, cs, "aitriage_suppress", map[string]any{
		"action": "add", "rule_id": "SECRET-ASSIGN", "file": "app.js", "rule_wide": true,
	}); !strings.Contains(msg, "rule_wide") {
		t.Errorf("rule_wide with a file failed with %q, want it to name the conflict", msg)
	}
	store, err := suppression.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Entries) != 0 {
		t.Fatalf("refused adds recorded %d dismissal(s)", len(store.Entries))
	}

	// Asked for explicitly, the rule-wide dismissal is recorded and the result
	// says how far it reaches.
	var added suppressResult
	callToolOK(t, cs, "aitriage_suppress", map[string]any{
		"action": "add", "rule_id": "SECRET-ASSIGN", "source": "core", "rule_wide": true, "reason": "false_positive",
	}, &added)
	const everywhere = "covers every core finding of SECRET-ASSIGN anywhere in the project"
	if !strings.Contains(added.Scope, everywhere) || !strings.Contains(added.Summary, everywhere) {
		t.Errorf("rule-wide add: scope %q, summary %q; want both to say it %s", added.Scope, added.Summary, everywhere)
	}
	if added.Total != 1 || added.Entries[0].File != "" {
		t.Fatalf("rule-wide add recorded %+v, want one entry without a file", added.Entries)
	}
	store, err = suppression.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.SuppressesInProject(root, baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: "src/settings.py", Evidence: "x"}); !ok {
		t.Error("the rule-wide dismissal does not cover the rule in another file")
	}
}

// Every add reports which findings the dismissal covers, as the CLI prints
// after `aitriage ignore add`.
func TestSuppressToolReturnsTheScopeOfEachDismissal(t *testing.T) {
	root, _ := containerWorkspace(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	cs := connectClient(t, Config{Profile: ProfileFull, ScanRoot: root})

	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{
			map[string]any{"rule_id": "ENTR-INNERHTML", "source": "core", "file": "app.js"},
			"covers every core finding of ENTR-INNERHTML in app.js",
		},
		{
			map[string]any{"rule_id": "ENTR-INNERHTML", "file": filepath.Join(root, "app.js"), "evidence": "document.body.innerHTML = location.hash"},
			"covers only the core finding of ENTR-INNERHTML in app.js that carries this evidence",
		},
		{
			map[string]any{"rule_id": "NFR-API-001", "source": "nfr", "evidence": "No rate limiting", "rule_wide": true},
			"covers only nfr findings of NFR-API-001 that are reported without a file and carry this evidence",
		},
	} {
		tc.args["action"] = "add"
		var added suppressResult
		callToolOK(t, cs, "aitriage_suppress", tc.args, &added)
		if !strings.Contains(added.Scope, tc.want) || !strings.Contains(added.Summary, added.Scope) {
			t.Errorf("add %v: scope %q, summary %q; want the scope to say it %s, in the summary too", tc.args, added.Scope, added.Summary, tc.want)
		}
	}
}
