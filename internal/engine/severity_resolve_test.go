package engine

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
)

func TestResolveSeverity(t *testing.T) {
	tests := []struct {
		name           string
		rule           models.Rule
		legacy         bool
		wantSeverity   string
		wantSuggestion string
	}{
		{"builtin field", models.Rule{Severity: "high", Suggestion: "Fix it."}, false, "HIGH", "Fix it."},
		{"builtin ignores prefix", models.Rule{Suggestion: "CRITICAL: Fix it."}, false, "LOW", "CRITICAL: Fix it."},
		{"pack field wins", models.Rule{Severity: "MEDIUM", Suggestion: "CRITICAL: Fix it."}, true, "MEDIUM", "CRITICAL: Fix it."},
		{"pack legacy prefix", models.Rule{Suggestion: "critical: Fix it."}, true, "CRITICAL", "Fix it."},
		{"pack no severity", models.Rule{Suggestion: "Fix it."}, true, "LOW", "Fix it."},
		{"pack unknown value", models.Rule{Severity: "urgent", Suggestion: "Fix it."}, true, "LOW", "Fix it."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule
			resolveSeverity(&r, tt.legacy)
			if r.Severity != tt.wantSeverity || r.Suggestion != tt.wantSuggestion {
				t.Errorf("got (%q, %q); want (%q, %q)", r.Severity, r.Suggestion, tt.wantSeverity, tt.wantSuggestion)
			}
		})
	}
}
