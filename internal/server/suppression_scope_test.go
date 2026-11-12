package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Web API applies the same rule as the MCP tool: a dismissal without a file
// covers the rule across the whole project, so it must be requested explicitly
// with rule_wide, and the response says what a dismissal covers.
func TestWebSuppressionRequiresAFileOrAnExplicitRuleWideScope(t *testing.T) {
	root, reports := baselineTestProject(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	s := setupTestServer(t)
	s.hostPrefix = root

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/suppressions", bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post(`{"source":"core","rule_id":"SECRET-ASSIGN","reason":"false_positive","note":"fixture"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("bare rule_id dismissal = %d, want 422", code)
	}
	if code := post(`{"source":"core","rule_id":"SECRET-ASSIGN","file":"app.py","rule_wide":true,"reason":"false_positive","note":"fixture"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("rule_wide with a file = %d, want 422", code)
	}

	wide := callSuppressions(t, s, http.MethodPost, "/api/suppressions",
		`{"source":"core","rule_id":"SECRET-ASSIGN","rule_wide":true,"reason":"accepted_risk","note":"fixture tokens only"}`)
	if !strings.Contains(wide.Note, "anywhere in the project") {
		t.Errorf("rule-wide response note = %q, want the project-wide scope", wide.Note)
	}
	scoped := callSuppressions(t, s, http.MethodPost, "/api/suppressions",
		`{"source":"core","rule_id":"PY-SUBPROCESS","file":"app.py","reason":"false_positive","note":"fixture"}`)
	if !strings.Contains(scoped.Note, "in app.py") {
		t.Errorf("file-scoped response note = %q, want the file scope", scoped.Note)
	}
}
