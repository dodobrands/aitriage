package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
)

func callSuppressions(t *testing.T, s *Server, method, target, body string) suppressionListResponse {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s %s = %d: %s", method, target, rr.Code, rr.Body.String())
	}
	var resp suppressionListResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode %s %s: %v", method, target, err)
	}
	return resp
}

// scannedInnerHTML is the built-in finding the baseline test project always
// reports, as a scan of that project returns it.
func scannedInnerHTML(t *testing.T, root string) core.CheckResult {
	t.Helper()
	rich := orchestrator.RunAllScanners(context.Background(), orchestrator.Options{ProjectPath: root})
	for _, r := range rich.Report.Results {
		if r.ID == "ENTR-INNERHTML" && r.Status == core.Absent {
			return r
		}
	}
	t.Fatalf("fixture finding ENTR-INNERHTML missing from the scan: %+v", rich.Report.Results)
	return core.CheckResult{}
}

// dismissal is the request the Web UI sends to dismiss a scanned finding.
func dismissal(t *testing.T, r core.CheckResult, reason, note string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"source": "core", "rule_id": r.ID, "file": r.File, "line": r.Line,
		"evidence": r.Evidence, "severity": r.Severity, "reason": reason, "note": note,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// In the container the project is mounted read-only, so a dismissal made in
// the Web UI must land under the writable reports directory and be listed from
// there.
func TestWebSuppressionsInContainerAreWrittenUnderReports(t *testing.T) {
	root, reports := baselineTestProject(t)
	finding := scannedInnerHTML(t, root)
	containerBaselineEnv(t, reports)
	mountReadOnly(t, root)
	s := setupTestServer(t)
	s.hostPrefix = root

	want := filepath.Join(reports, "suppressions", suppression.File)
	added := callSuppressions(t, s, http.MethodPost, "/api/suppressions", dismissal(t, finding, "false_positive", ""))
	if added.Path != want || added.Total != 1 {
		t.Fatalf("add response = %+v, want one entry recorded in %s", added, want)
	}
	mustExist(t, want)
	mustNotExist(t, filepath.Join(root, suppression.File))

	listed := callSuppressions(t, s, http.MethodGet, "/api/suppressions", "")
	if listed.Path != want || listed.Total != 1 || listed.Entries[0].RuleID != finding.ID {
		t.Fatalf("list after add = %+v, want the entry from %s", listed, want)
	}

	removed := callSuppressions(t, s, http.MethodDelete, "/api/suppressions?id="+finding.ID, "")
	if removed.Path != want || removed.Total != 0 {
		t.Fatalf("remove response = %+v, want an empty record in %s", removed, want)
	}
}

// Dismissals committed with the project keep applying in the container next
// to the local ones, cannot be undone from there, and the project's own file
// is never touched.
func TestWebSuppressionsInContainerKeepTheProjectFile(t *testing.T) {
	root, reports := baselineTestProject(t)
	finding := scannedInnerHTML(t, root)
	containerBaselineEnv(t, reports)

	committed := suppression.New()
	if _, _, err := committed.Add(baseline.Item{Source: "trivy", RuleID: "CVE-2026-1", File: "package-lock.json", Evidence: "lodash 4.17.20"}, "accepted_risk", "not reachable from our code", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(root, committed); err != nil {
		t.Fatal(err)
	}
	projectFile := filepath.Join(root, suppression.File)
	original, err := os.ReadFile(projectFile)
	if err != nil {
		t.Fatal(err)
	}
	mountReadOnly(t, root)
	s := setupTestServer(t)
	s.hostPrefix = root

	listed := callSuppressions(t, s, http.MethodGet, "/api/suppressions", "")
	if listed.Path != projectFile || listed.Total != 1 {
		t.Fatalf("list = %+v, want the committed entry from %s", listed, projectFile)
	}

	copyFile := filepath.Join(reports, "suppressions", suppression.File)
	added := callSuppressions(t, s, http.MethodPost, "/api/suppressions", dismissal(t, finding, "false_positive", ""))
	if added.Path != copyFile || added.Total != 2 || !strings.Contains(added.Note, "commit") {
		t.Fatalf("add response = %+v, want the committed entry and the new one, recorded in %s with a note on sharing it", added, copyFile)
	}

	// The committed decision lives in the read-only project file.
	req := httptest.NewRequest(http.MethodDelete, "/api/suppressions?id=CVE-2026-1", nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "read-only") {
		t.Fatalf("removing a committed decision = %d %s, want 409 explaining the project file is read-only", rr.Code, rr.Body.String())
	}

	removed := callSuppressions(t, s, http.MethodDelete, "/api/suppressions?id="+finding.ID, "")
	if removed.Path != copyFile || removed.Total != 1 || removed.Entries[0].RuleID != "CVE-2026-1" {
		t.Fatalf("remove response = %+v, want only the committed entry left", removed)
	}

	after, err := os.ReadFile(projectFile)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("the project's dismissal file changed (err=%v)", err)
	}
}

// A dismissal committed to the project after the container recorded its own
// still applies to the next scan there, and a local decision overrides the
// project's decision about the same finding.
func TestWebScanInContainerMergesProjectAndLocalDismissals(t *testing.T) {
	root, reports := baselineTestProject(t)
	if err := os.WriteFile(filepath.Join(root, "other.js"), []byte("el.innerHTML = input;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rich := orchestrator.RunAllScanners(context.Background(), orchestrator.Options{ProjectPath: root})
	var appFinding, otherFinding core.CheckResult
	for _, r := range rich.Report.Results {
		if r.ID != "ENTR-INNERHTML" || r.Status != core.Absent {
			continue
		}
		switch filepath.Base(r.File) {
		case "app.js":
			appFinding = r
		case "other.js":
			otherFinding = r
		}
	}
	if appFinding.ID == "" || otherFinding.ID == "" {
		t.Fatalf("fixture findings missing: %+v", rich.Report.Results)
	}
	containerBaselineEnv(t, reports)
	s := setupTestServer(t)
	s.hostPrefix = root

	callSuppressions(t, s, http.MethodPost, "/api/suppressions", dismissal(t, appFinding, "false_positive", ""))

	// A commit pulled into the checkout later dismisses the other finding.
	upstream := suppression.New()
	upstreamItem := baseline.Relativize(root, baseline.FromCore([]core.CheckResult{otherFinding}))[0]
	if _, _, err := upstream.Add(upstreamItem, "false_positive", "", "upstream"); err != nil {
		t.Fatal(err)
	}
	if err := suppression.Save(root, upstream); err != nil {
		t.Fatal(err)
	}

	ignored := func() map[string]bool {
		t.Helper()
		scan := orchestrator.RunAllScanners(context.Background(), orchestrator.Options{ProjectPath: root})
		if _, err := applyScanDecisions(&scan, root, false); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, r := range scan.Report.Results {
			if r.ID == "ENTR-INNERHTML" && r.AuditStatus == core.AuditStatusIgnored {
				out[filepath.Base(r.File)] = true
			}
		}
		return out
	}
	if got := ignored(); !got["app.js"] || !got["other.js"] {
		t.Fatalf("dismissed findings = %v, want both the local and the later committed decision applied", got)
	}

	// Overriding the committed decision locally wins for that finding.
	overridden := callSuppressions(t, s, http.MethodPost, "/api/suppressions", dismissal(t, otherFinding, "accepted_risk", "covered by the content security policy"))
	if overridden.Total != 2 {
		t.Fatalf("after the override %d decision(s) apply, want 2: %+v", overridden.Total, overridden.Entries)
	}
	for _, entry := range overridden.Entries {
		if entry.File == "other.js" && (entry.Reason != suppression.ReasonAcceptedRisk || entry.Note != "covered by the content security policy") {
			t.Fatalf("the project's decision was not overridden locally: %+v", entry)
		}
	}
}

// Natively the project is writable and the Web UI keeps sharing the project
// file with the CLI and the IDE tools.
func TestWebSuppressionsNativeWriteTheProjectFile(t *testing.T) {
	root, reports := baselineTestProject(t)
	finding := scannedInnerHTML(t, root)
	t.Setenv("AITRIAGE_RUNTIME", "")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	s := setupTestServer(t)
	s.hostPrefix = root

	want := filepath.Join(root, suppression.File)
	added := callSuppressions(t, s, http.MethodPost, "/api/suppressions", dismissal(t, finding, "false_positive", ""))
	if added.Path != want || added.Total != 1 {
		t.Fatalf("native add response = %+v, want the project file %s", added, want)
	}
	mustExist(t, want)
	mustNotExist(t, filepath.Join(reports, "suppressions"))
}
