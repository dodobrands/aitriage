package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// containerFolder is a project as the container sees it, with the container
// environment set.
func containerFolder(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(project); err == nil {
		project = resolved
	}
	reports := filepath.Join(project, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	return project
}

var (
	acceptedLocally  = Item{Source: "core", RuleID: "ENTR-INNERHTML", File: "app.js", Severity: "HIGH", Evidence: "innerHTML"}
	acceptedUpstream = Item{Source: "trivy", RuleID: "CVE-2026-1", File: "package-lock.json", Severity: "MEDIUM", Evidence: "lodash 4.17.20"}
)

func mustLoadAt(t *testing.T, project string) *Baseline {
	t.Helper()
	b, err := LoadAt(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("no baseline applies")
	}
	return b
}

// A baseline committed to the project after the local copy was written still
// applies: findings accepted in either file are accepted.
func TestContainerBaselineIncludesFindingsCommittedLater(t *testing.T) {
	project := containerFolder(t)
	if err := SaveAt(Locate(project), NewFromItems([]Item{acceptedLocally})); err != nil {
		t.Fatal(err)
	}
	if err := Save(project, NewFromItems([]Item{acceptedUpstream})); err != nil {
		t.Fatal(err)
	}

	applied := mustLoadAt(t, project)
	if !applied.Accepts(acceptedLocally) || !applied.Accepts(acceptedUpstream) || applied.Stats().Total != 2 {
		t.Fatalf("applied baseline = %+v, want both the local and the committed finding", applied.Findings)
	}
}

// For a finding in both files the copy's record is kept, and the combined
// baseline dates from the older of the two.
func TestContainerBaselineCopyWinsForTheSameFinding(t *testing.T) {
	project := containerFolder(t)
	committed := NewFromItems([]Item{acceptedUpstream})
	committed.CreatedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := Save(project, committed); err != nil {
		t.Fatal(err)
	}
	relabelled := acceptedUpstream
	relabelled.Severity = "CRITICAL"
	if err := SaveAt(Locate(project), NewFromItems([]Item{relabelled})); err != nil {
		t.Fatal(err)
	}

	applied := mustLoadAt(t, project)
	if applied.Stats().Total != 1 || applied.Findings[FingerprintItem(acceptedUpstream)].Severity != "CRITICAL" {
		t.Fatalf("applied baseline = %+v, want the copy's record of the shared finding", applied.Findings)
	}
	if !applied.CreatedAt.Equal(committed.CreatedAt) {
		t.Fatalf("created_at = %s, want the older date %s", applied.CreatedAt, committed.CreatedAt)
	}
}

// A project baseline in an older format keeps matching the way that format
// requires once a local copy, always in the current format, is combined
// with it.
func TestContainerBaselineKeepsMatchingOlderProjectFormats(t *testing.T) {
	project := containerFolder(t)
	legacy := core.CheckResult{ID: "DOCKER-NO-USER", File: filepath.Join(project, "Dockerfile"), Evidence: "FROM debian", Severity: "HIGH"}
	if err := Save(project, New([]core.CheckResult{legacy})); err != nil {
		t.Fatal(err)
	}
	if err := SaveAt(Locate(project), NewFromItems([]Item{acceptedLocally})); err != nil {
		t.Fatal(err)
	}

	applied := mustLoadAt(t, project)
	scanned := Relativize(project, FromCore([]core.CheckResult{legacy}))[0]
	if !applied.AcceptsInProject(project, scanned) {
		t.Error("a finding accepted by the project's older baseline resurfaced next to a local copy")
	}
	if !applied.AcceptsInProject(project, acceptedLocally) {
		t.Error("the local copy's finding is not accepted")
	}
}

// Natively only the project's own file counts, whatever the reports directory
// holds.
func TestNativeBaselineIsTheProjectFile(t *testing.T) {
	project := containerFolder(t)
	if err := SaveAt(Locate(project), NewFromItems([]Item{acceptedLocally})); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AITRIAGE_RUNTIME", "")
	if b, err := LoadAt(Locate(project)); err != nil || b != nil {
		t.Fatalf("native LoadAt = %+v, %v; want no baseline, since the project has none", b, err)
	}
}
