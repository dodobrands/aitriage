package suppression

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
)

// containerFolder is a project as the container sees it: its own folder with
// the writable aitriage-reports directory inside, and the container
// environment set.
func containerFolder(t *testing.T) (project, reports string) {
	t.Helper()
	project = t.TempDir()
	if resolved, err := filepath.EvalSymlinks(project); err == nil {
		project = resolved
	}
	reports = filepath.Join(project, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	return project, reports
}

// commit writes the project's own record, as a commit pulled into the
// checkout would.
func commit(t *testing.T, project string, items map[baseline.Item]string) {
	t.Helper()
	store := New()
	for it, reason := range items {
		if _, _, err := store.Add(it, reason, "reviewed upstream", "upstream"); err != nil {
			t.Fatal(err)
		}
	}
	if err := Save(project, store); err != nil {
		t.Fatal(err)
	}
}

func recordLocally(t *testing.T, project string, it baseline.Item, reason, note string) Entry {
	t.Helper()
	record, err := Open(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err := record.Add(it, reason, note, "container")
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Save(); err != nil {
		t.Fatal(err)
	}
	return entry
}

var (
	localFinding     = item("core", "ENTR-INNERHTML", "app.js", "document.body.innerHTML = location.hash")
	committedFinding = item("trivy", "CVE-2026-1", "package-lock.json", "lodash 4.17.20")
)

// A decision committed to the project after the local copy was written still
// applies: the copy adds to the project's record instead of replacing it.
func TestContainerAppliesDecisionsCommittedAfterTheCopy(t *testing.T) {
	project, reports := containerFolder(t)
	recordLocally(t, project, localFinding, ReasonFalsePositive, "")
	if _, err := os.Stat(filepath.Join(reports, ReportsArea, File)); err != nil {
		t.Fatalf("the local decision was not written under the reports directory: %v", err)
	}
	commit(t, project, map[baseline.Item]string{committedFinding: ReasonAcceptedRisk})

	applied, err := LoadAt(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := applied.Suppresses(committedFinding); !ok {
		t.Error("a decision committed after the local copy was written does not apply")
	}
	if _, ok := applied.Suppresses(localFinding); !ok {
		t.Error("the local decision stopped applying once the project changed")
	}
}

// For the same finding the local entry wins over the project's, keeps the
// project entry's date, and stays in force after the project drops its own.
func TestContainerCopyOverridesTheProjectEntry(t *testing.T) {
	project, _ := containerFolder(t)
	commit(t, project, map[baseline.Item]string{committedFinding: ReasonFalsePositive})
	committedEntry, _ := mustLoad(t, project).Suppresses(committedFinding)

	record, err := Open(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	entry, replaced, err := record.Add(committedFinding, ReasonAcceptedRisk, "mitigated at the gateway", "container")
	if err != nil {
		t.Fatal(err)
	}
	if !replaced || !entry.CreatedAt.Equal(committedEntry.CreatedAt) {
		t.Fatalf("override = %+v (replaced=%v), want it reported as a replacement keeping the date %s", entry, replaced, committedEntry.CreatedAt)
	}
	if err := record.Save(); err != nil {
		t.Fatal(err)
	}

	applied, err := LoadAt(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := applied.Suppresses(committedFinding)
	if !ok || got.Reason != ReasonAcceptedRisk || got.Note != "mitigated at the gateway" || len(applied.Entries) != 1 {
		t.Fatalf("applied = %+v, want the local decision in place of the project's", applied.Entries)
	}

	// The project drops its own entry; the local one is not undone by that.
	commit(t, project, nil)
	applied, err = LoadAt(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := applied.Suppresses(committedFinding); !ok {
		t.Error("a local decision stopped applying when the project removed its own entry")
	}
}

// A decision recorded in the project's own file cannot be undone from the
// container, where that file is read-only. Remove says so instead of
// pretending, and removing a local override brings the project's entry back.
func TestContainerRemoveReportsCommittedDecisions(t *testing.T) {
	project, _ := containerFolder(t)
	commit(t, project, map[baseline.Item]string{committedFinding: ReasonFalsePositive})

	record, err := Open(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	if removed, committed := record.Remove("CVE-2026-1"); removed != 0 || committed != 1 {
		t.Fatalf("Remove of a committed decision = (%d, %d), want (0, 1)", removed, committed)
	}
	if _, ok := record.Applied.Suppresses(committedFinding); !ok {
		t.Fatal("a committed decision disappeared from what applies")
	}

	if _, _, err := record.Add(committedFinding, ReasonWontFix, "", "container"); err != nil {
		t.Fatal(err)
	}
	if removed, committed := record.Remove("CVE-2026-1"); removed != 1 || committed != 1 {
		t.Fatalf("Remove of a local override = (%d, %d), want (1, 1)", removed, committed)
	}
	if got, ok := record.Applied.Suppresses(committedFinding); !ok || got.Reason != ReasonFalsePositive {
		t.Fatalf("after removing the override the project's entry should apply again, got %+v (ok=%v)", got, ok)
	}
}

// Natively there is one file, read and written as before.
func TestNativeRecordIsTheProjectFile(t *testing.T) {
	project := t.TempDir()
	t.Setenv("AITRIAGE_RUNTIME", "")
	commit(t, project, map[baseline.Item]string{committedFinding: ReasonFalsePositive})

	record, err := Open(Locate(project))
	if err != nil {
		t.Fatal(err)
	}
	if removed, committed := record.Remove("CVE-2026-1"); removed != 1 || committed != 0 {
		t.Fatalf("native Remove = (%d, %d), want (1, 0)", removed, committed)
	}
	if err := record.Save(); err != nil {
		t.Fatal(err)
	}
	if store := mustLoad(t, project); len(store.Entries) != 0 {
		t.Fatalf("the project file still holds %v", store.Entries)
	}
}

func mustLoad(t *testing.T, dir string) *Store {
	t.Helper()
	store, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
