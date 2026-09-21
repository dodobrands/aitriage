package baseline

import (
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// Issue #30: the baseline file is meant to be committed, and it stored absolute
// paths. That shipped the author's home directory into the repository and made
// the file useless on any other machine — in CI the recorded path matched
// nothing at all.

func TestPathsAreStoredRelativeToTheProject(t *testing.T) {
	root := t.TempDir()
	items := Relativize(root, []Item{
		{Source: "core", RuleID: "ENTR-17", File: filepath.Join(root, "app", "config.php")},
		{Source: "trivy", RuleID: "CVE-1", File: filepath.Join(root, "composer.lock")},
	})

	for _, item := range items {
		if filepath.IsAbs(item.File) {
			t.Errorf("%s kept an absolute path: %q", item.RuleID, item.File)
		}
	}
	if items[0].File != "app/config.php" {
		t.Errorf("file = %q; want app/config.php", items[0].File)
	}
	if items[1].File != "composer.lock" {
		t.Errorf("file = %q; want composer.lock", items[1].File)
	}
}

func TestRelativePathLeavesUnusualPathsAlone(t *testing.T) {
	root := t.TempDir()

	// Already relative: nothing to do.
	if got := RelativePath(root, "app/main.go"); got != "app/main.go" {
		t.Errorf("relative path was rewritten: %q", got)
	}
	// A name beginning with two dots is still inside the project.
	if got := RelativePath(root, filepath.Join(root, "..config")); got != "..config" {
		t.Errorf("in-project file became %q; want ..config", got)
	}
	// Outside the root: preserve the location with portable separators rather
	// than emit ../../.. — a finding is never dropped because it is unusual.
	outside := filepath.Join(t.TempDir(), "passwd")
	if got, want := RelativePath(root, outside), filepath.ToSlash(outside); got != want {
		t.Errorf("path outside the root = %q; want %q", got, want)
	}
	// No root known: pass through, cleaned.
	unclean := filepath.Join(root, "a", "b", "..", "c")
	if got, want := RelativePath("", unclean), filepath.ToSlash(filepath.Clean(unclean)); got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	// Project-level findings carry no file.
	if got := RelativePath(root, ""); got != "" {
		t.Errorf("empty path became %q", got)
	}
}

func TestPathsAreSlashedOnEveryPlatform(t *testing.T) {
	// The file is committed and read on other systems, so separators must not
	// depend on who wrote it.
	root := t.TempDir()
	got := RelativePath(root, filepath.Join(root, "a", "b", "c.go"))
	if got != "a/b/c.go" {
		t.Errorf("got %q; want a/b/c.go", got)
	}
}

// The fingerprint includes the path, so making paths relative changes every key.
// Without the migration below, upgrading would resurface everything a team had
// already accepted — the worst possible outcome for a baseline.
func TestBaselineWrittenWithAbsolutePathsStillMatchesAfterUpgrade(t *testing.T) {
	root := t.TempDir()
	absolute := Item{Source: "trivy", RuleID: "CVE-1", File: filepath.Join(root, "composer.lock"), Evidence: "guzzle 7.8.1"}

	// A version "2" baseline, as written before the fix.
	old := NewFromItems([]Item{absolute})
	old.Version = SchemaVersion2

	// The same finding as it is reported now: relative.
	current := absolute
	current.File = "composer.lock"

	if !old.AcceptsInProject(root, current) {
		t.Fatal("an accepted finding came back after the upgrade")
	}
}

func TestVersionOneBaselineSurvivesTheRelativePathChange(t *testing.T) {
	root := t.TempDir()
	legacyResults := []core.CheckResult{
		{ID: "ENTR-17", File: filepath.Join(root, "app", "config.php"), Evidence: "key=abc", Severity: "CRITICAL"},
	}
	legacy := New(legacyResults) // version "1", absolute paths

	current := Item{Source: "core", RuleID: "ENTR-17", File: "app/config.php", Evidence: "key=abc"}

	if !legacy.AcceptsInProject(root, current) {
		t.Error("a finding accepted under the oldest format came back after the upgrade")
	}
}

func TestCurrentBaselinesNeedNoLegacyLookup(t *testing.T) {
	root := t.TempDir()
	relative := Item{Source: "trivy", RuleID: "CVE-1", File: "composer.lock", Evidence: "e"}

	modern := NewFromItems([]Item{relative})
	if modern.Version != CurrentSchema {
		t.Fatalf("version = %q; want %q", modern.Version, CurrentSchema)
	}
	if !modern.AcceptsInProject(root, relative) {
		t.Error("a current baseline does not match its own findings")
	}
	// A genuinely different finding must still be reported.
	other := relative
	other.RuleID = "CVE-2"
	if modern.AcceptsInProject(root, other) {
		t.Error("the migration path made an unrelated finding look accepted")
	}
}

// The stored record must not contain anything identifying the machine.
func TestStoredEntriesCarryNoLocalLayout(t *testing.T) {
	root := t.TempDir()
	items := Relativize(root, []Item{
		{Source: "core", RuleID: "R1", File: filepath.Join(root, "src", "a.go")},
		{Source: "semgrep", RuleID: "R2", File: filepath.Join(root, "web", "b.ts")},
	})

	b := NewFromItems(items)
	for _, finding := range b.Findings {
		if filepath.IsAbs(finding.File) {
			t.Errorf("%s stored an absolute path: %q", finding.RuleID, finding.File)
		}
		if finding.File != "" && (finding.File[0] == '/' || len(finding.File) > 1 && finding.File[1] == ':') {
			t.Errorf("%s stored a rooted path: %q", finding.RuleID, finding.File)
		}
	}
}

func TestCLIFilterMatchesCurrentAndOlderBaselines(t *testing.T) {
	root := t.TempDir()
	absolute := filepath.Join(root, "app", "config.php")
	accepted := core.CheckResult{ID: "ENTR-17", File: absolute, Evidence: "key=abc"}
	newFinding := core.CheckResult{ID: "ENTR-18", File: absolute, Evidence: "key=def"}

	current := NewFromItems(Relativize(root, FromCore([]core.CheckResult{accepted})))
	oldV2 := NewFromItems(FromCore([]core.CheckResult{accepted}))
	oldV2.Version = SchemaVersion2
	oldV1 := New([]core.CheckResult{accepted})

	for _, tc := range []struct {
		name string
		b    *Baseline
	}{
		{"current", current},
		{"v2", oldV2},
		{"v1", oldV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterInProject(root, []core.CheckResult{accepted, newFinding}, tc.b)
			if len(got.Baseline) != 1 || got.Baseline[0].ID != accepted.ID {
				t.Errorf("accepted = %+v", got.Baseline)
			}
			if len(got.New) != 1 || got.New[0].ID != newFinding.ID {
				t.Errorf("new = %+v", got.New)
			}
		})
	}
}

func TestOlderBaselinesStillMatchAfterCheckoutMoves(t *testing.T) {
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	oldFile := filepath.Join(oldRoot, "app", "config.php")
	accepted := core.CheckResult{ID: "ENTR-17", File: oldFile, Evidence: "key=abc"}
	newFile := filepath.Join(newRoot, "app", "config.php")
	current := Item{Source: "core", RuleID: accepted.ID, File: "app/config.php", Evidence: accepted.Evidence}

	oldV2 := NewFromItems(FromCore([]core.CheckResult{accepted}))
	oldV2.Version = SchemaVersion2
	oldV1 := New([]core.CheckResult{accepted})
	for _, b := range []*Baseline{oldV1, oldV2} {
		if !b.AcceptsInProject(newRoot, current) {
			t.Errorf("version %s lost an accepted finding after checkout moved", b.Version)
		}
		changed := current
		changed.Evidence = "different key"
		if b.AcceptsInProject(newRoot, changed) {
			t.Errorf("version %s hid different evidence", b.Version)
		}
		if got := FilterInProject(newRoot, []core.CheckResult{{ID: accepted.ID, File: newFile, Evidence: accepted.Evidence}}, b); len(got.Baseline) != 1 {
			t.Errorf("version %s CLI filter lost an accepted finding", b.Version)
		}
	}
}

func TestLegacyPathMatchesAcrossOperatingSystems(t *testing.T) {
	if !LegacyPathMatches(`C:\Users\alice\shop\app\config.php`, "app/config.php") {
		t.Error("Windows baseline path did not match a relative file")
	}
	if LegacyPathMatches(`C:\Users\alice\shop\other\config.php`, "app/config.php") {
		t.Error("different directories matched")
	}
	if LegacyPathMatches("/home/alice/shop/app/config.php", "../app/config.php") {
		t.Error("parent traversal matched an old path")
	}
}
