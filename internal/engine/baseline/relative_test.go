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
	// Outside the root: keep it rather than emit ../../.. — a finding is never
	// dropped or mangled just because its path is unusual.
	outside := filepath.Join(t.TempDir(), "passwd")
	if got := RelativePath(root, outside); got != outside {
		t.Errorf("path outside the root = %q; want it untouched", got)
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
