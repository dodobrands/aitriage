package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/models"
)

// ENTR-02 listed npm, pip, go, cargo and poetry lockfiles but not composer.lock,
// so a PHP project with a perfectly good lockfile was told it had none. The rule
// also accepted any lockfile from any ecosystem, which meant a Go project could
// satisfy it with a yarn.lock it never used.

func lockRule() Rule {
	return Rule{
		ID:        "ENTR-02",
		Name:      "Missing Lockfile",
		Condition: "missing_lockfile",
		Ecosystems: []models.Ecosystem{
			{Name: "Composer (PHP)", Manifests: []string{"composer.json"}, Lockfiles: []string{"composer.lock"}},
			{Name: "Go", Manifests: []string{"go.mod"}, Lockfiles: []string{"go.sum"}},
			{Name: "npm", Manifests: []string{"package.json"}, Lockfiles: []string{"package-lock.json", "yarn.lock"}},
		},
	}
}

func projectWith(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestComposerLockSatisfiesTheLockfileRule(t *testing.T) {
	dir := projectWith(t, "composer.json", "composer.lock")

	if missing := missingLockEcosystems(lockRule(), dir); len(missing) != 0 {
		t.Errorf("missing = %v; a PHP project with composer.lock is fully pinned", missing)
	}
}

func TestComposerProjectWithoutLockIsReported(t *testing.T) {
	dir := projectWith(t, "composer.json")

	missing := missingLockEcosystems(lockRule(), dir)
	if len(missing) != 1 || missing[0] != "Composer (PHP)" {
		t.Errorf("missing = %v; want exactly the PHP ecosystem", missing)
	}
}

func TestPhpProjectIsNotAskedForGoOrNpmLockfiles(t *testing.T) {
	dir := projectWith(t, "composer.json", "composer.lock")

	for _, name := range missingLockEcosystems(lockRule(), dir) {
		if name == "Go" || name == "npm" {
			t.Errorf("a PHP project was asked for the %s lockfile", name)
		}
	}
}

func TestEachEcosystemIsJudgedIndependently(t *testing.T) {
	// Pinned on the PHP side, unpinned on the npm side.
	dir := projectWith(t, "composer.json", "composer.lock", "package.json")

	missing := missingLockEcosystems(lockRule(), dir)
	if len(missing) != 1 || missing[0] != "npm" {
		t.Errorf("missing = %v; want only npm", missing)
	}
}

func TestProjectWithNoManifestHasNothingToPin(t *testing.T) {
	dir := projectWith(t, "README.md")

	if missing := missingLockEcosystems(lockRule(), dir); len(missing) != 0 {
		t.Errorf("missing = %v; a project with no dependency manifest has no lockfile to demand", missing)
	}
}

func TestLegacyFlatFileListStillWorks(t *testing.T) {
	// Rules written before ecosystems existed keep their any-of semantics.
	legacy := Rule{ID: "ENTR-02", Condition: "missing_lockfile", Files: []string{"go.sum", "yarn.lock"}}

	dir := projectWith(t, "go.sum")
	if missing := missingLockEcosystems(legacy, dir); len(missing) != 0 {
		t.Errorf("missing = %v; a legacy rule is satisfied by any listed lockfile", missing)
	}

	empty := projectWith(t)
	if missing := missingLockEcosystems(legacy, empty); len(missing) == 0 {
		t.Errorf("a legacy rule with no lockfile present must still report")
	}
}
