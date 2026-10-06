package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/scanner/detector"
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
			{Name: "npm", Manifests: []string{"package.json"}, Lockfiles: []string{"package-lock.json", "yarn.lock"}, WorkspaceRoot: true},
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

	if missing := missingLockEcosystems(lockRule(), dir, dir); len(missing) != 0 {
		t.Errorf("missing = %v; a PHP project with composer.lock is fully pinned", missing)
	}
}

func TestComposerProjectWithoutLockIsReported(t *testing.T) {
	dir := projectWith(t, "composer.json")

	missing := missingLockEcosystems(lockRule(), dir, dir)
	if len(missing) != 1 || missing[0] != "Composer (PHP)" {
		t.Errorf("missing = %v; want exactly the PHP ecosystem", missing)
	}
}

func TestPhpProjectIsNotAskedForGoOrNpmLockfiles(t *testing.T) {
	dir := projectWith(t, "composer.json", "composer.lock")

	for _, name := range missingLockEcosystems(lockRule(), dir, dir) {
		if name == "Go" || name == "npm" {
			t.Errorf("a PHP project was asked for the %s lockfile", name)
		}
	}
}

func TestEachEcosystemIsJudgedIndependently(t *testing.T) {
	// Pinned on the PHP side, unpinned on the npm side.
	dir := projectWith(t, "composer.json", "composer.lock", "package.json")

	missing := missingLockEcosystems(lockRule(), dir, dir)
	if len(missing) != 1 || missing[0] != "npm" {
		t.Errorf("missing = %v; want only npm", missing)
	}
}

func TestProjectWithNoManifestHasNothingToPin(t *testing.T) {
	dir := projectWith(t, "README.md")

	if missing := missingLockEcosystems(lockRule(), dir, dir); len(missing) != 0 {
		t.Errorf("missing = %v; a project with no dependency manifest has no lockfile to demand", missing)
	}
}

func TestLegacyFlatFileListStillWorks(t *testing.T) {
	// Rules written before ecosystems existed keep their any-of semantics.
	legacy := Rule{ID: "ENTR-02", Condition: "missing_lockfile", Files: []string{"go.sum", "yarn.lock"}}

	dir := projectWith(t, "go.sum")
	if missing := missingLockEcosystems(legacy, dir, dir); len(missing) != 0 {
		t.Errorf("missing = %v; a legacy rule is satisfied by any listed lockfile", missing)
	}

	empty := projectWith(t)
	if missing := missingLockEcosystems(legacy, empty, empty); len(missing) == 0 {
		t.Errorf("a legacy rule with no lockfile present must still report")
	}
}

func writeFiles(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func TestWorkspaceLockfileInAnAncestorPinsTheMember(t *testing.T) {
	root := t.TempDir()
	member := filepath.Join(root, "apps", "web", "packages", "ui")
	writeFiles(t, filepath.Join(root, "yarn.lock"), filepath.Join(member, "package.json"))

	if missing := missingLockEcosystems(lockRule(), member, root); len(missing) != 0 {
		t.Errorf("missing = %v; the workspace root yarn.lock pins every member below it", missing)
	}
}

func TestPerModuleLockfileIsNotTakenFromAnAncestor(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "services", "api")
	writeFiles(t, filepath.Join(root, "go.sum"), filepath.Join(module, "go.mod"))

	missing := missingLockEcosystems(lockRule(), module, root)
	if len(missing) != 1 || missing[0] != "Go" {
		t.Errorf("missing = %v; every Go module needs its own go.sum", missing)
	}
}

func TestLockfileAboveTheScanRootDoesNotCount(t *testing.T) {
	outside := t.TempDir()
	scanRoot := filepath.Join(outside, "repo")
	member := filepath.Join(scanRoot, "packages", "app")
	writeFiles(t, filepath.Join(outside, "yarn.lock"), filepath.Join(member, "package.json"))

	missing := missingLockEcosystems(lockRule(), member, scanRoot)
	if len(missing) != 1 || missing[0] != "npm" {
		t.Errorf("missing = %v; a lockfile outside the scanned repository pins nothing in it", missing)
	}
}

func TestWithoutScanRootOnlyTheProjectDirectoryIsChecked(t *testing.T) {
	root := t.TempDir()
	member := filepath.Join(root, "packages", "app")
	writeFiles(t, filepath.Join(root, "yarn.lock"), filepath.Join(member, "package.json"))

	missing := missingLockEcosystems(lockRule(), member, "")
	if len(missing) != 1 || missing[0] != "npm" {
		t.Errorf("missing = %v; with no scan root there is no workspace boundary to search up to", missing)
	}
}

func TestRelativeScanRootIsSearchedUpToItself(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, filepath.Join(root, "yarn.lock"), filepath.Join(root, "packages", "app", "package.json"))
	t.Chdir(root)

	if missing := missingLockEcosystems(lockRule(), filepath.Join("packages", "app"), "."); len(missing) != 0 {
		t.Errorf("missing = %v; `aitriage scan .` must find the workspace lockfile in the current directory", missing)
	}
}

func yarnWorkspace(t *testing.T, withRootLockfile bool) (root, member string) {
	t.Helper()
	root = t.TempDir()
	member = filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(root, "package.json"):   `{"name":"root","private":true,"workspaces":["packages/*"]}`,
		filepath.Join(member, "package.json"): `{"name":"app","dependencies":{"react":"18.2.0"}}`,
	}
	if withRootLockfile {
		files[filepath.Join(root, "yarn.lock")] = "__metadata:\n  version: 8\n"
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return root, member
}

func lockfileFindingsByProject(t *testing.T, root string) map[string]bool {
	t.Helper()
	ws, err := core.NewWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, project := range detector.DetectProjects(ws) {
		reported[project.RootPath] = false
		for _, result := range eng.Run(project) {
			if result.ID == "ENTR-02" {
				reported[project.RootPath] = true
			}
		}
	}
	return reported
}

func TestYarnWorkspaceMemberIsPinnedByTheRootLockfile(t *testing.T) {
	root, member := yarnWorkspace(t, true)

	reported := lockfileFindingsByProject(t, root)
	flagged, detected := reported[member]
	if !detected {
		t.Fatalf("workspace member %s was not detected as a project; projects: %v", member, reported)
	}
	if flagged {
		t.Errorf("ENTR-02 reported for %s although the workspace is pinned by the root yarn.lock", member)
	}
}

func TestYarnWorkspaceWithoutRootLockfileIsReported(t *testing.T) {
	root, member := yarnWorkspace(t, false)

	if reported := lockfileFindingsByProject(t, root); !reported[member] {
		t.Errorf("ENTR-02 not reported for %s although the workspace has no lockfile", member)
	}
}
