package statefile

import (
	"os"
	"path/filepath"
	"testing"
)

const testFile = ".aitriage-test-state.json"

// containerProject lays out a project the way the container sees it: the
// project root with its aitriage-reports directory inside.
func containerProject(t *testing.T) (root, reports string) {
	t.Helper()
	root = t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	reports = filepath.Join(root, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, reports
}

func inContainer(t *testing.T, reports string) {
	t.Helper()
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
}

func writeState(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, testFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Natively the project is writable and its own file is the only one, so the
// CLI, the Web UI and the IDE tools keep sharing it.
func TestNativeRuntimeUsesTheProjectFile(t *testing.T) {
	root, reports := containerProject(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	writeState(t, root)

	loc := Locate(root, "area", testFile)
	if loc.Redirected() || loc.WriteDir != root || loc.HasCopy() || loc.CurrentFile() != filepath.Join(root, testFile) {
		t.Fatalf("native location = %+v, want the project file for reads and writes", loc)
	}
	if _, ok := ReportsDir(root); ok {
		t.Fatal("natively nothing is redirected to the reports directory")
	}
	if err := loc.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(reports, "area")); !os.IsNotExist(err) {
		t.Fatalf("native Prepare created a folder under the reports directory (stat err = %v)", err)
	}
}

// Without a reports directory the container has nowhere else to write, and a
// write to the project must fail visibly rather than land somewhere unknown.
func TestContainerWithoutReportsDirUsesTheProjectFile(t *testing.T) {
	root, _ := containerProject(t)
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", "")

	if loc := Locate(root, "area", testFile); loc.Redirected() {
		t.Fatalf("location without a reports directory = %+v, want the project", loc)
	}
	if _, ok := ReportsDir(root); ok {
		t.Fatal("a reports directory was reported although none is configured")
	}
}

// In the container the copy mirrors the scanned folder, so two folders of one
// project never share a file. The project's own file is named as the record's
// home until a copy exists.
func TestContainerWritesMirrorTheScannedFolder(t *testing.T) {
	root, reports := containerProject(t)
	inContainer(t, reports)
	nested := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	top := Locate(root, "area", testFile)
	if want := filepath.Join(reports, "area"); top.WriteDir != want {
		t.Fatalf("root writes to %s, want %s", top.WriteDir, want)
	}
	inner := Locate(nested, "area", testFile)
	if want := filepath.Join(reports, "area", "services", "api"); inner.WriteDir != want {
		t.Fatalf("nested folder writes to %s, want %s", inner.WriteDir, want)
	}
	for _, folder := range []string{root, nested} {
		if got, ok := ReportsDir(folder); !ok || got != reports {
			t.Fatalf("ReportsDir(%s) = %s, %v; want %s", folder, got, ok, reports)
		}
	}

	if inner.HasCopy() || inner.CurrentFile() != filepath.Join(nested, testFile) {
		t.Fatalf("without a copy the record's home is %s (copy=%v), want the project file", inner.CurrentFile(), inner.HasCopy())
	}
	if err := inner.Prepare(); err != nil {
		t.Fatal(err)
	}
	writeState(t, inner.WriteDir)
	if !inner.HasCopy() || inner.CurrentFile() != inner.WriteFile() {
		t.Fatalf("with a copy the record's home is %s (copy=%v), want %s", inner.CurrentFile(), inner.HasCopy(), inner.WriteFile())
	}
	if top.HasCopy() {
		t.Fatal("the root picked up the nested folder's copy")
	}
	if inner.ProjectFile() != filepath.Join(nested, testFile) {
		t.Fatalf("project file = %s", inner.ProjectFile())
	}
}

// The container agent scans ".", and a folder reached through a symlink is the
// same folder: both must map to the copy every other surface uses.
func TestContainerLocationIgnoresHowTheFolderIsNamed(t *testing.T) {
	root, reports := containerProject(t)
	inContainer(t, reports)
	want := filepath.Join(reports, "area")

	t.Chdir(root)
	if loc := Locate(".", "area", testFile); loc.WriteDir != want || loc.ProjectDir != "." {
		t.Fatalf("relative location = %+v, want writes to %s and reads from the given path", loc, want)
	}

	link := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if loc := Locate(link, "area", testFile); loc.WriteDir != want {
		t.Fatalf("symlinked folder writes to %s, want %s", loc.WriteDir, want)
	}
}

// A folder outside the project the reports directory belongs to has no
// mirror, so it keeps its own file.
func TestContainerFolderOutsideTheProjectIsNotRedirected(t *testing.T) {
	_, reports := containerProject(t)
	inContainer(t, reports)

	outside := t.TempDir()
	if loc := Locate(outside, "area", testFile); loc.Redirected() {
		t.Fatalf("folder outside the project was redirected: %+v", loc)
	}
	if _, ok := ReportsDir(outside); ok {
		t.Fatal("a folder outside the project was given the project's reports directory")
	}
}

// A copy that exists but cannot be read still counts as present: skipping it
// would silently drop the decisions it records instead of reporting them.
func TestUnreadableCopyCountsAsPresent(t *testing.T) {
	root, reports := containerProject(t)
	inContainer(t, reports)
	loc := Locate(root, "area", testFile)
	// A directory where the file should be makes the stat succeed and any
	// read fail, which is what an unreadable copy looks like to a loader.
	if err := os.MkdirAll(loc.WriteFile(), 0o700); err != nil {
		t.Fatal(err)
	}
	if !loc.HasCopy() {
		t.Fatal("an unreadable copy was treated as missing")
	}
}
