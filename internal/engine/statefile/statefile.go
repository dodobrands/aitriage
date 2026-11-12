// Package statefile decides where the project files that record decisions
// made through AITriage are read and written: the accepted baseline and the
// dismissed findings.
//
// Natively each is a file in the scanned folder. The CLI, the Web UI and the
// IDE tools share it, and it is committed with the repository.
//
// The container runtime mounts the project read-only and only
// <project>/aitriage-reports read-write (internal/runtime.DockerRunArgs), so
// writing the project file there can only fail. In that runtime a write goes
// to a local copy under the reports directory instead, at a path that mirrors
// the scanned folder. Readers combine the project's own file with that copy:
// an entry in either applies, and where both record the same finding the
// copy's entry wins. A decision committed to the project later therefore
// still applies. A local entry also stays in force after the project drops
// its own entry for the same finding: local decisions override until they are
// committed or the copy is deleted.
//
// A copy is local to the machine: aitriage-reports is not committed, so a
// decision recorded in the container reaches CI and other checkouts only once
// the file is copied into the project and committed.
package statefile

import (
	"os"
	"path/filepath"
	"strings"
)

// LocalOverrideNote is what a surface tells its user while a local copy is in
// effect.
const LocalOverrideNote = "Local decisions in aitriage-reports are applied on top of the project's own file and override it for the same finding; commit them to the project to share them with CI."

// Location is where one state file of one scanned folder is read and written.
type Location struct {
	// ProjectDir is the scanned folder. Its own copy of the file is the one
	// the CLI reads and the one committed with the repository.
	ProjectDir string
	// WriteDir receives the file on every write. It is ProjectDir unless the
	// project is mounted read-only, in which case it is a folder under the
	// reports directory that mirrors the scanned folder.
	WriteDir string
	// Name is the file name, for example .aitriage-baseline.json.
	Name string
}

// Locate resolves where the state file name of the scanned folder projectDir
// lives. area is the folder under the reports directory that holds this kind
// of file when the project is read-only.
func Locate(projectDir, area, name string) Location {
	loc := Location{ProjectDir: projectDir, WriteDir: projectDir, Name: name}
	if reports, rel, ok := redirect(projectDir); ok {
		loc.WriteDir = filepath.Join(reports, area, rel)
	}
	return loc
}

// ReportsDir returns the writable reports directory that takes the writes
// meant for the scanned folder projectDir while the project is mounted
// read-only, or false when the folder's own location is written.
func ReportsDir(projectDir string) (string, bool) {
	reports, _, ok := redirect(projectDir)
	return reports, ok
}

// redirect decides whether writes for projectDir go to the reports directory.
//
// They do only in the container runtime (AITRIAGE_RUNTIME=container) with a
// known reports directory (AITRIAGE_REPORTS_DIR). Every launcher places that
// directory at <project root>/aitriage-reports, so its parent is the root the
// scanned folder is mirrored against, and every surface in the container maps
// the same folder to the same place. Without a reports directory, or for a
// folder outside that root, there is nowhere else to write: a write to the
// project fails and its error says why.
func redirect(projectDir string) (reports, rel string, ok bool) {
	if os.Getenv("AITRIAGE_RUNTIME") != "container" {
		return "", "", false
	}
	reports = strings.TrimSpace(os.Getenv("AITRIAGE_REPORTS_DIR"))
	if reports == "" {
		return "", "", false
	}
	reports, err := filepath.Abs(reports)
	if err != nil {
		return "", "", false
	}
	rel, ok = mirrorPath(filepath.Dir(reports), projectDir)
	if !ok {
		return "", "", false
	}
	return reports, rel, true
}

// Redirected reports whether writes go to a local copy rather than the
// project's own file.
func (l Location) Redirected() bool {
	return l.WriteDir != l.ProjectDir
}

// ProjectFile is the project's own file.
func (l Location) ProjectFile() string {
	return filepath.Join(l.ProjectDir, l.Name)
}

// WriteFile is the path every write goes to.
func (l Location) WriteFile() string {
	return filepath.Join(l.WriteDir, l.Name)
}

// HasCopy reports whether a local copy exists. One that cannot be read counts
// as existing, so loading it reports the problem instead of skipping it.
func (l Location) HasCopy() bool {
	if !l.Redirected() {
		return false
	}
	_, err := os.Stat(l.WriteFile())
	return err == nil || !os.IsNotExist(err)
}

// CurrentFile is the file a surface names as the record's home: the local copy
// once one exists, otherwise the project's own file.
func (l Location) CurrentFile() string {
	if l.HasCopy() {
		return l.WriteFile()
	}
	return l.ProjectFile()
}

// Prepare creates the mirrored folder under the reports directory. The project
// folder is never created: it exists, or the request was wrong.
func (l Location) Prepare() error {
	if !l.Redirected() {
		return nil
	}
	return os.MkdirAll(l.WriteDir, 0o700)
}

// mirrorPath expresses dir relative to root. Both are resolved first, so a
// folder reached through a symlink maps to the same copy as the folder itself.
func mirrorPath(root, dir string) (string, bool) {
	rel, err := filepath.Rel(resolve(root), resolve(dir))
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func resolve(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}
