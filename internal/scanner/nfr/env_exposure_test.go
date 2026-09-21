package nfr

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// NFR-ENV-002 used to fire on the mere existence of a .env file and claim it
// "may be committed to git". Every developer has a local .env, so the rule
// produced a CRITICAL finding on correctly configured projects.

func initRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestEnvIgnoredByGitIsNotAFinding(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, filepath.Join(dir, ".gitignore"), ".env\n")
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY=secret\n")

	if fileIsExposedToGit(dir, ".env") {
		t.Errorf("a .env covered by .gitignore was reported as exposed")
	}
}

func TestEnvTrackedByGitIsAFinding(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY=secret\n")
	gitRun(t, dir, "add", ".env")

	if !fileIsExposedToGit(dir, ".env") {
		t.Errorf("a .env tracked by git was not reported as exposed")
	}
}

func TestEnvUntrackedAndUnignoredIsAFinding(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY=secret\n")

	// Nothing ignores it, so the next `git add .` commits it.
	if !fileIsExposedToGit(dir, ".env") {
		t.Errorf("an unignored, untracked .env was not reported as exposed")
	}
}

func TestMissingEnvIsNeverAFinding(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)

	if fileIsExposedToGit(dir, ".env") {
		t.Errorf("a project without a .env was reported as exposed")
	}
}

func TestNonRepositoryFallsBackToPresence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "API_KEY=secret\n")

	// Outside a repository there is no way to prove the file is ignored, so the
	// conservative answer is that it is exposed.
	if !fileIsExposedToGit(dir, ".env") {
		t.Errorf("a .env outside a git repository must be treated as exposed")
	}
}
