package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine"
	"github.com/dodobrands/aitriage/internal/rules/packs"
	"github.com/spf13/cobra"
)

// packsHome points the user's home directory, and with it ~/.aitriage/packs,
// at a temporary directory.
func packsHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func packRule(id string) string {
	return "  - id: " + id + "\n" +
		"    name: \"Synthetic pack rule\"\n" +
		"    stack: universal\n" +
		"    extensions: [\".js\"]\n" +
		"    pattern: 'syntheticDangerousCall\\('\n" +
		"    severity: HIGH\n" +
		"    suggestion: \"Avoid the synthetic call.\"\n"
}

// teamRulesSource builds a pack directory with three rules in two files, next
// to files that are not rule files and must not be installed.
func teamRulesSource(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "team-rules")
	writeTestFile(t, filepath.Join(src, "web.yaml"), "rules:\n"+packRule("TEAM-PACK-ONE")+packRule("TEAM-PACK-TWO"))
	writeTestFile(t, filepath.Join(src, "nested", "go.yml"), "rules:\n"+packRule("TEAM-PACK-THREE"))
	writeTestFile(t, filepath.Join(src, "broken.yaml"), "rules: [\n")
	writeTestFile(t, filepath.Join(src, "notes.yaml"), "title: not a rule file\n")
	writeTestFile(t, filepath.Join(src, "README.md"), "# Team rules\n")
	return src
}

func runRulesCommand(t *testing.T, run func(*cobra.Command, []string) error, args ...string) (string, error) {
	t.Helper()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := run(cmd, args)
	return out.String(), err
}

func assertNoStagingLeftovers(t *testing.T, home string) {
	t.Helper()
	leftovers, _ := filepath.Glob(filepath.Join(home, ".aitriage", ".rules-install-*"))
	if len(leftovers) != 0 {
		t.Fatalf("install left staging directories behind: %v", leftovers)
	}
}

// `rules list` used to advertise seven packs from repositories that were never
// published. It must list only what is installed and point at the one install
// path that works.
func TestRulesListAdvertisesOnlyInstalledPacks(t *testing.T) {
	packsHome(t)

	out, err := runRulesCommand(t, runRulesList)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "No rule packs installed") || !strings.Contains(out, rulesInstallHint) {
		t.Fatalf("empty list output does not say what to do:\n%s", out)
	}
	for _, text := range []string{out, rulesCmd.Long, rulesListCmd.Short, rulesInstallCmd.Short} {
		lower := strings.ToLower(text)
		if strings.Contains(lower, "registry") || strings.Contains(lower, "github.com/") || strings.Contains(lower, "owasp-api") {
			t.Fatalf("rules command still advertises a remote registry:\n%s", text)
		}
	}

	if _, err := runRulesCommand(t, runRulesInstall, teamRulesSource(t)); err != nil {
		t.Fatal(err)
	}
	out, err = runRulesCommand(t, runRulesList)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "team-rules (local) — 3 rules") {
		t.Fatalf("installed pack missing from list output:\n%s", out)
	}
}

func TestRulesInstallFromLocalDirectory(t *testing.T) {
	home := packsHome(t)
	src := teamRulesSource(t)

	out, err := runRulesCommand(t, runRulesInstall, src)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if !strings.Contains(out, "team-rules (3 rules from 2 files)") {
		t.Fatalf("install output does not count rules:\n%s", out)
	}
	for _, skipped := range []string{"broken.yaml: not a rule file", "notes.yaml: no rules"} {
		if !strings.Contains(out, skipped) {
			t.Errorf("install output does not report %q:\n%s", skipped, out)
		}
	}

	installed := packs.List()
	if len(installed) != 1 || installed[0].Name != "team-rules" || installed[0].RuleCount != 3 || installed[0].Version != "local" {
		t.Fatalf("installed packs = %+v, want team-rules with 3 rules", installed)
	}
	packDir := filepath.Join(packs.Dir(), "team-rules")
	for _, want := range []string{"web.yaml", filepath.Join("nested", "go.yml"), "manifest.json"} {
		if _, err := os.Stat(filepath.Join(packDir, want)); err != nil {
			t.Errorf("installed pack is missing %s: %v", want, err)
		}
	}
	for _, unwanted := range []string{"broken.yaml", "notes.yaml", "README.md"} {
		if _, err := os.Stat(filepath.Join(packDir, unwanted)); !os.IsNotExist(err) {
			t.Errorf("%s was installed although it holds no rules", unwanted)
		}
	}
	assertNoStagingLeftovers(t, home)

	// The engine loads what was installed.
	eng, err := engine.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]bool{}
	for _, rule := range eng.Rules {
		loaded[rule.ID] = true
	}
	for _, id := range []string{"TEAM-PACK-ONE", "TEAM-PACK-TWO", "TEAM-PACK-THREE"} {
		if !loaded[id] {
			t.Errorf("engine did not load installed pack rule %s", id)
		}
	}
}

// Reinstalling replaces the pack, so a file deleted from the source stops
// being loaded and the reported count stays true.
func TestRulesInstallReplacesThePreviousCopy(t *testing.T) {
	home := packsHome(t)
	src := teamRulesSource(t)
	if _, err := runRulesCommand(t, runRulesInstall, src); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(src, "nested")); err != nil {
		t.Fatal(err)
	}
	if _, err := runRulesCommand(t, runRulesInstall, src); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(packs.Dir(), "team-rules", "nested", "go.yml")); !os.IsNotExist(err) {
		t.Fatal("a file removed from the source is still installed")
	}
	if installed := packs.List(); len(installed) != 1 || installed[0].RuleCount != 2 {
		t.Fatalf("installed packs after reinstall = %+v, want one pack with 2 rules", installed)
	}
	assertNoStagingLeftovers(t, home)
}

func TestRulesInstallRejectsWhatItCannotInstall(t *testing.T) {
	home := packsHome(t)
	empty := filepath.Join(t.TempDir(), "empty-pack")
	writeTestFile(t, filepath.Join(empty, "notes.yaml"), "title: no rules here\n")
	plainFile := filepath.Join(t.TempDir(), "rules.yaml")
	writeTestFile(t, plainFile, "rules:\n"+packRule("TEAM-PACK-FILE"))

	for _, tc := range []struct {
		arg, want string
	}{
		{"owasp-api-2025", "local directory"},
		{"https://example.com/rules.tar.gz", "not downloaded"},
		{"github.com/example/rules", "not downloaded"},
		{plainFile, "not a directory"},
		{empty, "no rules found"},
	} {
		out, err := runRulesCommand(t, runRulesInstall, tc.arg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("install %q: err = %v, want an error mentioning %q\n%s", tc.arg, err, tc.want, out)
		}
	}
	if installed := packs.List(); len(installed) != 0 {
		t.Fatalf("a failed install left packs behind: %+v", installed)
	}
	assertNoStagingLeftovers(t, home)
}

// A pack name is one directory inside the packs directory; anything else must
// be refused before a path is built from it.
func TestRulesRemoveAndInfoStayInsideThePacksDirectory(t *testing.T) {
	home := packsHome(t)
	sentinels := []string{
		filepath.Join(home, ".aitriage", "telemetry.json"),
		filepath.Join(home, "keep.txt"),
	}
	for _, path := range sentinels {
		writeTestFile(t, path, "keep\n")
	}
	if err := os.MkdirAll(packs.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"..", "../..", ".", "nested/pack", `..\..`, ""} {
		if _, err := runRulesCommand(t, runRulesRemove, name); err == nil {
			t.Errorf("remove %q succeeded", name)
		}
		if _, err := runRulesCommand(t, runRulesInfo, name); err == nil {
			t.Errorf("info %q succeeded", name)
		}
	}
	for _, path := range sentinels {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was removed: %v", path, err)
		}
	}

	if _, err := runRulesCommand(t, runRulesRemove, "never-installed"); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("removing a pack that is not installed: err = %v", err)
	}
}

func TestRulesInfoAndRemoveInstalledPack(t *testing.T) {
	packsHome(t)
	src := teamRulesSource(t)
	if _, err := runRulesCommand(t, runRulesInstall, src); err != nil {
		t.Fatal(err)
	}
	absSrc, _ := filepath.Abs(src)

	out, err := runRulesCommand(t, runRulesInfo, "team-rules")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Rules: 3") || !strings.Contains(out, "Source: "+absSrc) {
		t.Fatalf("info output:\n%s", out)
	}

	if _, err := runRulesCommand(t, runRulesRemove, "team-rules"); err != nil {
		t.Fatal(err)
	}
	if installed := packs.List(); len(installed) != 0 {
		t.Fatalf("pack still listed after remove: %+v", installed)
	}
	if _, err := runRulesCommand(t, runRulesInfo, "team-rules"); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("info after remove: err = %v", err)
	}
}

// The binary reports a refused install once, without the usage text, and
// exits non-zero: scripts must not mistake it for success.
func TestRulesInstallFailureExitCode(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(binaryPath, "rules", "install", "owasp-api-2025")
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("install of an unknown name: err = %v, want a non-zero exit\n%s", err, stderr.String())
	}
	got := stderr.String()
	if strings.Count(got, "is not a directory") != 1 || strings.Contains(got, "Usage:") {
		t.Fatalf("install error output:\n%s", got)
	}
}
