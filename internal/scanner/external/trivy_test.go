package external

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/config"
)

// The fixtures under testdata/trivy are Trivy 0.72.0 JSON reports recorded from
// the bundled scanner image (trimmed: three of the 55 dependency advisories,
// misconfiguration source excerpts removed). The scanned project held a
// Dockerfile without USER, a Terraform file with an SSH security group open to
// 0.0.0.0/0 and a public-read S3 bucket, and a requirements.txt pinning
// pillow 9.0.0 and jinja2 2.11.2.

// fakeTrivy puts a stand-in trivy on PATH that records its arguments and
// replays a recorded report for the requested mode, so RunTrivy is exercised
// end to end without the real scanner or its vulnerability database.
// It returns a function that reads back the arguments of the last run of a
// mode ("fs" or "config").
func fakeTrivy(t *testing.T, reports map[string]string) func(mode string) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in scanner is a POSIX shell script")
	}
	bin := t.TempDir()
	argsDir := t.TempDir()
	reportDir := t.TempDir()
	for mode, fixture := range reports {
		data, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(reportDir, mode+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$FAKE_TRIVY_ARGS/$1.args\"\n" +
		"cat \"$FAKE_TRIVY_REPORTS/$1.json\"\n"
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_TRIVY_ARGS", argsDir)
	t.Setenv("FAKE_TRIVY_REPORTS", reportDir)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TRIVY_IGNOREFILE", "")

	return func(mode string) []string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(argsDir, mode+".args"))
		if err != nil {
			t.Fatalf("trivy %s was not run: %v", mode, err)
		}
		return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	}
}

const (
	configFixture = "testdata/trivy/config-misconfigurations.json"
	fsFixture     = "testdata/trivy/fs-vulnerabilities.json"
)

func findingByRule(findings []UnifiedFinding, ruleID string) (UnifiedFinding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return UnifiedFinding{}, false
}

// argValue returns the value following flag in args, or "" when absent.
func argValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// `trivy config` reports misconfigurations, not vulnerabilities. Decoding only
// the Vulnerabilities array made every IaC scan report zero findings while
// Trivy itself found twelve.
func TestRunTrivyConfigReportsMisconfigurations(t *testing.T) {
	fakeTrivy(t, map[string]string{"config": configFixture})

	findings, err := RunTrivy(context.Background(), t.TempDir(), "config")
	if err != nil {
		t.Fatalf("RunTrivy config: %v", err)
	}
	if len(findings) != 12 {
		t.Fatalf("got %d findings, want the 12 misconfigurations in the report: %+v", len(findings), findings)
	}
	perFile := map[string]int{}
	for _, f := range findings {
		perFile[f.File]++
		if f.Source != "trivy" || f.RuleID == "" || f.Severity == "" || f.Message == "" {
			t.Errorf("incomplete misconfiguration finding: %+v", f)
		}
	}
	if perFile["infra/main.tf"] != 10 || perFile["Dockerfile"] != 2 {
		t.Errorf("findings per file = %v; want 10 in infra/main.tf and 2 in Dockerfile", perFile)
	}

	ssh, ok := findingByRule(findings, "AWS-0107")
	if !ok {
		t.Fatal("open SSH security group (AWS-0107) is missing")
	}
	if ssh.File != "infra/main.tf" || ssh.Line != 10 || ssh.EndLine != 10 {
		t.Errorf("AWS-0107 location = %s:%d-%d; want infra/main.tf:10-10", ssh.File, ssh.Line, ssh.EndLine)
	}
	if ssh.Severity != "HIGH" {
		t.Errorf("AWS-0107 severity = %q; want HIGH", ssh.Severity)
	}
	if !strings.Contains(ssh.Message, "Security group rule allows unrestricted ingress from any IP address.") {
		t.Errorf("AWS-0107 message does not carry the concrete violation: %q", ssh.Message)
	}
	if ssh.Suggestion != "Set a more restrictive CIDR range" {
		t.Errorf("AWS-0107 suggestion = %q; want Trivy's resolution", ssh.Suggestion)
	}
	if ssh.PrimaryURL != "https://avd.aquasec.com/misconfig/aws-0107" {
		t.Errorf("AWS-0107 primary URL = %q", ssh.PrimaryURL)
	}

	publicACL, ok := findingByRule(findings, "AWS-0092")
	if !ok || publicACL.Line != 20 {
		t.Errorf("public-read ACL (AWS-0092) = %+v; want it on infra/main.tf:20", publicACL)
	}

	// A check about something absent has no cause line and stays file-level.
	noUser, ok := findingByRule(findings, "DS-0002")
	if !ok || noUser.File != "Dockerfile" || noUser.Line != 0 {
		t.Errorf("Dockerfile without USER (DS-0002) = %+v; want a file-level Dockerfile finding", noUser)
	}
}

func TestParseTrivyReportKeepsOnlyFailedChecks(t *testing.T) {
	report := `{"Results":[{"Target":"main.tf","Misconfigurations":[
		{"ID":"AWS-0001","Title":"failed","Severity":"HIGH","Status":"FAIL","CauseMetadata":{"StartLine":3,"EndLine":4}},
		{"ID":"AWS-0002","Title":"passed","Severity":"HIGH","Status":"PASS"},
		{"ID":"AWS-0003","Title":"excepted","Severity":"HIGH","Status":"EXCEPTION"},
		{"AVDID":"AVD-AWS-0004","Title":"legacy report without a status","Message":"detail","Severity":"LOW"}
	]}]}`
	findings, err := parseTrivyReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	if !slices.Equal(ids, []string{"AWS-0001", "AVD-AWS-0004"}) {
		t.Fatalf("rule ids = %v; want the failed check and the status-less legacy entry (AVDID as id)", ids)
	}
	if findings[0].Line != 3 || findings[0].EndLine != 4 {
		t.Errorf("line range = %d-%d; want 3-4", findings[0].Line, findings[0].EndLine)
	}
	if findings[1].Message != "legacy report without a status: detail" {
		t.Errorf("message = %q", findings[1].Message)
	}
}

// Dependency findings carry the package, so 50 advisories in one library can
// be read as one upgrade rather than 50 unrelated problems.
func TestRunTrivyFsReportsPackageFields(t *testing.T) {
	args := fakeTrivy(t, map[string]string{"fs": fsFixture})

	findings, err := RunTrivy(context.Background(), t.TempDir(), "fs")
	if err != nil {
		t.Fatalf("RunTrivy fs: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	pillow, ok := findingByRule(findings, "CVE-2022-22817")
	if !ok {
		t.Fatal("CVE-2022-22817 is missing")
	}
	want := UnifiedFinding{
		Source:           "trivy",
		RuleID:           "CVE-2022-22817",
		Severity:         "CRITICAL",
		Message:          "python-pillow: PIL.ImageMath.eval allows evaluation of arbitrary expressions: PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that use the Python exec method. A lambda expression could also be used.",
		File:             "requirements.txt",
		Package:          "pillow",
		InstalledVersion: "9.0.0",
		FixedVersion:     "9.0.1",
		PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2022-22817",
	}
	if pillow != want {
		t.Errorf("finding = %+v\nwant      %+v", pillow, want)
	}

	// Secrets are Gitleaks' job; Trivy's default "vuln,secret" scanned for them
	// only for the results to be discarded.
	if got := argValue(args("fs"), "--scanners"); got != "vuln" {
		t.Errorf("trivy fs --scanners = %q; want vuln", got)
	}
}

// Trivy resolves its default .trivyignore against its working directory. In
// the container the working directory is /project and the repository is
// mounted elsewhere, so a committed .trivyignore was silently not applied.
func TestRunTrivyPassesProjectIgnoreFileToBothModes(t *testing.T) {
	args := fakeTrivy(t, map[string]string{"fs": fsFixture, "config": configFixture})
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".trivyignore"), []byte("CVE-2022-22817\nAWS-0107\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(abs, ".trivyignore")

	for _, mode := range []string{"fs", "config"} {
		if _, err := RunTrivy(context.Background(), root, mode); err != nil {
			t.Fatalf("RunTrivy %s: %v", mode, err)
		}
		if got := argValue(args(mode), "--ignorefile"); got != want {
			t.Errorf("trivy %s --ignorefile = %q; want %q", mode, got, want)
		}
	}
}

func TestTrivyIgnoreFileSelection(t *testing.T) {
	t.Setenv("TRIVY_IGNOREFILE", "")
	write := func(dir, name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("CVE-2022-22817\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	none := t.TempDir()
	if got := trivyIgnoreFile(none); got != "" {
		t.Errorf("project without an ignore file: got %q, want no --ignorefile (Trivy fails on a missing one)", got)
	}

	yamlOnly := t.TempDir()
	write(yamlOnly, ".trivyignore.yaml")
	if got := trivyIgnoreFile(yamlOnly); filepath.Base(got) != ".trivyignore.yaml" || !filepath.IsAbs(got) {
		t.Errorf("YAML-only project: got %q, want the absolute .trivyignore.yaml", got)
	}

	both := t.TempDir()
	write(both, ".trivyignore")
	write(both, ".trivyignore.yaml")
	if got := trivyIgnoreFile(both); filepath.Base(got) != ".trivyignore.yaml" {
		t.Errorf("project with both files: got %q, want .trivyignore.yaml to take precedence", got)
	}

	// A directory with the right name is not an ignore file.
	dirOnly := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirOnly, ".trivyignore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := trivyIgnoreFile(dirOnly); got != "" {
		t.Errorf("directory named .trivyignore: got %q, want none", got)
	}

	// An ignore file chosen through Trivy's own variable is left to Trivy.
	t.Setenv("TRIVY_IGNOREFILE", "/etc/team/trivyignore")
	if got := trivyIgnoreFile(both); got != "" {
		t.Errorf("TRIVY_IGNOREFILE set: got %q, want AITriage not to override it", got)
	}
}

func TestTrivyArgs(t *testing.T) {
	t.Setenv("TRIVY_IGNOREFILE", "")
	root := t.TempDir()
	opts := config.TrivyScannerConfig{IgnoreUnfixed: true, Severity: []string{"critical", " HIGH", "CRITICAL"}}

	fs, err := trivyArgs(root, "fs", opts)
	if err != nil {
		t.Fatal(err)
	}
	if fs[0] != "fs" || fs[len(fs)-1] != root {
		t.Errorf("fs args must start with the mode and end with the target: %v", fs)
	}
	if !slices.Contains(fs, "--ignore-unfixed") {
		t.Errorf("fs args lack --ignore-unfixed: %v", fs)
	}
	if got := argValue(fs, "--severity"); got != "CRITICAL,HIGH" {
		t.Errorf("fs --severity = %q; want CRITICAL,HIGH (normalized, deduplicated)", got)
	}
	if got := argValue(fs, "--scanners"); got != "vuln" {
		t.Errorf("fs --scanners = %q; want vuln", got)
	}

	cfg, err := trivyArgs(root, "config", opts)
	if err != nil {
		t.Fatal(err)
	}
	// `trivy config` rejects both flags ("unknown flag: --ignore-unfixed").
	if slices.Contains(cfg, "--ignore-unfixed") || slices.Contains(cfg, "--scanners") {
		t.Errorf("config args carry fs-only flags: %v", cfg)
	}
	if got := argValue(cfg, "--severity"); got != "CRITICAL,HIGH" {
		t.Errorf("config --severity = %q; want CRITICAL,HIGH", got)
	}

	plain, err := trivyArgs(root, "fs", config.TrivyScannerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(plain, "--ignore-unfixed") || slices.Contains(plain, "--severity") || slices.Contains(plain, "--ignorefile") {
		t.Errorf("default args carry optional flags: %v", plain)
	}

	if _, err := trivyArgs(root, "fs", config.TrivyScannerConfig{Severity: []string{"CRITICAL", "HIHG"}}); err == nil || !strings.Contains(err.Error(), "HIHG") {
		t.Errorf("a misspelled severity must fail the run with its name, got %v", err)
	}
	if _, err := trivyArgs(root, "image", config.TrivyScannerConfig{}); err == nil {
		t.Error("an unsupported scan type must be refused")
	}
}

func TestRunTrivyAppliesProjectConfig(t *testing.T) {
	args := fakeTrivy(t, map[string]string{"fs": fsFixture, "config": configFixture})
	root := t.TempDir()
	cfg := "scanners:\n  trivy:\n    ignore_unfixed: true\n    severity: [CRITICAL, HIGH]\n"
	if err := os.WriteFile(filepath.Join(root, ".aitriage.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"fs", "config"} {
		if _, err := RunTrivy(context.Background(), root, mode); err != nil {
			t.Fatalf("RunTrivy %s: %v", mode, err)
		}
		if got := argValue(args(mode), "--severity"); got != "CRITICAL,HIGH" {
			t.Errorf("trivy %s --severity = %q; want CRITICAL,HIGH", mode, got)
		}
	}
	if !slices.Contains(args("fs"), "--ignore-unfixed") {
		t.Errorf("trivy fs lacks --ignore-unfixed: %v", args("fs"))
	}
	if slices.Contains(args("config"), "--ignore-unfixed") {
		t.Errorf("trivy config must not get --ignore-unfixed: %v", args("config"))
	}
}

func TestRunTrivyReportsTrivysOwnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in scanner is a POSIX shell script")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"printf '2026-01-01T00:00:00Z\\tFATAL\\tFatal error\\tunknown flag: --ignore-unfixed\\n' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := RunTrivy(context.Background(), t.TempDir(), "config")
	if err == nil {
		t.Fatal("a failed Trivy run must be an error")
	}
	if !strings.Contains(err.Error(), "unknown flag: --ignore-unfixed") || strings.Contains(err.Error(), "FATAL") {
		t.Errorf("error = %q; want Trivy's reason without the log columns", err)
	}
}
