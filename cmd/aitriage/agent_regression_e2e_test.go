package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/dodobrands/aitriage/internal/engine/suppression"
)

// TestE2E_AgentRegressionPilotOrg is the end-to-end regression test for the
// scanner scope, project decision and LLM-stage fixes. It runs the real scanner
// bundle over testdata/regression/pilot-org the way a CI job runs the image,
// and needs no LLM.
//
// The agent is pointed at an LLM endpoint that refuses connections. A provider
// failure no longer destroys the run: every artifact is still written, every
// finding the model would have classified is marked triage-failed, the gate
// blocks with triage_incomplete and the agent exits 2. Everything that does
// not depend on the model is then asserted from the artifacts.
//
// The container is started the way a CI job starts it: the project is mounted
// at /github/workspace, the container working directory is /project, the
// project path is passed positionally, `--runtime native` runs with
// AITRIAGE_RUNTIME=container, the gate flags are
// `--no-chat --fail-on confirmed --health-profile baseline`, and every
// `--*-out` artifact goes to a mounted reports directory.
//
// What each part of the fixture guards:
//
//	.aitriage.yaml ignore.paths             no finding inside wp-content/plugins/akismet/
//	.aitriage.yaml ignore.rules             no ENTR-SLOP-01, port-53, nginx_missing_server_tokens_off, B404 (bandit: qualifier; B404 fires on this fixture)
//	.trivyignore                            CVE-2022-22817 is not reported
//	docker-compose.yml (services app, db)   no network findings without --probe-compose
//	infra/main.tf, Dockerfile without USER  trivy config reports misconfigurations
//	docker/apache-hardening.conf,
//	deploy/supervisord.conf                 no nginx_* checks on configs that are not nginx
//	main.py `except Exception: pass`        FAST-LAZY-EXC is LOW
//	core/fns.py:3, main.py shell=True       one finding per line once detectors merge
//	requirements.txt pillow==9.0.0          Pillow CVEs grouped by package in the summary
//
// A second scenario records two decisions with `aitriage ignore add`, run by
// the binary under test: an accepted risk for CVE-2023-50447 and a false
// positive for SECRET-ASSIGN in core/fns.py, both without --evidence. Neither
// finding may then be counted.
//
// Running it needs Docker and network access: Semgrep fetches its registry
// rules on each run, and Trivy its databases, which are kept in a named volume
// mounted at /root/.cache so they download once.
//
//	make e2e-regression    # aitriage built from this checkout, mounted into E2E_IMAGE
//	AITRIAGE_IMAGE=aitriage:publish-candidate go test ./cmd/aitriage -run '^TestE2E_AgentRegressionPilotOrg$' -count=1 -v
//
// AITRIAGE_IMAGE selects the scanner image; without it the test is skipped.
// AITRIAGE_E2E_BINARY is a linux aitriage binary (`make build-linux`) that is
// bind-mounted over /usr/local/bin/aitriage; without it the image's own binary
// is the one under test. AITRIAGE_E2E_CACHE_VOLUME names the volume mounted at
// /root/.cache (default aitriage-e2e-scanner-cache). AITRIAGE_E2E_ARTIFACTS_DIR,
// when set, keeps each scenario's artifacts and logs in <dir>/<scenario>.
//
// The checks under base/pending depend on work that has not landed yet: merged
// detectors, stable finding ids, project-relative paths and per-package CVE
// grouping. To leave them out, add -skip 'TestE2E_AgentRegressionPilotOrg/base/pending'.
func TestE2E_AgentRegressionPilotOrg(t *testing.T) {
	if testing.Short() || !dockerImageAvailable(t) {
		t.Skip("requires Docker and the resolved AITriage runtime image")
	}
	h := newRegressionHarness(t)

	base := h.runScenario(t, "base", nil)
	decided := h.runScenario(t, "suppressions", func(t *testing.T, project string) {
		h.ignoreAdd(t, project, regressionAcceptedCVE, "--source", "trivy", "--reason", "accepted-risk",
			"--note", "regression fixture: the Pillow upgrade is scheduled")
		h.ignoreAdd(t, project, regressionDismissedRule, "--file", regressionDismissedFile, "--reason", "false-positive",
			"--note", "regression fixture: placeholder credential")
	})

	t.Run("base", func(t *testing.T) {
		t.Run("landed", func(t *testing.T) { runRegressionChecks(t, base, landedRegressionChecks()) })
		t.Run("pending", func(t *testing.T) { runRegressionChecks(t, base, pendingRegressionChecks()) })
	})
	t.Run("suppressions", func(t *testing.T) { checkDecisionScenario(t, base, decided) })
}

const (
	regressionWorkspace = "/github/workspace"
	regressionReports   = "/reports"
	// Nothing listens on regressionDeadLLM inside the container, so every
	// provider call is refused and, after the client's bounded retries, the LLM
	// stage gives up within seconds.
	regressionDeadLLM     = "http://127.0.0.1:9/v1"
	regressionCacheVolume = "aitriage-e2e-scanner-cache"
	regressionIgnoredDir  = "wp-content/plugins/akismet/"

	regressionAcceptedCVE   = "CVE-2023-50447"
	regressionDismissedRule = "SECRET-ASSIGN"
	regressionDismissedFile = "core/fns.py"

	dispositionFalsePositive = "False Positive"
	sourceSuppressed         = "suppressed"
	sourceTriageFailed       = "triage-failed"
)

var regressionFixtureDir = filepath.Join("..", "..", "testdata", "regression", "pilot-org")

// regressionArtifacts lists every agent output flag and the file it writes.
var regressionArtifacts = []struct{ flag, file string }{
	{"--triage-out", "triage-findings.json"},
	{"--summary-out", "summary.md"},
	{"--report-out", "report.md"},
	{"--fixspec-out", "fixspec.md"},
	{"--manifest-out", "manifest.json"},
	{"--sarif-out", "aitriage.sarif"},
}

// ── Harness ──────────────────────────────────────────────────────────────────

type regressionHarness struct {
	image  string
	binary string // linux aitriage mounted over the image's copy; "" keeps the image's
	cache  string // named volume mounted at /root/.cache
	keep   string // AITRIAGE_E2E_ARTIFACTS_DIR
	runs   int
}

type regressionProcess struct {
	stdout, stderr []byte
	code           int
	elapsed        time.Duration
}

func newRegressionHarness(t *testing.T) *regressionHarness {
	t.Helper()
	h := &regressionHarness{
		image: strings.TrimSpace(os.Getenv("AITRIAGE_IMAGE")),
		cache: strings.TrimSpace(os.Getenv("AITRIAGE_E2E_CACHE_VOLUME")),
	}
	if h.cache == "" {
		h.cache = regressionCacheVolume
	}
	if keep := strings.TrimSpace(os.Getenv("AITRIAGE_E2E_ARTIFACTS_DIR")); keep != "" {
		abs, err := filepath.Abs(keep)
		if err != nil {
			t.Fatal(err)
		}
		h.keep = abs
	}
	mode := "the image's own binary"
	if bin := strings.TrimSpace(os.Getenv("AITRIAGE_E2E_BINARY")); bin != "" {
		abs, err := filepath.Abs(bin)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			t.Fatalf("AITRIAGE_E2E_BINARY: %v (build it with `make build-linux`)", err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("AITRIAGE_E2E_BINARY=%s is not a regular file", abs)
		}
		h.binary = abs
		mode = "local binary " + abs
	}
	version := h.docker(t, 2*time.Minute, "/project", nil, nil, "version")
	if version.code != 0 {
		t.Fatalf("the binary under test does not run in %s (%s): exit %d\n%s%s",
			h.image, mode, version.code, version.stdout, version.stderr)
	}
	t.Logf("binary under test: %s (%s, image %s, cache volume %s)",
		strings.TrimSpace(string(version.stdout)), mode, h.image, h.cache)
	return h
}

// docker runs one command in the scanner image, with the binary under test in
// place, and returns its exit status. A failure of docker itself, as opposed
// to the command's own exit status, ends the test.
func (h *regressionHarness) docker(t *testing.T, limit time.Duration, workdir string, mounts, env []string, argv ...string) regressionProcess {
	t.Helper()
	h.runs++
	name := fmt.Sprintf("aitriage-e2e-regression-%d-%d", os.Getpid(), h.runs)
	args := []string{"run", "--rm", "--name", name, "-w", workdir}
	if h.binary != "" {
		args = append(args, "-v", h.binary+":/usr/local/bin/aitriage:ro")
	}
	for _, mount := range mounts {
		args = append(args, "-v", mount)
	}
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	args = append(args, h.image)
	args = append(args, argv...)

	ctx, cancel := context.WithTimeout(context.Background(), regressionTimeout(t, limit))
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	p := regressionProcess{stdout: stdout.Bytes(), stderr: stderr.Bytes(), elapsed: time.Since(start)}
	if ctx.Err() != nil {
		// Killing the docker client does not stop the container.
		_ = exec.Command("docker", "rm", "-f", name).Run()
		t.Fatalf("aitriage %s timed out after %s\n%s", argv[0], p.elapsed.Round(time.Second), regressionTail(p.stderr))
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		p.code = exitErr.ExitCode()
	default:
		t.Fatalf("docker run (aitriage %s): %v", argv[0], err)
	}
	// 125-127 are docker's own failures (daemon, mount, entrypoint), not an
	// aitriage exit status.
	if p.code >= 125 {
		t.Fatalf("docker could not run aitriage %s (status %d):\n%s", argv[0], p.code, regressionTail(p.stderr))
	}
	return p
}

// regressionTimeout keeps a container run inside the test deadline, so a hung
// run is stopped and its container removed before `go test` panics.
func regressionTimeout(t *testing.T, limit time.Duration) time.Duration {
	if deadline, ok := t.Deadline(); ok {
		if left := time.Until(deadline) - 30*time.Second; left < limit {
			return max(left, 10*time.Second)
		}
	}
	return limit
}

// reclaim gives the files the container wrote in bind mounts back to the test
// user. CI runs the image as root, so on a Linux host the artifacts are
// root-owned 0600 files the test could neither read nor remove. Docker Desktop
// maps ownership by itself.
func (h *regressionHarness) reclaim(t *testing.T, dirs ...string) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		return
	}
	args := []string{"run", "--rm", "--entrypoint", "chown"}
	targets := make([]string, 0, len(dirs))
	for i, dir := range dirs {
		target := fmt.Sprintf("/reclaim/%d", i)
		args = append(args, "-v", dir+":"+target)
		targets = append(targets, target)
	}
	args = append(args, h.image, "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()))
	args = append(args, targets...)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Logf("could not reclaim %v: %v\n%s", dirs, err, out)
	}
}

// ignoreAdd records a decision the way a person does it from a terminal:
// `aitriage ignore add`, run by the binary under test in the project.
func (h *regressionHarness) ignoreAdd(t *testing.T, project, rule string, flags ...string) {
	t.Helper()
	argv := append([]string{"ignore", "add", rule, regressionWorkspace}, flags...)
	p := h.docker(t, 2*time.Minute, regressionWorkspace, []string{project + ":" + regressionWorkspace}, nil, argv...)
	h.reclaim(t, project)
	if p.code != 0 {
		t.Fatalf("aitriage ignore add %s: exit %d\n%s%s", rule, p.code, p.stdout, p.stderr)
	}
}

// runScenario copies the fixture, lets prepare change the copy, runs the agent
// in the CI layout and loads every artifact.
func (h *regressionHarness) runScenario(t *testing.T, name string, prepare func(t *testing.T, project string)) *regressionRun {
	t.Helper()
	root := t.TempDir()
	r := &regressionRun{name: name, project: filepath.Join(root, "project"), reports: filepath.Join(root, "reports")}
	if h.keep != "" {
		r.reports = filepath.Join(h.keep, name)
		if err := os.RemoveAll(r.reports); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(r.reports, 0o755); err != nil {
		t.Fatal(err)
	}
	// Registered after TempDir, so it runs before TempDir removes the files.
	t.Cleanup(func() { h.reclaim(t, r.project, r.reports) })
	if err := os.CopyFS(r.project, os.DirFS(regressionFixtureDir)); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	if prepare != nil {
		prepare(t, r.project)
	}

	argv := []string{"agent", regressionWorkspace, "--runtime", "native", "--no-chat",
		"--fail-on", "confirmed", "--health-profile", "baseline"}
	for _, artifact := range regressionArtifacts {
		argv = append(argv, artifact.flag, regressionReports+"/"+artifact.file)
	}
	mounts := []string{
		r.project + ":" + regressionWorkspace,
		r.reports + ":" + regressionReports,
		h.cache + ":/root/.cache",
	}
	env := []string{
		"AITRIAGE_RUNTIME=container",
		"AITRIAGE_LLM_PROVIDER=openai",
		"AITRIAGE_LLM_BASE_URL=" + regressionDeadLLM,
		"AITRIAGE_LLM_API_KEY=e2e-placeholder-not-a-key",
	}
	r.proc = h.docker(t, 15*time.Minute, "/project", mounts, env, argv...)
	h.reclaim(t, r.project, r.reports)
	if h.keep != "" {
		for file, data := range map[string][]byte{"agent.stdout.log": r.proc.stdout, "agent.stderr.log": r.proc.stderr} {
			if err := os.WriteFile(filepath.Join(r.reports, file), data, 0o644); err != nil {
				t.Logf("keep %s: %v", file, err)
			}
		}
	}
	r.load()
	t.Logf("scenario %s: exit %d in %s; %s", name, r.proc.code, r.proc.elapsed.Round(time.Second), r.describe())
	return r
}

// ── Artifacts ────────────────────────────────────────────────────────────────

type regressionRun struct {
	name    string
	project string // the scenario project, mounted at /github/workspace
	reports string // mounted at /reports
	proc    regressionProcess

	files    map[string][]byte // artifacts that were written, by file name
	loadErrs []string          // artifacts that were missing, empty or unreadable
	triage   *regressionTriage
	manifest *regressionManifest
	sarif    *regressionSARIF
}

type regressionTriage struct {
	TriageStatus        string `json:"triage_status"`
	TriageFailureReason string `json:"triage_failure_reason"`
	TotalFindings       int    `json:"total_findings"`
	HealthCheck         struct {
		Breakdown struct {
			ActiveFindings      int `json:"active_findings"`
			NeedsReviewFindings int `json:"needs_review_findings"`
			IgnoredFindings     int `json:"ignored_findings"`
			// Pointers tell a missing counter from a zero one.
			UnclassifiedFindings *int `json:"unclassified_findings"`
			TriageFailedFindings *int `json:"triage_failed_findings"`
		} `json:"breakdown"`
		Verdict struct {
			Passed          bool   `json:"passed"`
			Status          string `json:"status"`
			BlockingReasons []struct {
				Code  string `json:"code"`
				Count int    `json:"count"`
			} `json:"blocking_reasons"`
		} `json:"verdict"`
	} `json:"health_check"`
	Classification struct {
		BySource map[string]int `json:"by_source"`
	} `json:"classification"`
	Suppressions struct {
		Total    int            `json:"total"`
		ByReason map[string]int `json:"by_reason"`
	} `json:"suppressions"`
	Findings []regressionFinding `json:"findings"`
}

type regressionFinding struct {
	// StableID is read wherever the stable finding id ends up: on the entry,
	// on the finding or on its disposition.
	StableID string `json:"stable_id"`
	Finding  struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Source   string `json:"source"`
		Severity string `json:"severity"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		StableID string `json:"stable_id"`
		Origins  []struct {
			Type   string `json:"type"`
			Source string `json:"source"`
			RuleID string `json:"rule_id"`
		} `json:"origins"`
	} `json:"finding"`
	Disposition struct {
		Disposition       string `json:"disposition"`
		DispositionSource string `json:"disposition_source"`
		StableID          string `json:"stable_id"`
	} `json:"disposition"`
}

type regressionScanner struct {
	Scanner  string `json:"scanner"`
	Status   string `json:"status"`
	Version  string `json:"version"`
	Findings int    `json:"findings"`
	Error    string `json:"error"`
}

type regressionManifest struct {
	ScannerCoverage string              `json:"scanner_coverage"`
	Scanners        []regressionScanner `json:"scanners"`
}

type regressionSARIF struct {
	Runs []struct {
		Results []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func (r *regressionRun) load() {
	r.files = map[string][]byte{}
	for _, artifact := range regressionArtifacts {
		data, err := os.ReadFile(filepath.Join(r.reports, artifact.file))
		switch {
		case err != nil:
			r.loadErrs = append(r.loadErrs, err.Error())
		case len(bytes.TrimSpace(data)) == 0:
			r.loadErrs = append(r.loadErrs, artifact.file+" is empty")
		default:
			r.files[artifact.file] = data
		}
	}
	r.triage = decodeRegressionArtifact[regressionTriage](r, "triage-findings.json")
	r.manifest = decodeRegressionArtifact[regressionManifest](r, "manifest.json")
	r.sarif = decodeRegressionArtifact[regressionSARIF](r, "aitriage.sarif")
}

func decodeRegressionArtifact[T any](r *regressionRun, file string) *T {
	data, ok := r.files[file]
	if !ok {
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		r.loadErrs = append(r.loadErrs, fmt.Sprintf("%s: %v", file, err))
		return nil
	}
	return &v
}

func (r *regressionRun) describe() string {
	if r.triage == nil {
		return "no triage artifact: " + strings.Join(r.loadErrs, "; ")
	}
	out := fmt.Sprintf("triage_status=%s findings=%d by_source=%v suppressions=%d gate=%s",
		r.triage.TriageStatus, len(r.triage.Findings), r.triage.Classification.BySource,
		r.triage.Suppressions.Total, r.triage.HealthCheck.Verdict.Status)
	if r.manifest != nil {
		var scanners []string
		for _, s := range r.manifest.Scanners {
			scanners = append(scanners, fmt.Sprintf("%s=%s(%d)", s.Scanner, s.Status, s.Findings))
		}
		out += " scanners: " + strings.Join(scanners, " ")
	}
	return out
}

func (r *regressionRun) requireTriage(t *testing.T) *regressionTriage {
	t.Helper()
	if r.triage == nil {
		t.Fatalf("%s: triage-findings.json is not available: %s", r.name, strings.Join(r.loadErrs, "; "))
	}
	return r.triage
}

func (r *regressionRun) requireScanner(t *testing.T, name string) regressionScanner {
	t.Helper()
	if r.manifest == nil {
		t.Fatalf("%s: manifest.json is not available: %s", r.name, strings.Join(r.loadErrs, "; "))
	}
	for _, s := range r.manifest.Scanners {
		if s.Scanner == name {
			return s
		}
	}
	t.Fatalf("%s: manifest has no %s execution: %s", r.name, name, r.describe())
	return regressionScanner{}
}

func (r *regressionRun) requireFile(t *testing.T, file string) []byte {
	t.Helper()
	data, ok := r.files[file]
	if !ok {
		t.Fatalf("%s: %s is not available: %s", r.name, file, strings.Join(r.loadErrs, "; "))
	}
	return data
}

// sarifLocations lists every SARIF result as rule and location URI.
func (r *regressionRun) sarifLocations(t *testing.T) [][2]string {
	t.Helper()
	if r.sarif == nil {
		t.Fatalf("%s: aitriage.sarif is not available: %s", r.name, strings.Join(r.loadErrs, "; "))
	}
	var out [][2]string
	for _, run := range r.sarif.Runs {
		for _, result := range run.Results {
			if len(result.Locations) == 0 {
				out = append(out, [2]string{result.RuleID, ""})
			}
			for _, location := range result.Locations {
				out = append(out, [2]string{result.RuleID, location.PhysicalLocation.ArtifactLocation.URI})
			}
		}
	}
	return out
}

func (tr *regressionTriage) where(keep func(regressionFinding) bool) []regressionFinding {
	var out []regressionFinding
	for _, f := range tr.Findings {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

// rel is the finding's path relative to the project, whatever form the
// scanner reported. Only the project_relative_paths check looks at the form.
func (f regressionFinding) rel() string {
	path := strings.TrimSpace(strings.ReplaceAll(f.Finding.File, `\`, "/"))
	path = strings.TrimPrefix(path, regressionWorkspace+"/")
	return strings.TrimPrefix(path, "./")
}

// hasRule reports whether the finding, or any detector merged into it, is rule.
func (f regressionFinding) hasRule(rule string) bool {
	if strings.EqualFold(f.Finding.ID, rule) {
		return true
	}
	for _, origin := range f.Finding.Origins {
		if strings.EqualFold(origin.RuleID, rule) {
			return true
		}
	}
	return false
}

// dismissed reports whether a project decision took the finding out of the
// count: a False Positive disposition from the decision, never from a model.
func (f regressionFinding) dismissed() bool {
	return f.Disposition.Disposition == dispositionFalsePositive && f.Disposition.DispositionSource == sourceSuppressed
}

func (f regressionFinding) stableID() string {
	for _, id := range []string{f.StableID, f.Finding.StableID, f.Disposition.StableID} {
		if strings.TrimSpace(id) != "" {
			return id
		}
	}
	return ""
}

func (f regressionFinding) String() string {
	location := f.Finding.File
	if location == "" {
		location = "(project)"
	}
	if f.Finding.Line > 0 {
		location += fmt.Sprintf(":%d", f.Finding.Line)
	}
	return fmt.Sprintf("%s [%s %s %s, %s]", f.Finding.ID, f.Finding.Source, f.Finding.Severity, location, f.Disposition.DispositionSource)
}

func describeRegressionFindings(findings []regressionFinding) string {
	const limit = 12
	parts := make([]string, 0, limit+1)
	for i, f := range findings {
		if i == limit {
			parts = append(parts, fmt.Sprintf("… %d more", len(findings)-limit))
			break
		}
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("%d finding(s): %s", len(findings), strings.Join(parts, "; "))
}

// regressionTail keeps failure messages readable: the agent prints its whole
// report to stderr.
func regressionTail(output []byte) string {
	const limit = 4000
	if len(output) <= limit {
		return string(output)
	}
	start := len(output) - limit
	for start < len(output) && !utf8.RuneStart(output[start]) {
		start++
	}
	return "…" + string(output[start:])
}

// fixtureLine returns the 1-based line of the fixture file that contains needle.
func fixtureLine(t *testing.T, file, needle string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(regressionFixtureDir, filepath.FromSlash(file)))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("fixture %s has no line containing %q", file, needle)
	return 0
}

// ── Checks ───────────────────────────────────────────────────────────────────

type regressionCheck struct {
	name string
	run  func(t *testing.T, r *regressionRun)
}

func runRegressionChecks(t *testing.T, r *regressionRun, checks []regressionCheck) {
	t.Helper()
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) { check.run(t, r) })
	}
}

// cobraUsage matches the usage text cobra prints after a failing command.
var cobraUsage = regexp.MustCompile(`(?m)^Usage:\s*$|aitriage agent \[path\] \[flags\]`)

var semverPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

// pillowGrouping matches the per-package summary line, e.g.
// `pillow 9.0.0 → 13.0.0: 6 CRITICAL, 32 HIGH`.
var pillowGrouping = regexp.MustCompile(`pillow 9\.0\.0\s*(→|->)`)

func checkArtifactsWritten(t *testing.T, r *regressionRun) {
	if len(r.loadErrs) > 0 {
		t.Errorf("artifacts not written or unreadable: %s", strings.Join(r.loadErrs, "; "))
	}
}

func checkExitStatus2(t *testing.T, r *regressionRun) {
	if r.proc.code != exitAuditIncomplete {
		t.Errorf("exit status = %d, want %d (audit incomplete)\n%s", r.proc.code, exitAuditIncomplete, regressionTail(r.proc.stderr))
	}
}

func checkTriageStatusFailed(t *testing.T, r *regressionRun) {
	tr := r.requireTriage(t)
	if tr.TriageStatus != "failed" {
		t.Errorf("triage_status = %q, want failed (reason %q)", tr.TriageStatus, tr.TriageFailureReason)
	}
}

// landedRegressionChecks cover behaviour this branch already implements.
func landedRegressionChecks() []regressionCheck {
	return []regressionCheck{
		{"artifacts_written", checkArtifactsWritten},
		{"exit_status_2", checkExitStatus2},
		{"triage_status_failed", checkTriageStatusFailed},
		{"llm_bound_findings_triage_failed", func(t *testing.T, r *regressionRun) {
			tr := r.requireTriage(t)
			// Sources that are decided without the model by design.
			withoutModel := map[string]bool{sourceSuppressed: true, "network-probe": true, "deterministic": true}
			failed := 0
			var other []regressionFinding
			for _, f := range tr.Findings {
				switch source := f.Disposition.DispositionSource; {
				case source == sourceTriageFailed:
					failed++
				case !withoutModel[source]:
					other = append(other, f)
				}
			}
			if failed == 0 || len(other) > 0 {
				t.Errorf("every model-bound finding must be triage-failed: %d are; not: %s (by_source %v)",
					failed, describeRegressionFindings(other), tr.Classification.BySource)
			}
		}},
		{"gate_blocks_triage_incomplete", func(t *testing.T, r *regressionRun) {
			verdict := r.requireTriage(t).HealthCheck.Verdict
			var codes []string
			blocked := false
			for _, reason := range verdict.BlockingReasons {
				codes = append(codes, reason.Code)
				blocked = blocked || reason.Code == "triage_incomplete"
			}
			if verdict.Passed || !blocked {
				t.Errorf("gate passed=%v status=%q blocking=%v, want failed with triage_incomplete", verdict.Passed, verdict.Status, codes)
			}
		}},
		{"no_usage_text", func(t *testing.T, r *regressionRun) {
			for stream, output := range map[string][]byte{"stderr": r.proc.stderr, "stdout": r.proc.stdout} {
				if match := cobraUsage.Find(output); match != nil {
					t.Errorf("%s contains cobra usage text %q after a runtime failure", stream, match)
				}
			}
		}},
		{"ignore_paths_akismet", func(t *testing.T, r *regressionRun) {
			inside := r.requireTriage(t).where(func(f regressionFinding) bool {
				return strings.Contains(strings.ReplaceAll(f.Finding.File, `\`, "/"), regressionIgnoredDir)
			})
			if len(inside) > 0 {
				t.Errorf("ignore.paths %s still reported: %s", regressionIgnoredDir, describeRegressionFindings(inside))
			}
			for _, location := range r.sarifLocations(t) {
				if strings.Contains(location[1], regressionIgnoredDir) {
					t.Errorf("SARIF result %s at %s is inside ignore.paths", location[0], location[1])
				}
			}
		}},
		{"ignore_rules", func(t *testing.T, r *regressionRun) {
			for _, rule := range []string{"ENTR-SLOP-01", "port-53", "nginx_missing_server_tokens_off", "B404"} {
				t.Run(rule, func(t *testing.T) {
					reported := r.requireTriage(t).where(func(f regressionFinding) bool { return f.hasRule(rule) })
					if len(reported) > 0 {
						t.Errorf("ignore.rules %s still reported: %s", rule, describeRegressionFindings(reported))
					}
					for _, location := range r.sarifLocations(t) {
						if strings.EqualFold(location[0], rule) {
							t.Errorf("ignore.rules %s still in SARIF at %s", rule, location[1])
						}
					}
				})
			}
		}},
		{"no_network_findings", func(t *testing.T, r *regressionRun) {
			network := r.requireTriage(t).where(func(f regressionFinding) bool {
				return strings.EqualFold(f.Finding.Type, "network") || strings.HasPrefix(f.Finding.ID, "port-") ||
					f.Disposition.DispositionSource == "network-probe"
			})
			if len(network) > 0 {
				t.Errorf("network findings without --probe-compose: %s", describeRegressionFindings(network))
			}
		}},
		{"trivyignore_CVE-2022-22817", func(t *testing.T, r *regressionRun) {
			tr := r.requireTriage(t)
			if ignored := tr.where(func(f regressionFinding) bool { return f.hasRule("CVE-2022-22817") }); len(ignored) > 0 {
				t.Errorf(".trivyignore entry still reported: %s", describeRegressionFindings(ignored))
			}
			// Not vacuous: Trivy did scan requirements.txt with a database.
			pillow := tr.where(func(f regressionFinding) bool {
				return f.Finding.Source == "trivy" && f.rel() == "requirements.txt"
			})
			if len(pillow) == 0 {
				t.Errorf("no Trivy dependency findings for requirements.txt at all; the .trivyignore check proves nothing")
			}
		}},
		{"trivy_config_findings", func(t *testing.T, r *regressionRun) {
			s := r.requireScanner(t, "trivy_config")
			if s.Status != "completed" || s.Findings <= 0 {
				t.Errorf("manifest trivy_config status=%q findings=%d error=%q, want completed with findings > 0", s.Status, s.Findings, s.Error)
			}
		}},
		{"no_nginx_checks_on_apache_or_supervisord", func(t *testing.T, r *regressionRun) {
			nginx := r.requireTriage(t).where(func(f regressionFinding) bool {
				return strings.HasPrefix(strings.ToLower(f.Finding.ID), "nginx_")
			})
			for _, f := range nginx {
				switch f.rel() {
				case "docker/apache-hardening.conf", "deploy/supervisord.conf":
					t.Errorf("nginx check on a config that is not nginx: %s", f)
				default:
					t.Logf("nginx finding elsewhere: %s", f)
				}
			}
		}},
		{"fast_lazy_exc_low", func(t *testing.T, r *regressionRun) {
			lazy := r.requireTriage(t).where(func(f regressionFinding) bool { return f.hasRule("FAST-LAZY-EXC") })
			if len(lazy) == 0 {
				t.Fatalf("no FAST-LAZY-EXC finding for main.py `except Exception: pass`")
			}
			for _, f := range lazy {
				if !strings.EqualFold(f.Finding.Severity, "LOW") {
					t.Errorf("FAST-LAZY-EXC severity = %q, want LOW: %s", f.Finding.Severity, f)
				}
			}
		}},
		{"manifest_deploy_nfr_counts", func(t *testing.T, r *regressionRun) {
			for _, name := range []string{"deploy", "nfr"} {
				if s := r.requireScanner(t, name); s.Status != "completed" || s.Findings <= 0 {
					t.Errorf("manifest %s status=%q findings=%d, want completed with findings > 0", name, s.Status, s.Findings)
				}
			}
		}},
		{"semgrep_version_not_update_notice", func(t *testing.T, r *regressionRun) {
			s := r.requireScanner(t, "semgrep")
			version := strings.ToLower(s.Version)
			if s.Status != "completed" || strings.Contains(version, "new version") ||
				strings.Contains(version, "upgrade") || !semverPattern.MatchString(version) {
				t.Errorf("manifest semgrep status=%q version=%q, want completed with a plain version", s.Status, s.Version)
			}
		}},
		{"breakdown_unclassified_counters", func(t *testing.T, r *regressionRun) {
			b := r.requireTriage(t).HealthCheck.Breakdown
			switch {
			case b.UnclassifiedFindings == nil || b.TriageFailedFindings == nil:
				t.Errorf("health_check.breakdown lacks unclassified_findings (%v) or triage_failed_findings (%v)",
					b.UnclassifiedFindings != nil, b.TriageFailedFindings != nil)
			case *b.UnclassifiedFindings <= 0 || *b.TriageFailedFindings <= 0 || *b.UnclassifiedFindings > b.NeedsReviewFindings:
				t.Errorf("breakdown unclassified=%d triage_failed=%d needs_review=%d, want 0 < counters <= needs_review",
					*b.UnclassifiedFindings, *b.TriageFailedFindings, b.NeedsReviewFindings)
			}
		}},
	}
}

// pendingRegressionChecks cover work landing in parallel: semantic merging of
// detectors, stable finding ids, project-relative paths and per-package CVE
// grouping in the summary header. They are expected to fail until it lands.
func pendingRegressionChecks() []regressionCheck {
	oneFindingAt := func(file, needle string) func(*testing.T, *regressionRun) {
		return func(t *testing.T, r *regressionRun) {
			line := fixtureLine(t, file, needle)
			at := r.requireTriage(t).where(func(f regressionFinding) bool { return f.rel() == file && f.Finding.Line == line })
			if len(at) != 1 {
				t.Errorf("%s:%d (%s) has %s; want exactly one", file, line, needle, describeRegressionFindings(at))
			}
		}
	}
	return []regressionCheck{
		{"one_finding_core_fns_py_3", oneFindingAt("core/fns.py", "CLIENT_SECRET =")},
		{"one_finding_main_py_shell_true_line", oneFindingAt("main.py", "shell=True")},
		{"findings_carry_stable_id", func(t *testing.T, r *regressionRun) {
			tr := r.requireTriage(t)
			missing := tr.where(func(f regressionFinding) bool { return f.stableID() == "" })
			if len(tr.Findings) == 0 || len(missing) > 0 {
				t.Errorf("%d of %d findings have no stable_id: %s", len(missing), len(tr.Findings), describeRegressionFindings(missing))
			}
		}},
		{"project_relative_paths", func(t *testing.T, r *regressionRun) {
			bad := map[string]bool{}
			for _, f := range r.requireTriage(t).Findings {
				if f.Finding.File != "" && !isProjectRelative(f.Finding.File) {
					bad["triage-findings.json: "+f.Finding.File] = true
				}
			}
			for _, location := range r.sarifLocations(t) {
				if location[1] != "" && !isProjectRelative(location[1]) {
					bad["aitriage.sarif: "+location[1]] = true
				}
			}
			for _, file := range []string{"summary.md", "report.md", "fixspec.md"} {
				if n := bytes.Count(r.requireFile(t, file), []byte(regressionWorkspace+"/")); n > 0 {
					bad[fmt.Sprintf("%s: %d path(s) under %s/", file, n, regressionWorkspace)] = true
				}
			}
			if len(bad) > 0 {
				var list []string
				for entry := range bad {
					list = append(list, entry)
				}
				sort.Strings(list)
				t.Errorf("paths not relative to the project:\n  %s", strings.Join(list, "\n  "))
			}
		}},
		{"summary_groups_pillow_by_package", func(t *testing.T, r *regressionRun) {
			summary := r.requireFile(t, "summary.md")
			if !pillowGrouping.Match(summary) {
				t.Errorf("summary.md has no per-package line `pillow 9.0.0 → …`; Pillow lines found: %q", pillowLines(summary))
			}
		}},
	}
}

func isProjectRelative(path string) bool {
	path = strings.ReplaceAll(strings.TrimSpace(path), `\`, "/")
	return !strings.HasPrefix(path, "/") && !strings.Contains(path, ":/") &&
		path != ".." && !strings.HasPrefix(path, "../") && !strings.Contains(path, regressionWorkspace)
}

func pillowLines(summary []byte) []string {
	var out []string
	for _, line := range strings.Split(string(summary), "\n") {
		if strings.Contains(strings.ToLower(line), "pillow") {
			if runes := []rune(strings.TrimSpace(line)); len(runes) > 120 {
				line = string(runes[:120]) + "…"
			}
			out = append(out, strings.TrimSpace(line))
			if len(out) == 3 {
				break
			}
		}
	}
	return out
}

// checkDecisionScenario checks the run with the two recorded decisions. The
// base run serves as the control: there, both findings are open.
func checkDecisionScenario(t *testing.T, base, decided *regressionRun) {
	t.Run("decisions_recorded", func(t *testing.T) {
		store, err := suppression.Load(decided.project)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]suppression.Entry{
			regressionAcceptedCVE:   {Source: "trivy", Reason: suppression.ReasonAcceptedRisk},
			regressionDismissedRule: {Source: "core", File: regressionDismissedFile, Reason: suppression.ReasonFalsePositive},
		}
		for _, entry := range store.List() {
			if w, ok := want[entry.RuleID]; ok && entry.Source == w.Source && entry.File == w.File && entry.Reason == w.Reason {
				delete(want, entry.RuleID)
			}
		}
		if len(want) > 0 {
			t.Errorf("%s lacks decisions for %v: %+v", suppression.File, want, store.List())
		}
	})
	runRegressionChecks(t, decided, []regressionCheck{
		{"artifacts_written", checkArtifactsWritten},
		{"exit_status_2", checkExitStatus2},
		{"triage_status_failed", checkTriageStatusFailed},
	})
	t.Run("accepted_cve_not_counted", func(t *testing.T) {
		checkDecisionApplied(t, base, decided, regressionAcceptedCVE, suppression.ReasonAcceptedRisk,
			func(f regressionFinding) bool { return f.hasRule(regressionAcceptedCVE) })
	})
	t.Run("dismissed_secret_not_counted", func(t *testing.T) {
		checkDecisionApplied(t, base, decided, regressionDismissedRule+" in "+regressionDismissedFile, suppression.ReasonFalsePositive,
			func(f regressionFinding) bool {
				return f.hasRule(regressionDismissedRule) && f.rel() == regressionDismissedFile
			})
	})
}

// checkDecisionApplied checks that a recorded decision took a finding out of
// the count. The finding may leave the inventory, as dismissed external
// findings do, or stay in it as a suppressed False Positive, as built-in ones
// do; either way it must not be open, the decision must be tallied under its
// reason, and a finding that stays must be scored as ignored.
func checkDecisionApplied(t *testing.T, base, decided *regressionRun, what, reason string, match func(regressionFinding) bool) {
	t.Helper()
	// Not vacuous: without the decision the finding is reported and counted.
	control := base.requireTriage(t)
	if open := control.where(func(f regressionFinding) bool {
		return match(f) && f.Disposition.Disposition != dispositionFalsePositive
	}); len(open) == 0 {
		t.Fatalf("control: the base scenario has no open %s, so the fixture no longer exercises this decision", what)
	}

	tr := decided.requireTriage(t)
	kept := tr.where(match)
	var open []regressionFinding
	for _, f := range kept {
		if !f.dismissed() {
			open = append(open, f)
		}
	}
	if len(open) > 0 {
		t.Errorf("%s is still counted after `aitriage ignore add`: %s; suppressions=%+v",
			what, describeRegressionFindings(open), tr.Suppressions)
	}
	if n := tr.Suppressions.ByReason[reason]; n < 1 {
		t.Errorf("suppressions.by_reason.%s = %d, want >= 1 (suppressions=%+v)", reason, n, tr.Suppressions)
	}
	if len(kept) > len(open) && tr.HealthCheck.Breakdown.IgnoredFindings <= control.HealthCheck.Breakdown.IgnoredFindings {
		t.Errorf("%s is kept as suppressed, but health check ignored_findings = %d, no more than the %d without decisions",
			what, tr.HealthCheck.Breakdown.IgnoredFindings, control.HealthCheck.Breakdown.IgnoredFindings)
	}
}
