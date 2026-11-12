package graph

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// identityMainPy has the shell=True call on line 11 and the swallowed
// exception on line 13.
const identityMainPy = `import subprocess
from fastapi import FastAPI

app = FastAPI()


@app.get("/run")
def run(cmd: str):
    try:
        # run the requested command
        out = subprocess.check_output(cmd, shell=True)
        return {"out": out.decode()}
    except Exception:
        pass
`

func identityFixtureFiles() map[string]string {
	return map[string]string{
		"main.py":           identityMainPy,
		"core/fns.py":       "import os\n\nCLIENT_SECRET = \"example-not-a-real-secret\"\n",
		"Dockerfile":        "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nRUN pip install -r requirements.txt\nCMD [\"python\", \"main.py\"]\n",
		"requirements.txt":  "pillow==9.0.0\njinja2==2.11.2\n",
		"deploy/nginx.conf": "server {\n  listen 80;\n}\n",
	}
}

// multiDetectorState is one hardcoded secret and one shell=True call, each
// reported by four detectors, with paths as the scanners report them.
func multiDetectorState(root string) *AgentState {
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	return &AgentState{
		ProjectPath: root,
		CoreFindings: []core.CheckResult{
			{ID: "SECRET-ASSIGN", Name: "Hardcoded Secret", Status: core.Absent, Severity: "CRITICAL", File: abs("core/fns.py"), Line: 3, Evidence: "CLIENT_SECRET assignment"},
			{ID: "FAST-SUBPROCESS", Name: "Unsafe Subprocess", Status: core.Absent, Severity: "CRITICAL", File: abs("main.py"), Line: 11, Evidence: "Rule FAST-SUBPROCESS found issue in " + abs("main.py")},
			{ID: "PY-SUBPROCESS", Name: "Unsafe Subprocess (shell=True)", Status: core.Absent, Severity: "CRITICAL", File: abs("main.py"), Line: 11, Evidence: "Rule PY-SUBPROCESS found issue in " + abs("main.py")},
		},
		ExternalFindings: []external.UnifiedFinding{
			{Source: "bandit", RuleID: "B105", Severity: "LOW", File: abs("core/fns.py"), Line: 3, Message: "hardcoded_password_string: Possible hardcoded password"},
			{Source: "gitleaks", RuleID: "generic-api-key", Severity: "CRITICAL", File: abs("core/fns.py"), Line: 3, Message: "Detected a Generic API Key: ex****et"},
			{Source: "semgrep", RuleID: "generic.secrets.security.detected-generic-secret.detected-generic-secret", Severity: "HIGH", File: "core/fns.py", Line: 3, Message: "Generic Secret detected"},
			{Source: "bandit", RuleID: "B602", Severity: "HIGH", File: abs("main.py"), Line: 11, Message: "subprocess_popen_with_shell_equals_true: subprocess call with shell=True"},
			{Source: "semgrep", RuleID: "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", Severity: "HIGH", File: "main.py", Line: 11, Message: "Found 'subprocess' function with shell=True"},
		},
	}
}

func allDispositions(state *AgentState, disposition string) []FindingDisposition {
	out := make([]FindingDisposition, len(state.EnrichedFindings))
	for i, f := range state.EnrichedFindings {
		out[i] = FindingDisposition{FindingIndex: i, FindingID: f.VulnID, Disposition: disposition, Rationale: "r", DispositionSource: dispositionSourceLLM, Fingerprint: Fingerprint(f)}
	}
	return out
}

// summarySection returns the part of a Markdown document from heading to the
// next heading.
func summarySection(doc, heading string) string {
	start := strings.Index(doc, heading)
	if start < 0 {
		return ""
	}
	rest := doc[start+len(heading):]
	if end := strings.Index(rest, "\n#"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func findingByClass(t *testing.T, findings []EnrichedFinding, class string) EnrichedFinding {
	t.Helper()
	for _, f := range findings {
		if f.Class == class {
			return f
		}
	}
	t.Fatalf("no finding of class %q in %+v", class, findings)
	return EnrichedFinding{}
}

// D1: one defect reported by four detectors is one finding with four
// origins, and the gate, the score and Top Critical Issues count it once.
func TestDetectorsOfOneDefectMergeIntoOneFinding(t *testing.T) {
	root := writeProjectFiles(t, identityFixtureFiles())
	state := multiDetectorState(root)

	enrichFindings(state)
	if len(state.EnrichedFindings) != 2 {
		t.Fatalf("enriched findings = %d, want 2 (one per defect): %+v", len(state.EnrichedFindings), state.EnrichedFindings)
	}
	secret := findingByClass(t, state.EnrichedFindings, healthcheck.ClassHardcodedSecret)
	if len(secret.Origins) != 4 || secret.File != "core/fns.py" || secret.Line != 3 || secret.Severity != "CRITICAL" {
		t.Fatalf("hardcoded secret = %s:%d %s with %d origins, want core/fns.py:3 CRITICAL with 4", secret.File, secret.Line, secret.Severity, len(secret.Origins))
	}
	if !strings.HasPrefix(secret.VulnID, "CS-SECRETS-") {
		t.Fatalf("secret id = %q, want CS-SECRETS-<hex>", secret.VulnID)
	}
	command := findingByClass(t, state.EnrichedFindings, healthcheck.ClassCommandInjection)
	if len(command.Origins) != 4 || command.File != "main.py" || command.Line != 11 || command.ID != "FAST-SUBPROCESS" {
		t.Fatalf("command injection = %s %s:%d with %d origins, want FAST-SUBPROCESS main.py:11 with 4", command.ID, command.File, command.Line, len(command.Origins))
	}
	for _, origin := range secret.Origins {
		if origin.File != "core/fns.py" || origin.Line != 3 || origin.Severity == "" {
			t.Fatalf("origin %+v lost what its detector reported", origin)
		}
	}

	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	bd := state.HealthCheck.Breakdown
	if bd.ActiveFindings != 2 || bd.ConfirmedFindings != 2 || bd.CountBySeverity["CRITICAL"] != 2 {
		t.Fatalf("breakdown = %+v, want 2 confirmed CRITICAL findings, not 8", bd)
	}
	// Policies written against one detector keep seeing its report.
	if bd.CountByRule["b105"] != 1 || bd.CountBySource["gitleaks"] != 1 || bd.CountByClass[healthcheck.ClassHardcodedSecret] != 1 {
		t.Fatalf("counts by rule/source/class = %v / %v / %v", bd.CountByRule, bd.CountBySource, bd.CountByClass)
	}

	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	top := summarySection(state.SummaryMarkdown, "Top Critical Issues")
	for _, location := range []string{"`core/fns.py:3`", "`main.py:11`"} {
		if n := strings.Count(top, location); n != 1 {
			t.Fatalf("Top Critical Issues names %s %d times, want once:\n%s", location, n, top)
		}
	}
}

// D1: merging never crosses classes. SQL injection and XSS on one line are
// two findings, while two SQL injection detectors on it are one.
func TestDifferentClassesOnOneLineStaySeparate(t *testing.T) {
	state := &AgentState{
		CoreFindings: []core.CheckResult{
			{ID: "FAST-SQLI", Name: "SQL Injection Risk", Status: core.Absent, Severity: "CRITICAL", File: "app.py", Line: 7, Evidence: "raw query"},
			{ID: "FAST-XSS", Name: "Reflected XSS", Status: core.Absent, Severity: "HIGH", File: "app.py", Line: 7, Evidence: "html response"},
		},
		ExternalFindings: []external.UnifiedFinding{
			{Source: "semgrep", RuleID: "python.django.security.injection.sql.sql-injection-using-db-cursor-execute", Severity: "HIGH", File: "app.py", Line: 7, Message: "user input in SQL"},
		},
	}
	enrichFindings(state)
	if len(state.EnrichedFindings) != 2 {
		t.Fatalf("findings = %+v, want SQL injection and XSS kept apart", state.EnrichedFindings)
	}
	if sqli := findingByClass(t, state.EnrichedFindings, "sql_injection"); len(sqli.Origins) != 2 {
		t.Fatalf("sql injection origins = %+v, want core and semgrep", sqli.Origins)
	}
	if xss := findingByClass(t, state.EnrichedFindings, "xss"); len(xss.Origins) != 1 {
		t.Fatalf("xss origins = %+v, want only its own detector", xss.Origins)
	}
}

// F5: a swallowed exception stays LOW when it is merged with a detector that
// rates it higher; the class fixes the severity.
func TestMergedExceptionSwallowKeepsTheClassSeverity(t *testing.T) {
	state := &AgentState{
		CoreFindings: []core.CheckResult{
			{ID: "FAST-LAZY-EXC", Name: "Lazy Exception Handling", Status: core.Absent, Severity: "HIGH", File: "main.py", Line: 13, Evidence: "except: pass"},
		},
		ExternalFindings: []external.UnifiedFinding{
			{Source: "bandit", RuleID: "B110", Severity: "LOW", File: "main.py", Line: 13, Message: "try_except_pass"},
		},
	}
	enrichFindings(state)
	if len(state.EnrichedFindings) != 1 {
		t.Fatalf("findings = %+v, want one merged exception_swallow", state.EnrichedFindings)
	}
	if got := state.EnrichedFindings[0]; got.Severity != "LOW" || got.Class != healthcheck.ClassExceptionSwallow {
		t.Fatalf("merged finding = %s %s, want exception_swallow LOW", got.Class, got.Severity)
	}
}

// D1: the project-level DOCKER-NO-USER is placed on the project's only
// Dockerfile without USER and merges with the file-level reports of Semgrep
// and Trivy. Its own origin stays project-level, so a recorded dismissal of
// it still matches.
func TestDockerfileWithoutUserMergesAcrossDetectors(t *testing.T) {
	root := writeProjectFiles(t, identityFixtureFiles())
	newState := func() *AgentState {
		return &AgentState{
			ProjectPath: root,
			CoreFindings: []core.CheckResult{
				{ID: "DOCKER-NO-USER", Name: "Missing USER Instruction", Status: core.Absent, Severity: "HIGH", Evidence: `Required pattern not found: (?m)^USER\s+`},
			},
			ExternalFindings: []external.UnifiedFinding{
				{Source: "semgrep", RuleID: "dockerfile.security.missing-user.missing-user", Severity: "MEDIUM", File: filepath.Join(root, "Dockerfile"), Line: 5, Message: "By not specifying a USER, a program in the container may run as 'root'"},
				{Source: "trivy", RuleID: "DS-0002", Severity: "HIGH", File: "Dockerfile", Message: "Image user should not be 'root'"},
			},
		}
	}

	state := newState()
	enrichFindings(state)
	if len(state.EnrichedFindings) != 1 {
		t.Fatalf("findings = %+v, want one container_runs_as_root", state.EnrichedFindings)
	}
	root0 := state.EnrichedFindings[0]
	if root0.Class != healthcheck.ClassContainerRunsAsRoot || root0.File != "Dockerfile" || root0.Line != 5 || len(root0.Origins) != 3 {
		t.Fatalf("merged = %s %s:%d with %d origins, want container_runs_as_root Dockerfile:5 with 3", root0.Class, root0.File, root0.Line, len(root0.Origins))
	}
	if !strings.HasPrefix(root0.VulnID, "CS-ROOT-") {
		t.Fatalf("id = %q, want CS-ROOT-<hex>", root0.VulnID)
	}
	for _, origin := range root0.Origins {
		if origin.RuleID == "DOCKER-NO-USER" && (origin.File != "" || origin.Line != 0) {
			t.Fatalf("core origin = %+v, want the project-level location it reported", origin)
		}
	}

	// Dismissed in the audit log, and the other detectors suppressed by
	// decisions: the remaining finding is recognised as dismissed.
	dismissed := newState()
	dismissed.ExternalFindings = nil
	dismissed.CoreFindings[0].AuditStatus = core.AuditStatusIgnored
	enrichFindings(dismissed)
	if got := dismissed.EnrichedFindings[0]; got.File != "Dockerfile" {
		t.Fatalf("dismissed finding location = %q, want Dockerfile", got.File)
	}
	preset := deterministicDispositions(dismissed)
	if d, ok := preset[0]; !ok || d.DispositionSource != dispositionSourceSuppressed {
		t.Fatalf("dismissed DOCKER-NO-USER disposition = %+v, want suppressed", preset)
	}
}

func TestDockerfileWithoutUserStaysProjectLevelWhenAmbiguous(t *testing.T) {
	files := identityFixtureFiles()
	files["worker/Dockerfile"] = "FROM alpine:3.20\nCMD [\"sh\"]\n"
	root := writeProjectFiles(t, files)
	if file, _ := dockerfileWithoutUser(root); file != "" {
		t.Fatalf("dockerfileWithoutUser = %q, want none with two candidates", file)
	}
	files["worker/Dockerfile"] = "FROM alpine:3.20\nUSER 65534\nCMD [\"sh\"]\n"
	root = writeProjectFiles(t, files)
	if file, line := dockerfileWithoutUser(root); file != "Dockerfile" || line != 5 {
		t.Fatalf("dockerfileWithoutUser = %q:%d, want Dockerfile:5", file, line)
	}
}

// D3: a project-level finding is one rule's verdict. The same rule reported
// once per stack is one finding; two rules of one class (FastAPI's and
// Express's missing authentication, and the NFR check) are three, because
// each names a different component. Reports call the location "project".
func TestProjectLevelFindingsAreOneFindingPerRule(t *testing.T) {
	root := writeProjectFiles(t, identityFixtureFiles())
	state := &AgentState{
		ProjectPath: root,
		CoreFindings: []core.CheckResult{
			{ID: "FAST-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "Required pattern not found"},
			{ID: "EXPRESS-AUTH", Name: "Missing Authentication", Status: core.Absent, Severity: "HIGH", Evidence: "Required pattern not found: passport"},
			{ID: "ENTR-02", Name: "Missing Lockfile", Status: core.Absent, Severity: "HIGH", Evidence: "No lockfile for npm in " + filepath.Join(root, "web")},
			{ID: "ENTR-02", Name: "Missing Lockfile", Status: core.Absent, Severity: "HIGH", Evidence: "No lockfile for pip in " + filepath.Join(root, "api")},
		},
		NFRFindings: []nfr.NFRFinding{
			{RuleID: "NFR-API-003", Name: "Authentication Middleware Missing", Severity: "HIGH", Message: "No authentication middleware detected"},
		},
	}
	enrichFindings(state)
	if len(state.EnrichedFindings) != 4 {
		t.Fatalf("findings = %d, want three authentication rules and the lockfile rule once: %+v", len(state.EnrichedFindings), state.EnrichedFindings)
	}
	rules := map[string]int{}
	for _, f := range state.EnrichedFindings {
		rules[f.ID] = len(f.Origins)
		if f.ID != "ENTR-02" && f.Class != "missing_authentication" {
			t.Fatalf("finding %s class = %q, want missing_authentication", f.ID, f.Class)
		}
	}
	// The two lockfile reports are one origin: same rule, same (project) place.
	if want := map[string]int{"FAST-AUTH": 1, "EXPRESS-AUTH": 1, "NFR-API-003": 1, "ENTR-02": 1}; !reflect.DeepEqual(rules, want) {
		t.Fatalf("origins per rule = %v, want %v", rules, want)
	}

	state.FindingDispositions = allDispositions(state, "Needs Manual Review")
	computeHealthCheck(state)
	if bd := state.HealthCheck.Breakdown; bd.ActiveFindings != 4 || bd.CountBySeverity["HIGH"] != 4 {
		t.Fatalf("breakdown = %+v, want 4 active HIGH findings", bd)
	}
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	top := summarySection(state.SummaryMarkdown, "Top Critical Issues")
	if strings.Count(top, "— `project`") != 4 || strings.Contains(state.SummaryMarkdown, "N/A") {
		t.Fatalf("project-level findings must read `project`, not N/A:\n%s", state.SummaryMarkdown)
	}
}

// G1: every artifact names files relative to the project root, never the
// absolute path the project was scanned at.
func TestArtifactsUseProjectRelativePaths(t *testing.T) {
	root := writeProjectFiles(t, identityFixtureFiles())
	state := multiDetectorState(root)
	state.ExternalFindings = append(state.ExternalFindings, external.UnifiedFinding{
		Source: "trivy", RuleID: "CVE-2023-50447", Severity: "CRITICAL", File: "requirements.txt",
		Message: "pillow: Arbitrary Code Execution", Package: "pillow", InstalledVersion: "9.0.0", FixedVersion: "10.2.0",
	})
	state.DeployFindings = []deployaudit.DeployFinding{
		{File: filepath.Join(root, "deploy", "nginx.conf"), Line: 1, Issue: "nginx_missing_server_tokens_off", Severity: "LOW", Advice: "Set server_tokens off"},
	}

	enrichFindings(state)
	state.FindingDispositions = allDispositions(state, "True Positive")
	computeHealthCheck(state)
	if err := generateSummary(state); err != nil {
		t.Fatal(err)
	}
	artifact, err := BuildTriageFindingsArtifact(state)
	if err != nil {
		t.Fatal(err)
	}
	triageJSON, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	documents := map[string]string{
		"triage-findings.json": string(triageJSON),
		"summary.md":           state.SummaryMarkdown,
		"report.md":            buildDeterministicReport(state, ""),
		"fixspec.md":           buildDeterministicFixSpec(state, ""),
	}
	roots := []string{filepath.ToSlash(root)}
	if real, err := filepath.EvalSymlinks(root); err == nil {
		roots = append(roots, filepath.ToSlash(real))
	}
	for name, body := range documents {
		for _, r := range roots {
			if strings.Contains(body, r) {
				t.Fatalf("%s contains the absolute project path %s", name, r)
			}
		}
	}
	files := map[string]bool{}
	for _, f := range state.EnrichedFindings {
		files[f.File] = true
	}
	for _, want := range []string{"core/fns.py", "main.py", "requirements.txt", "deploy/nginx.conf"} {
		if !files[want] {
			t.Fatalf("finding files = %v, want %s", files, want)
		}
	}
	command := findingByClass(t, state.EnrichedFindings, healthcheck.ClassCommandInjection)
	if !strings.Contains(command.Message, "found issue in main.py") {
		t.Fatalf("message = %q, want the project-relative path", command.Message)
	}
}

// identityRun enriches a fixed set of findings against the given project.
func identityRun(root string, mainLineShift int, extra ...external.UnifiedFinding) *AgentState {
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	state := &AgentState{
		ProjectPath: root,
		CoreFindings: []core.CheckResult{
			{ID: "FAST-SUBPROCESS", Name: "Unsafe Subprocess", Status: core.Absent, Severity: "CRITICAL", File: abs("main.py"), Line: 11 + mainLineShift, Evidence: "Rule FAST-SUBPROCESS found issue in " + abs("main.py")},
			{ID: "FAST-LAZY-EXC", Name: "Lazy Exception Handling", Status: core.Absent, Severity: "LOW", File: abs("main.py"), Line: 13 + mainLineShift, Evidence: "Rule FAST-LAZY-EXC found issue in " + abs("main.py")},
			{ID: "SECRET-ASSIGN", Name: "Hardcoded Secret", Status: core.Absent, Severity: "CRITICAL", File: abs("core/fns.py"), Line: 3, Evidence: "CLIENT_SECRET assignment"},
		},
		ExternalFindings: append([]external.UnifiedFinding{
			{Source: "bandit", RuleID: "B602", Severity: "HIGH", File: abs("main.py"), Line: 11 + mainLineShift, Message: "subprocess_popen_with_shell_equals_true"},
			{Source: "trivy", RuleID: "CVE-2023-50447", Severity: "HIGH", File: "requirements.txt", Message: "pillow: Arbitrary Code Execution", Package: "pillow", InstalledVersion: "9.0.0", FixedVersion: "10.2.0"},
			{Source: "trivy", RuleID: "CVE-2020-28493", Severity: "MEDIUM", File: "requirements.txt", Message: "jinja2: ReDoS", Package: "jinja2", InstalledVersion: "2.11.2", FixedVersion: "2.11.3"},
		}, extra...),
		DeployFindings: []deployaudit.DeployFinding{
			{File: abs("deploy/nginx.conf"), Line: 1, Issue: "nginx_missing_server_tokens_off", Severity: "LOW", Advice: "Set server_tokens off"},
		},
	}
	enrichFindings(state)
	return state
}

// D4: adding a finding and inserting a line above others changes neither the
// stable id nor the display id of any unchanged finding.
func TestStableIDsSurviveAnInsertedLineAndANewFinding(t *testing.T) {
	root := writeProjectFiles(t, identityFixtureFiles())
	before := identityRun(root, 0)

	files := identityFixtureFiles()
	files["main.py"] = "# service entry point\n" + identityMainPy
	shifted := writeProjectFiles(t, files)
	after := identityRun(shifted, 1, external.UnifiedFinding{
		Source: "trivy", RuleID: "CVE-2022-22817", Severity: "CRITICAL", File: "requirements.txt",
		Message: "pillow: PIL.ImageMath.eval allows evaluation of arbitrary expressions", Package: "pillow", InstalledVersion: "9.0.0", FixedVersion: "9.0.1",
	})

	if len(after.EnrichedFindings) != len(before.EnrichedFindings)+1 {
		t.Fatalf("findings after = %d, before = %d; want exactly one more", len(after.EnrichedFindings), len(before.EnrichedFindings))
	}
	ids := map[string]string{}
	for _, f := range after.EnrichedFindings {
		ids[f.StableID] = f.VulnID
	}
	for _, f := range before.EnrichedFindings {
		if f.StableID == "" {
			t.Fatalf("finding %s has no stable id", f.ID)
		}
		vulnID, ok := ids[f.StableID]
		if !ok {
			t.Fatalf("finding %s (%s) changed its stable id after an unrelated edit", f.ID, f.VulnID)
		}
		if vulnID != f.VulnID {
			t.Fatalf("finding %s was renumbered: %s -> %s", f.ID, f.VulnID, vulnID)
		}
	}
}

// D4: the stable id follows the flagged line's content, and identical lines
// in one file stay distinct by occurrence.
func TestStableIDFollowsTheFlaggedLineContent(t *testing.T) {
	root := writeProjectFiles(t, identityFixtureFiles())
	before := findingByClass(t, identityRun(root, 0).EnrichedFindings, healthcheck.ClassCommandInjection)

	files := identityFixtureFiles()
	files["main.py"] = strings.Replace(identityMainPy, "check_output(cmd, shell=True)", "check_output(cmd + suffix, shell=True)", 1)
	edited := findingByClass(t, identityRun(writeProjectFiles(t, files), 0).EnrichedFindings, healthcheck.ClassCommandInjection)
	if edited.StableID == before.StableID {
		t.Fatal("editing the flagged line kept its stable id")
	}

	twin := "x = input()\neval(x)\n\ny = input()\neval(x)\n"
	identical := func(prefix string) []EnrichedFinding {
		dir := writeProjectFiles(t, map[string]string{"run.py": prefix + twin})
		offset := strings.Count(prefix, "\n")
		state := &AgentState{ProjectPath: dir, CoreFindings: []core.CheckResult{
			{ID: "PY-EXEC", Name: "Dynamic Code Execution", Status: core.Absent, Severity: "CRITICAL", File: "run.py", Line: 2 + offset, Evidence: "eval"},
			{ID: "PY-EXEC", Name: "Dynamic Code Execution", Status: core.Absent, Severity: "CRITICAL", File: "run.py", Line: 5 + offset, Evidence: "eval"},
		}}
		enrichFindings(state)
		return state.EnrichedFindings
	}
	first, moved := identical(""), identical("import os\n")
	if len(first) != 2 || first[0].StableID == first[1].StableID {
		t.Fatalf("identical lines share a stable id: %+v", first)
	}
	if moved[0].StableID != first[0].StableID || moved[1].StableID != first[1].StableID {
		t.Fatal("a line inserted above identical lines changed their stable ids")
	}
}

// D4: the verdict cache is keyed without line numbers. A finding that only
// moved reuses its verdict, including a false positive whose evidence moved
// with it; an edit to the flagged line asks the model again.
func TestVerdictCacheSurvivesLineShiftsButNotEdits(t *testing.T) {
	pinConcurrency(t)
	t.Setenv("AITRIAGE_CACHE_DIR", t.TempDir())
	t.Setenv("AITRIAGE_LLM_MODEL", "model-a")

	source := "import shlex\nimport subprocess\n\n\ndef run(cmd):\n    cmd = shlex.quote(cmd)\n    return subprocess.check_output(cmd, shell=True)\n"
	// enriched scans a project whose main.py is source with prefix lines
	// inserted above it.
	enriched := func(prefix, body string) (string, []EnrichedFinding) {
		root := writeProjectFiles(t, map[string]string{"main.py": prefix + body})
		line := 7 + strings.Count(prefix, "\n")
		state := &AgentState{ProjectPath: root, CoreFindings: []core.CheckResult{
			{ID: "FAST-SUBPROCESS", Name: "Unsafe Subprocess", Status: core.Absent, Severity: "MEDIUM", File: filepath.Join(root, "main.py"), Line: line, Evidence: "shell=True"},
		}}
		enrichFindings(state)
		return root, state.EnrichedFindings
	}
	classify := func(root string, findings []EnrichedFinding, client llm.Client) ([]FindingDisposition, error) {
		var usage llm.Usage
		_, disps, _, _, err := ClassifyFindingsWithAudit(context.Background(), "", root, "", findings, client, &usage, 40)
		return disps, err
	}

	root, first := enriched("", source)
	model := &fakeLLM{t: t, classifyHandler: func(call int, batch []EnrichedFinding) (string, error) {
		return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"input is quoted","evidence":{"basis":"code_mitigation","file":"main.py","line":6,"observed":"shlex.quote(cmd)"}}]}`, nil
	}}
	disps, err := classify(root, first, model)
	if err != nil || disps[0].Disposition != "False Positive" || model.classifyCalls != 1 {
		t.Fatalf("first run: %+v err=%v calls=%d, want a model false positive", disps, err, model.classifyCalls)
	}

	root, moved := enriched("# entry point\n\n", source)
	offline := &fakeLLM{t: t, tmErr: errors.New("the model must not be asked about a finding that only moved")}
	disps, err = classify(root, moved, offline)
	if err != nil {
		t.Fatalf("moved run: %v", err)
	}
	if disps[0].DispositionSource != dispositionSourceCache || disps[0].Disposition != "False Positive" || disps[0].Evidence == nil || disps[0].Evidence.Line != 8 {
		t.Fatalf("moved run disposition = %+v, want the cached false positive with its evidence on line 8", disps[0])
	}

	root, edited := enriched("", strings.Replace(source, "check_output(cmd, shell=True)", "check_output(cmd + flags, shell=True)", 1))
	again := &fakeLLM{t: t}
	if _, err := classify(root, edited, again); err != nil || again.classifyCalls != 1 {
		t.Fatalf("edited run: err=%v classify calls=%d, want the model asked again", err, again.classifyCalls)
	}
}
