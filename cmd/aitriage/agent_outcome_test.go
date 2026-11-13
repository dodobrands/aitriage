package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/spf13/cobra"
)

func TestExitStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		code   int
		report bool
	}{
		{"policy violation", ErrPolicyViolation, 1, false},
		{"silent exit", errSilentExit, 1, false},
		{"audit incomplete", auditIncomplete(errors.New("provider failed")), 2, true},
		{"container status", &exitStatusError{code: 2}, 2, false},
		{"wrapped container status", errors.Join(errors.New("ctx"), &exitStatusError{code: 1}), 1, false},
		{"generic error", errors.New("boom"), 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, report := exitStatus(tc.err)
			if code != tc.code || report != tc.report {
				t.Fatalf("exitStatus(%v) = (%d, %v), want (%d, %v)", tc.err, code, report, tc.code, tc.report)
			}
		})
	}
}

// failingProvider rejects every request, as a revoked API key does.
type failingProvider struct{}

func (failingProvider) Chat(context.Context, []llm.Message) (string, llm.Usage, error) {
	return "", llm.Usage{}, errors.New("openai chat error: 401 Unauthorized")
}

func setAgentOutputs(t *testing.T, dir string) {
	t.Helper()
	previous := []string{agentReportOut, agentFixSpecOut, agentSummaryOut, agentTriageOut}
	agentReportOut = filepath.Join(dir, "report.md")
	agentFixSpecOut = filepath.Join(dir, "fixspec.md")
	agentSummaryOut = filepath.Join(dir, "summary.md")
	agentTriageOut = filepath.Join(dir, "triage-findings.json")
	t.Cleanup(func() {
		agentReportOut, agentFixSpecOut, agentSummaryOut, agentTriageOut = previous[0], previous[1], previous[2], previous[3]
	})
}

// A2: when the provider fails during triage every requested artifact is still
// written, the gate is failed, and the command exits 2 — not 1, which keeps
// meaning "the policy failed".
func TestAgentWritesArtifactsAndExitsTwoWhenTriageIsIncomplete(t *testing.T) {
	t.Setenv("AITRIAGE_CACHE_DIR", "")
	t.Setenv("AITRIAGE_VERDICT_CACHE_DIR", "")
	t.Setenv("AITRIAGE_ARTIFACT_CACHE_DIR", "")
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.py"), []byte("x = 1\nresult = eval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := &graph.AgentState{
		ProjectPath:  project,
		CoreFindings: []core.CheckResult{{ID: "PY-EVAL", Name: "eval", Status: core.Absent, Severity: "HIGH", File: "app.py", Line: 2, Evidence: "eval(user_input)"}},
		Policy:       healthcheck.Policy{FailOn: healthcheck.FailOnConfirmed},
	}
	runErr := graph.Run(context.Background(), state, failingProvider{})
	var incomplete *graph.TriageIncompleteError
	if !errors.As(runErr, &incomplete) {
		t.Fatalf("graph.Run() error = %v, want an incomplete triage", runErr)
	}

	out := t.TempDir()
	setAgentOutputs(t, out)
	if err := writeAgentArtifacts(state); err != nil {
		t.Fatalf("writeAgentArtifacts() error = %v", err)
	}
	for _, name := range []string{"report.md", "fixspec.md", "summary.md", "triage-findings.json"} {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("artifact %s missing: %v", name, err)
		}
		if name != "triage-findings.json" && !strings.Contains(string(data), "AI triage did not complete: ") {
			t.Fatalf("%s has no triage-incomplete banner:\n%s", name, data)
		}
	}
	var artifact struct {
		TriageStatus        string `json:"triage_status"`
		TriageFailureReason string `json:"triage_failure_reason"`
		HealthCheck         struct {
			Verdict healthcheck.Verdict `json:"verdict"`
		} `json:"health_check"`
	}
	data, _ := os.ReadFile(filepath.Join(out, "triage-findings.json"))
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.TriageStatus != "failed" || !strings.Contains(artifact.TriageFailureReason, "401 Unauthorized") || artifact.HealthCheck.Verdict.Passed {
		t.Fatalf("artifact status/reason/verdict = %q/%q/%+v, want failed, the reason and a failed gate", artifact.TriageStatus, artifact.TriageFailureReason, artifact.HealthCheck.Verdict)
	}

	var stderr bytes.Buffer
	err := agentOutcome(&stderr, state, incomplete)
	if code, _ := exitStatus(err); code != 2 {
		t.Fatalf("exit status = %d (err %v), want 2", code, err)
	}
	if !strings.Contains(stderr.String(), "AI triage did not complete") || !strings.Contains(stderr.String(), "triage_incomplete") {
		t.Fatalf("stderr = %q, want the failure and the blocking reason", stderr.String())
	}
}

// The closing message of an incomplete triage names its reason and the
// remedy that fits the cause: waiting for the provider helps nothing when the
// model left findings out, and a finding the model declined needs a person.
func TestAgentOutcomeNamesTheRemedyForTheCause(t *testing.T) {
	state := &graph.AgentState{HealthCheck: healthcheck.Result{Verdict: healthcheck.Verdict{Passed: false, Summary: "failed"}}}
	const declinedReason = "claude-sonnet-5-5 declined to classify 1 finding(s) (stop_reason refusal, category cyber), each sent on its own"
	for _, tc := range []struct {
		name       string
		incomplete *graph.TriageIncompleteError
		want       []string
	}{
		{
			name:       "provider failure",
			incomplete: &graph.TriageIncompleteError{Reason: "openai chat error: 401 Unauthorized", Unclassified: 2, Cause: graph.TriageFailureCauseProvider},
			want:       []string{"401 Unauthorized", "2 finding(s) without a verdict", "Re-run once the LLM provider is available."},
		},
		{
			name:       "left out of every reply",
			incomplete: &graph.TriageIncompleteError{Reason: "no reply carried a verdict for them", Unclassified: 2, Cause: graph.TriageFailureCauseNoVerdict},
			want:       []string{"Re-run, and if the model keeps leaving findings out, raise AITRIAGE_CLASSIFY_RETRIES or lower AITRIAGE_BATCH_SIZE."},
		},
		{
			name:       "declined",
			incomplete: &graph.TriageIncompleteError{Reason: declinedReason, Unclassified: 1, Declined: 1, Cause: graph.TriageFailureCauseNoVerdict},
			want:       []string{declinedReason, "The model declined to classify 1 of them and is likely to decline them again: review them by hand, or triage them with another model."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code, _ := exitStatus(agentOutcome(&out, state, tc.incomplete)); code != 2 {
				t.Fatalf("exit status = %d, want 2", code)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output lacks %q:\n%s", want, out.String())
				}
			}
			if tc.incomplete.Cause != graph.TriageFailureCauseProvider && strings.Contains(out.String(), "provider is available") {
				t.Errorf("output tells to wait for the provider:\n%s", out.String())
			}
			if strings.Contains(out.String(), "`") {
				t.Errorf("output carries Markdown:\n%s", out.String())
			}
		})
	}
}

func TestAgentOutcomeExitStatuses(t *testing.T) {
	passed := &graph.AgentState{HealthCheck: healthcheck.Result{Verdict: healthcheck.Verdict{Passed: true}}}
	if err := agentOutcome(&bytes.Buffer{}, passed, nil); err != nil {
		t.Fatalf("passed gate: err = %v, want nil", err)
	}
	failed := &graph.AgentState{HealthCheck: healthcheck.Result{Verdict: healthcheck.Verdict{Passed: false, Summary: "failed"}}}
	if code, _ := exitStatus(agentOutcome(&bytes.Buffer{}, failed, nil)); code != 1 {
		t.Fatalf("policy violation exit status = %d, want 1", code)
	}
}

// N5: a runtime failure must not print the full usage text (it used to follow
// every red CI run), and an operational failure exits 2.
func TestRunAgentRuntimeFailureSilencesUsageAndExitsTwo(t *testing.T) {
	for _, name := range []string{"AITRIAGE_LLM_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY", "AITRIAGE_LLM_PROVIDER", "AITRIAGE_LLM_MODEL", "AITRIAGE_LLM_BASE_URL"} {
		t.Setenv(name, "")
	}
	previousRuntime := agentRuntime
	agentRuntime = "native"
	t.Cleanup(func() { agentRuntime = previousRuntime })
	cmd := &cobra.Command{Use: "agent"}
	cmd.SetContext(context.Background())

	err := runAgent(cmd, []string{t.TempDir()})
	if !errors.Is(err, ErrAuditIncomplete) {
		t.Fatalf("runAgent() error = %v, want ErrAuditIncomplete (no LLM provider configured)", err)
	}
	if !cmd.SilenceUsage || !cmd.SilenceErrors {
		t.Fatalf("SilenceUsage=%v SilenceErrors=%v, want both set for a runtime failure", cmd.SilenceUsage, cmd.SilenceErrors)
	}
	if code, report := exitStatus(err); code != 2 || !report {
		t.Fatalf("exit status = (%d, %v), want (2, true)", code, report)
	}
}

func TestValidateAgentFlagsRejectsUnknownSeverityFloor(t *testing.T) {
	previous := agentConfirmedMinSeverity
	t.Cleanup(func() { agentConfirmedMinSeverity = previous })
	agentConfirmedMinSeverity = "severe"
	if err := validateAgentFlags(); err == nil || !strings.Contains(err.Error(), "--confirmed-min-severity") {
		t.Fatalf("validateAgentFlags() = %v, want the bad floor rejected", err)
	}
	agentConfirmedMinSeverity = "high"
	if err := validateAgentFlags(); err != nil {
		t.Fatalf("validateAgentFlags() = %v, want HIGH accepted", err)
	}
}

// --iac-findings accepts report or block, overrides the configuration and
// reaches the agent inside the container.
func TestAgentIaCFindingsFlag(t *testing.T) {
	previous := agentIaCFindings
	t.Cleanup(func() { agentIaCFindings = previous })

	agentIaCFindings = "gate"
	if err := validateAgentFlags(); err == nil || !strings.Contains(err.Error(), "--iac-findings") {
		t.Fatalf("validateAgentFlags() = %v, want the bad mode rejected", err)
	}

	agentIaCFindings = "block"
	if err := validateAgentFlags(); err != nil {
		t.Fatalf("validateAgentFlags() = %v, want block accepted", err)
	}
	cmd := newAgentPolicyTestCommand()
	cmd.Flags().String("iac-findings", "", "")
	if err := cmd.Flags().Set("iac-findings", "block"); err != nil {
		t.Fatal(err)
	}
	reported := &config.Config{HealthCheck: config.HealthCheckPolicyConfig{IaCFindings: "report"}}
	if policy := agentPolicyFromFlags(cmd, reported); policy.IaCFindings != healthcheck.IaCFindingsBlock {
		t.Fatalf("policy iac_findings = %q, want the flag to override the configuration", policy.IaCFindings)
	}
	if policy := agentPolicyFromFlags(newAgentPolicyTestCommand(), &config.Config{}); policy.IaCFindings != healthcheck.IaCFindingsReport {
		t.Fatalf("default iac_findings = %q, want report", policy.IaCFindings)
	}

	args, err := agentContainerCommandArgs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(args, " "); !strings.Contains(joined, "--iac-findings block") {
		t.Fatalf("inner agent args do not forward --iac-findings:\n%s", joined)
	}
}

// --quality-findings accepts report or block, overrides the configuration
// (with --health-profile too) and reaches the agent inside the container.
func TestAgentQualityFindingsFlag(t *testing.T) {
	previous, previousProfile := agentQualityFindings, agentHealthProfile
	t.Cleanup(func() { agentQualityFindings, agentHealthProfile = previous, previousProfile })

	agentQualityFindings = "gate"
	if err := validateAgentFlags(); err == nil || !strings.Contains(err.Error(), "--quality-findings") {
		t.Fatalf("validateAgentFlags() = %v, want the bad mode rejected", err)
	}

	agentQualityFindings = "block"
	if err := validateAgentFlags(); err != nil {
		t.Fatalf("validateAgentFlags() = %v, want block accepted", err)
	}
	cmd := newAgentPolicyTestCommand()
	cmd.Flags().String("quality-findings", "", "")
	agentHealthProfile = healthcheck.PolicyStrict
	for name, value := range map[string]string{"quality-findings": "block", "health-profile": healthcheck.PolicyStrict} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	reported := &config.Config{HealthCheck: config.HealthCheckPolicyConfig{QualityFindings: "report"}}
	if policy := agentPolicyFromFlags(cmd, reported); policy.QualityFindings != healthcheck.QualityFindingsBlock {
		t.Fatalf("policy quality_findings = %q, want the flag to override the configuration", policy.QualityFindings)
	}
	agentHealthProfile = previousProfile
	if policy := agentPolicyFromFlags(newAgentPolicyTestCommand(), &config.Config{}); policy.QualityFindings != healthcheck.QualityFindingsBlock {
		t.Fatalf("default quality_findings = %q, want block", policy.QualityFindings)
	}
	if policy := agentPolicyFromFlags(newAgentPolicyTestCommand(), reported); policy.QualityFindings != healthcheck.QualityFindingsReport {
		t.Fatalf("configured quality_findings = %q, want report", policy.QualityFindings)
	}

	args, err := agentContainerCommandArgs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(args, " "); !strings.Contains(joined, "--quality-findings block") {
		t.Fatalf("inner agent args do not forward --quality-findings:\n%s", joined)
	}
}

func TestAgentPolicyAppliesTriagePolicyFlags(t *testing.T) {
	cmd := newAgentPolicyTestCommand()
	cmd.Flags().String("confirmed-min-severity", "", "")
	cmd.Flags().Bool("fp-critical-requires-high-confidence", false, "")
	for name, value := range map[string]string{"fail-on": "confirmed", "confirmed-min-severity": "high", "fp-critical-requires-high-confidence": "true"} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	previous := []string{agentFailOn, agentConfirmedMinSeverity}
	previousFP := agentFPCriticalRequiresHighConfidence
	t.Cleanup(func() {
		agentFailOn, agentConfirmedMinSeverity = previous[0], previous[1]
		agentFPCriticalRequiresHighConfidence = previousFP
	})
	agentFailOn, agentConfirmedMinSeverity, agentFPCriticalRequiresHighConfidence = "confirmed", "high", true

	policy := agentPolicyFromFlags(cmd, &config.Config{})
	if policy.FailOn != healthcheck.FailOnConfirmed || policy.ConfirmedMinSeverity != healthcheck.SeverityHigh || !policy.FPCriticalRequiresHighConfidence {
		t.Fatalf("policy = %+v, want confirmed with a HIGH floor and the confidence policy", policy)
	}
}

func TestAgentContainerForwardsTriageAndProbeFlags(t *testing.T) {
	root := t.TempDir()
	previous := []string{agentConfirmedMinSeverity}
	previousBools := []bool{agentProbeCompose, agentFPCriticalRequiresHighConfidence}
	t.Cleanup(func() {
		agentConfirmedMinSeverity = previous[0]
		agentProbeCompose, agentFPCriticalRequiresHighConfidence = previousBools[0], previousBools[1]
	})
	agentConfirmedMinSeverity, agentProbeCompose, agentFPCriticalRequiresHighConfidence = "HIGH", true, true

	args, err := agentContainerCommandArgs(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--probe-compose", "--confirmed-min-severity HIGH", "--fp-critical-requires-high-confidence"} {
		if !strings.Contains(joined, want) {
			t.Errorf("inner agent args missing %q:\n%s", want, joined)
		}
	}
}

// Tuning variables reach the container (a host-CLI container run silently
// ignored them before); host paths and nothing else do not.
func TestAgentEnvAllowlistForwardsTuningButNotHostPaths(t *testing.T) {
	for _, name := range []string{"AITRIAGE_CLASSIFY_RETRIES", "AITRIAGE_CONCURRENCY", "AITRIAGE_LLM_BUDGET", "AITRIAGE_POC_BUDGET", "AITRIAGE_GATING", "AITRIAGE_RESPECT_GITIGNORE", "AITRIAGE_SCAN_VENDORED", "AITRIAGE_BATCH_SIZE"} {
		if !slices.Contains(agentEnvAllowlist, name) {
			t.Errorf("%s is not forwarded into the agent container", name)
		}
	}
	for _, name := range []string{"AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR", "AITRIAGE_CACHE_DIR", "AITRIAGE_REPORTS_DIR"} {
		if slices.Contains(agentEnvAllowlist, name) {
			t.Errorf("host path variable %s must not be forwarded into the container", name)
		}
	}
	seen := map[string]bool{}
	for _, name := range agentEnvAllowlist {
		if seen[name] {
			t.Errorf("%s is listed twice", name)
		}
		seen[name] = true
	}
}

// The containerised agent's exit status (1 policy, 2 incomplete) must reach CI
// unchanged instead of collapsing to 1.
func TestContainerExitStatusPassesChildStatusThrough(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 2").Run()
	if err == nil {
		t.Skip("shell unavailable")
	}
	code, report := exitStatus(containerExitStatus(err))
	if code != 2 || report {
		t.Fatalf("exit status = (%d, %v), want (2, false)", code, report)
	}
	if got := containerExitStatus(nil); got != nil {
		t.Fatalf("containerExitStatus(nil) = %v, want nil", got)
	}
}
