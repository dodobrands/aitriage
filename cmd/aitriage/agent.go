package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/pipeline"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/healthpolicy"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	rt "github.com/dodobrands/aitriage/internal/runtime"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/spf13/cobra"
)

var (
	agentProvider      string
	agentModel         string
	agentAPIKey        string
	agentNoChat        bool
	agentOutput        string
	agentProbe         string
	agentFullScan      bool
	agentRuleID        string
	agentTargetFile    string
	agentTargetLine    int
	agentReportOut     string
	agentFixSpecOut    string
	agentSummaryOut    string
	agentTriageOut     string
	agentManifestOut   string
	agentSARIFOut      string
	agentFailOn        string
	agentFailScore     int
	agentHealthProfile string
	agentRuntime       string

	agentProbeCompose                     bool
	agentConfirmedMinSeverity             string
	agentFPCriticalRequiresHighConfidence bool
)

var agentCmd = &cobra.Command{
	Use:   "agent [path]",
	Short: "Run AI-powered security audit with LLM analysis and interactive Q&A",
	Long: `Run a full security scan, then use an LLM to triage findings, generate
a prioritized report, and produce an AI fix specification.

The LLM provider is auto-detected from environment variables:
  GEMINI_API_KEY    → Google Gemini
  ANTHROPIC_API_KEY → Anthropic Claude
  OPENAI_API_KEY    → OpenAI GPT

You can also configure it in .aitriage.yaml under the "llm:" section.`,
	Example: `  aitriage agent                        # Audit current directory
  aitriage agent ./my-project           # Audit specific path
  aitriage agent --no-chat              # Skip interactive Q&A (CI/CD)
  aitriage agent --provider gemini      # Force specific provider
  aitriage agent --model gemini-1.5-pro # Use specific model`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgent,
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.Flags().StringVar(&agentProvider, "provider", "", "LLM provider: gemini, anthropic, openai, ollama, groq (auto-detected from env)")
	agentCmd.Flags().StringVar(&agentModel, "model", "", "LLM model name")
	agentCmd.Flags().StringVar(&agentAPIKey, "api-key", "", "LLM API key (or set via env)")
	agentCmd.Flags().BoolVar(&agentNoChat, "no-chat", false, "Skip interactive Q&A (for CI/CD)")
	agentCmd.Flags().StringVar(&agentOutput, "output", "text", "Output format: text | json | md")
	agentCmd.Flags().StringVar(&agentProbe, "probe", "", "Target host to probe for open DBs/Services (e.g. localhost, example.com)")
	agentCmd.Flags().BoolVar(&agentFullScan, "full-scan", false, "Probe all 65535 ports (slow, ~30-60s)")
	agentCmd.Flags().StringVar(&agentRuleID, "rule-id", "", "Target a specific rule ID to fix")
	agentCmd.Flags().StringVar(&agentTargetFile, "file", "", "Target a specific file to fix (used with --rule-id)")
	agentCmd.Flags().IntVar(&agentTargetLine, "line", 0, "Target a specific line to fix (used with --rule-id)")
	agentCmd.Flags().StringVar(&agentReportOut, "report-out", "", "Write the final Markdown triage report to this file (for CI/CD)")
	agentCmd.Flags().StringVar(&agentFixSpecOut, "fixspec-out", "", "Write the AI fix specification to this file (for CI/CD)")
	agentCmd.Flags().StringVar(&agentSummaryOut, "summary-out", "", "Write the actionable summary (TP/NR only, no FP) to this file")
	agentCmd.Flags().StringVar(&agentTriageOut, "triage-out", "", "Write the canonical JSON inventory of every triaged finding to this file (for CI/CD)")
	agentCmd.Flags().StringVar(&agentManifestOut, "manifest-out", "", "Write scanner execution coverage and statuses to this JSON file")
	agentCmd.Flags().StringVar(&agentSARIFOut, "sarif-out", "", "Write deterministic AITriage findings as SARIF")
	agentCmd.Flags().StringVar(&agentFailOn, "fail-on", "never", "CI gate: exit 1 when 'critical' (active CRITICAL/HIGH after AI triage), 'confirmed' (findings AI triage confirmed), 'any' finding, or 'never'")
	agentCmd.Flags().IntVar(&agentFailScore, "fail-score", 0, "CI gate: exit 1 if the post-AI Health Check score is below this threshold (0 = disabled)")
	agentCmd.Flags().StringVar(&agentHealthProfile, "health-profile", "", "Health Check policy profile: baseline, standard, strict")
	agentCmd.Flags().StringVar(&agentRuntime, "runtime", "container", "Where to run: container (default, full scanner bundle) or native (development only)")
	agentCmd.Flags().BoolVar(&agentProbeCompose, "probe-compose", false, "Also probe the service hosts declared in docker-compose files (opt-in; results describe the network, not the code, and are never scored)")
	agentCmd.Flags().StringVar(&agentConfirmedMinSeverity, "confirmed-min-severity", "", "With --fail-on confirmed: block only on confirmed findings at or above LOW, MEDIUM, HIGH or CRITICAL (default LOW: every confirmed finding blocks)")
	agentCmd.Flags().BoolVar(&agentFPCriticalRequiresHighConfidence, "fp-critical-requires-high-confidence", false, "Accept an AI false-positive verdict for a CRITICAL finding only when the model reports high confidence; otherwise keep it for manual review")
}

func runAgent(cmd *cobra.Command, args []string) error {
	if err := validateAgentFlags(); err != nil {
		return err
	}
	// Past flag validation every failure is about the run, not about how the
	// command was invoked: the full usage text would only bury the real error
	// (it used to follow every red CI run, policy failures included).
	cmd.SilenceUsage = true

	var err error
	switch agentRuntime {
	case "container", "":
		err = runAgentInContainer(cmd.Context(), cmd, args)
	case "native":
		err = runAgentNative(cmd, args)
	}
	var child *exitStatusError
	if errors.Is(err, ErrAuditIncomplete) || errors.Is(err, ErrPolicyViolation) || errors.As(err, &child) {
		// Execute reports these with the right exit status; cobra's own
		// "Error:" line would only repeat it.
		cmd.SilenceErrors = true
	}
	return err
}

// validateAgentFlags rejects flag values that cannot be acted on, before any
// work starts.
func validateAgentFlags() error {
	switch agentRuntime {
	case "container", "", "native":
	default:
		return fmt.Errorf("unsupported agent runtime %q: use container or native", agentRuntime)
	}
	if strings.TrimSpace(agentConfirmedMinSeverity) != "" {
		if _, ok := healthcheck.ParseConfirmedMinSeverity(agentConfirmedMinSeverity); !ok {
			return fmt.Errorf("invalid --confirmed-min-severity %q: use LOW, MEDIUM, HIGH or CRITICAL", agentConfirmedMinSeverity)
		}
	}
	return nil
}

func runAgentNative(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}
	ctx := cmd.Context()

	// Load config
	cfg := config.LoadConfig(projectPath)
	policy := agentPolicyFromFlags(cmd, cfg)

	// CLI flags override config file values
	llmCfg := cfg.LLM
	if agentProvider != "" {
		llmCfg.Provider = agentProvider
	}
	if agentModel != "" {
		llmCfg.Model = agentModel
	}
	if agentAPIKey != "" {
		llmCfg.APIKey = agentAPIKey
	}

	// Create LLM client
	client, err := llm.NewClient(llm.Config{
		Provider:        llmCfg.Provider,
		Model:           llmCfg.Model,
		APIKey:          llmCfg.APIKey,
		BaseURL:         llmCfg.BaseURL,
		Timeout:         llmCfg.Timeout,
		DisableThinking: llmCfg.DisableThinking,
	})
	if err != nil {
		return auditIncomplete(err)
	}

	fmt.Fprintf(os.Stderr, "🔍 AITriage Agent starting...\n\n")

	// Shared runner: the CLI and the local MCP host-agent workflow build the
	// same AgentState, run the same graph.Run, and compute the same gate.
	opts := pipeline.Options{
		ProjectPath: projectPath,
		Scan: pipeline.ScanOptions{
			ProbeHost:    agentProbe,
			RunExternal:  true,
			FullPortScan: agentFullScan,
			ProbeCompose: agentProbeCompose,
		},
		Policy: policy,
		LLM: pipeline.LLMIdentity{
			Provider:        llmCfg.Provider,
			Model:           llmCfg.Model,
			BaseURL:         llmCfg.BaseURL,
			DisableThinking: llmCfg.DisableThinking,
			BatchSize:       llmCfg.BatchSize,
		},
		Target: pipeline.Target{
			RuleID: agentRuleID,
			File:   agentTargetFile,
			Line:   agentTargetLine,
		},
	}

	// STEP 1: PARALLEL SCANNING
	fmt.Fprintf(os.Stderr, "📡 Step 1/3: Scanning (parallel)...\n")

	richResult := pipeline.Scan(ctx, opts)
	missingScanners := richResult.MissingRequiredScanners()
	coverage := "partial"
	if len(missingScanners) == 0 {
		coverage = "full"
	}
	if agentManifestOut != "" {
		manifest := struct {
			ScannerCoverage string                      `json:"scanner_coverage"`
			Scanners        []external.ScannerExecution `json:"scanners"`
		}{ScannerCoverage: coverage, Scanners: richResult.ScannerExecutions}
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return auditIncomplete(err)
		}
		if err := os.WriteFile(agentManifestOut, append(data, '\n'), 0o600); err != nil {
			return auditIncomplete(fmt.Errorf("write scanner manifest: %w", err))
		}
	}
	if agentSARIFOut != "" {
		// Findings a project decision dismissed are left out, as `aitriage
		// scan` leaves out audit-log dismissals.
		data, err := pipeline.SARIF(opts, richResult)
		if err != nil {
			return auditIncomplete(fmt.Errorf("build SARIF: %w", err))
		}
		if err := os.WriteFile(agentSARIFOut, data, 0o600); err != nil {
			return auditIncomplete(fmt.Errorf("write SARIF: %w", err))
		}
	}
	if os.Getenv("AITRIAGE_RUNTIME") == "container" {
		if len(missingScanners) > 0 {
			return auditIncomplete(fmt.Errorf("full audit aborted: required scanner execution(s) did not complete: %s", strings.Join(missingScanners, ", ")))
		}
	}

	fmt.Fprintf(os.Stderr, "   ✓ AITriage: %d findings\n", len(richResult.Report.Results))
	fmt.Fprintf(os.Stderr, "   ✓ External: %d findings\n", len(richResult.External))
	fmt.Fprintf(os.Stderr, "   ✓ NFR: %d issues\n", len(richResult.NFR))
	fmt.Fprintf(os.Stderr, "   ✓ Deploy: %d issues\n", len(richResult.Deploy))

	if agentProbe != "" || agentProbeCompose {
		fmt.Fprintf(os.Stderr, "   ✓ Network: %d ports open\n", len(richResult.Network))
	}
	fmt.Fprintf(os.Stderr, "   Health Check (pre-AI, core-only): %s (%d/100)\n\n", richResult.Report.SecurityGrade, richResult.Report.SecurityScore)

	if opts.Target.Enabled() {
		fmt.Fprintf(os.Stderr, "🎯 Targeted Mode: Focusing on finding %s in %s:%d\n\n", agentRuleID, agentTargetFile, agentTargetLine)
	}

	// STEP 2: LLM ANALYSIS (Map-Reduce Graph)
	fmt.Fprintf(os.Stderr, "🤖 Step 2/3: LLM Analysis (Map-Reduce)...\n")

	state := pipeline.BuildState(opts, richResult)

	// A provider failure during triage still yields a complete state: every
	// finding has a disposition (the unclassified ones marked triage-failed)
	// and the gate fails with triage_incomplete. Only an abort comes back
	// without one.
	_, runErr := pipeline.RunState(ctx, state, client)
	var incomplete *graph.TriageIncompleteError
	if runErr != nil && !errors.As(runErr, &incomplete) {
		return auditIncomplete(fmt.Errorf("LLM analysis failed: %w", runErr))
	}

	fmt.Fprintf(os.Stderr, "\n📝 FINAL REPORT:\n\n%s\n\n", state.ReportMarkdown)
	fmt.Fprintf(os.Stderr, "🛠 AI FIX SPECIFICATION:\n\n%s\n\n", state.AIFixSpec)

	// Persist artifacts to files when requested (CI/CD consumes these), also
	// when triage did not complete: the scan already ran and its findings are
	// exactly what the next person needs to look at.
	if err := writeAgentArtifacts(state); err != nil {
		return auditIncomplete(err)
	}

	// Auto-write actionable summary to GitHub Actions Step Summary.
	// The agent writes a clean, FP-free summary — workflows no longer need
	// to `cat report.md >> $GITHUB_STEP_SUMMARY`.
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		writeAgentGHASummary(state)
	}

	// STEP 3: INTERACTIVE CONSULTATION (pointless when the provider just failed)
	if !agentNoChat && incomplete == nil {
		fmt.Fprintf(os.Stderr, "💬 Step 3/3: Consultation mode (type 'exit' to quit)\n")

		messages := []llm.Message{
			{Role: "system", Content: "You are an expert security consultant. You have generated a report and fix spec. Answer the user's questions based on this context."},
			{Role: "user", Content: "Context: \nReport:\n" + state.ReportMarkdown + "\nFix Spec:\n" + state.AIFixSpec},
			{Role: "assistant", Content: "I have loaded the security context. How can I help you?"},
		}

		runConsultation(ctx, client, messages)
	}

	return agentOutcome(os.Stderr, state, incomplete)
}

// writeAgentArtifacts writes every requested output file from a finished run.
func writeAgentArtifacts(state *graph.AgentState) error {
	if agentReportOut != "" {
		if err := os.WriteFile(agentReportOut, []byte(state.ReportMarkdown), 0o600); err != nil {
			return fmt.Errorf("failed to write report to %s: %w", agentReportOut, err)
		}
		fmt.Fprintf(os.Stderr, "   ✓ Report written to %s\n", agentReportOut)
	}
	if agentFixSpecOut != "" {
		if err := os.WriteFile(agentFixSpecOut, []byte(state.AIFixSpec), 0o600); err != nil {
			return fmt.Errorf("failed to write fix spec to %s: %w", agentFixSpecOut, err)
		}
		fmt.Fprintf(os.Stderr, "   ✓ Fix spec written to %s\n", agentFixSpecOut)
	}
	if agentSummaryOut != "" {
		if err := os.WriteFile(agentSummaryOut, []byte(state.SummaryMarkdown), 0o600); err != nil {
			return fmt.Errorf("failed to write summary to %s: %w", agentSummaryOut, err)
		}
		fmt.Fprintf(os.Stderr, "   ✓ Summary written to %s\n", agentSummaryOut)
	}
	if agentTriageOut != "" {
		if err := writeTriageArtifact(agentTriageOut, state); err != nil {
			return fmt.Errorf("failed to write triage findings to %s: %w", agentTriageOut, err)
		}
		fmt.Fprintf(os.Stderr, "   ✓ Canonical triage findings written to %s\n", agentTriageOut)
	}
	return nil
}

// agentOutcome turns a finished run into the command result. An incomplete
// triage wins over the gate: its verdict is not authoritative, and CI must be
// able to tell "re-run when the provider is back" (status 2) from "fix the
// code" (status 1, ErrPolicyViolation). The gate cannot pass on an incomplete
// triage either way, unless fail_on is never.
func agentOutcome(w io.Writer, state *graph.AgentState, incomplete *graph.TriageIncompleteError) error {
	if incomplete != nil {
		_, _ = fmt.Fprintf(w, "\nAI triage did not complete: %s\nArtifacts were written; %d finding(s) without a verdict are marked triage-failed. Re-run once the LLM provider is available.\n",
			incomplete.Reason, incomplete.Unclassified)
		if !state.HealthCheck.Verdict.Passed {
			printPolicyFailure(w, state.HealthCheck.Verdict)
		}
		return auditIncomplete(incomplete)
	}
	// CI/CD GATE: decide the exit code from the post-AI Health Check verdict.
	// False Positives are already excluded from state.HealthCheck, so the gate
	// only trips on findings the AI triage considered real.
	if !state.HealthCheck.Verdict.Passed {
		printPolicyFailure(w, state.HealthCheck.Verdict)
		return ErrPolicyViolation
	}
	return nil
}

// agentEnvAllowlist names the variables forwarded into the agent container.
// Only names are passed (Docker reads the values), so secrets never reach
// argv. Tuning variables are included because a container run silently
// ignored them otherwise; host path variables (cache and reports
// directories) are deliberately absent: a host path means nothing inside the
// container, which gets its own mounts.
var agentEnvAllowlist = []string{
	"AITRIAGE_LLM_API_KEY",
	"AITRIAGE_LLM_PROVIDER",
	"AITRIAGE_LLM_MODEL",
	"AITRIAGE_LLM_BASE_URL",
	"AITRIAGE_LLM_DISABLE_THINKING",
	"AITRIAGE_LLM_TIMEOUT",
	"AITRIAGE_BATCH_SIZE",
	"AITRIAGE_CLASSIFY_RETRIES",
	"AITRIAGE_CONCURRENCY",
	"AITRIAGE_LLM_BUDGET",
	"AITRIAGE_POC_BUDGET",
	"AITRIAGE_GATING",
	"AITRIAGE_RESPECT_GITIGNORE",
	"AITRIAGE_SCAN_VENDORED",
	"GEMINI_API_KEY",
	"GOOGLE_API_KEY",
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"GROQ_API_KEY",
}

// agentContainerEnv is set inside the agent container. AITRIAGE_REPORTS_DIR
// names the writable reports mount, where the Web UI and IDE tools in the
// container record dismissals for the read-only project, so the run applies
// them.
var agentContainerEnv = []string{
	"AITRIAGE_RUNTIME=container",
	"AITRIAGE_CACHE_DIR=/workspace/aitriage-reports/cache",
	"AITRIAGE_REPORTS_DIR=/workspace/aitriage-reports",
}

func runAgentInContainer(ctx context.Context, cmd *cobra.Command, args []string) error {
	if agentAPIKey != "" {
		return fmt.Errorf("--api-key is not accepted in container mode because secrets must not appear in process arguments; set GEMINI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY, or AITRIAGE_LLM_API_KEY in the environment")
	}
	if err := requireContainerRuntime(ctx); err != nil {
		return err
	}

	project := "."
	if len(args) > 0 {
		project = args[0]
	}
	hostRoot, err := resolveProjectRoot([]string{project})
	if err != nil {
		return err
	}
	reports, err := ensureReportsDir(hostRoot)
	if err != nil {
		return err
	}
	cache, err := rt.EnsureScannerCacheDir()
	if err != nil {
		return err
	}
	if agentOutputsEmpty() {
		runDir := filepath.Join(reports, newCLIRunID())
		agentReportOut = filepath.Join(runDir, "report.md")
		agentFixSpecOut = filepath.Join(runDir, "fixspec.md")
		agentSummaryOut = filepath.Join(runDir, "summary.md")
		agentTriageOut = filepath.Join(runDir, "triage-findings.json")
		agentManifestOut = filepath.Join(runDir, "manifest.json")
		agentSARIFOut = filepath.Join(runDir, "aitriage.sarif")
		fmt.Fprintf(os.Stderr, "AITriage artifacts: %s\n", runDir)
	}

	inner, err := agentContainerCommandArgs(hostRoot)
	if err != nil {
		return err
	}
	name := managedContainerName("agent")
	dockerArgs := rt.DockerRunArgs(rt.RunSpec{
		Image:       rt.ResolveImage(Version),
		Name:        name,
		User:        rt.HostUser(),
		HostRoot:    hostRoot,
		ReportsDir:  reports,
		CacheDir:    cache,
		Interactive: !agentNoChat,
		TTY:         false,
		EnvPassed:   agentEnvAllowlist,
		EnvSet:      agentContainerEnv,
		Argv:        inner,
	})

	return containerExitStatus(runManagedContainer(ctx, dockerArgs, name))
}

// containerExitStatus passes the containerised agent's exit status through:
// 1 (policy violation) and 2 (audit incomplete) must reach CI unchanged, and
// the agent inside already printed why.
func containerExitStatus(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
		return &exitStatusError{code: exitErr.ExitCode()}
	}
	return err
}

// agentContainerCommandArgs reproduces the public agent flags for the native
// inner process. Secret values are intentionally absent; only allowlisted env
// names are forwarded by DockerRunArgs.
func agentContainerCommandArgs(hostRoot string) ([]string, error) {
	args := []string{"agent", "--runtime", "native"}
	appendStringFlag := func(name, value string) {
		if value != "" {
			args = append(args, name, value)
		}
	}
	appendStringFlag("--provider", agentProvider)
	appendStringFlag("--model", agentModel)
	if agentNoChat {
		args = append(args, "--no-chat")
	}
	appendStringFlag("--output", agentOutput)
	appendStringFlag("--probe", agentProbe)
	if agentFullScan {
		args = append(args, "--full-scan")
	}
	appendStringFlag("--rule-id", agentRuleID)
	if agentTargetFile != "" {
		mapped, err := containerProjectPath(hostRoot, agentTargetFile)
		if err != nil {
			return nil, fmt.Errorf("target file: %w", err)
		}
		appendStringFlag("--file", mapped)
	}
	if agentTargetLine > 0 {
		args = append(args, "--line", fmt.Sprint(agentTargetLine))
	}

	for _, output := range []struct {
		name string
		path string
	}{
		{"--report-out", agentReportOut},
		{"--fixspec-out", agentFixSpecOut},
		{"--summary-out", agentSummaryOut},
		{"--triage-out", agentTriageOut},
		{"--manifest-out", agentManifestOut},
		{"--sarif-out", agentSARIFOut},
	} {
		if output.path == "" {
			continue
		}
		mapped, err := containerReportPath(hostRoot, output.path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", output.name, err)
		}
		appendStringFlag(output.name, mapped)
	}
	appendStringFlag("--fail-on", agentFailOn)
	if agentFailScore > 0 {
		args = append(args, "--fail-score", fmt.Sprint(agentFailScore))
	}
	appendStringFlag("--health-profile", agentHealthProfile)
	if agentProbeCompose {
		args = append(args, "--probe-compose")
	}
	appendStringFlag("--confirmed-min-severity", agentConfirmedMinSeverity)
	if agentFPCriticalRequiresHighConfidence {
		args = append(args, "--fp-critical-requires-high-confidence")
	}
	args = append(args, ".")
	return args, nil
}

func agentOutputsEmpty() bool {
	return agentReportOut == "" && agentFixSpecOut == "" && agentSummaryOut == "" &&
		agentTriageOut == "" && agentManifestOut == "" && agentSARIFOut == ""
}

func newCLIRunID() string {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "run-" + time.Now().UTC().Format("20060102T150405") + "-cli"
	}
	return "run-" + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(suffix[:])
}

func containerProjectPath(hostRoot, path string) (string, error) {
	return rt.ContainerScanRoot(hostRoot, path)
}

func containerReportPath(hostRoot, path string) (string, error) {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(hostRoot, abs)
	}
	abs = filepath.Clean(abs)
	reports := filepath.Join(hostRoot, "aitriage-reports")
	rel, err := filepath.Rel(reports, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output must be inside %s", reports)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return "", err
	}
	resolvedReports, err := filepath.EvalSymlinks(reports)
	if err != nil {
		return "", err
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	parentRel, err := filepath.Rel(resolvedReports, resolvedParent)
	if err != nil || parentRel == ".." || strings.HasPrefix(parentRel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output path escapes %s through a symlink", reports)
	}
	if info, statErr := os.Lstat(abs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output file must not be a symlink: %s", abs)
	}
	return "/workspace/aitriage-reports/" + filepath.ToSlash(rel), nil
}

func agentPolicyFromFlags(cmd *cobra.Command, cfg *config.Config) healthcheck.Policy {
	policy := healthpolicy.FromConfig(cfg)
	if !healthpolicy.HasConfiguredGate(cfg) {
		policy.FailOn = healthcheck.FailOnNever
		policy.MinimumScore = 0
	}

	failOnSet := cmd.Flags().Changed("fail-on")
	failScoreSet := cmd.Flags().Changed("fail-score")
	policy = healthpolicy.ApplyOverrides(policy, healthpolicy.Overrides{
		Profile:                             agentHealthProfile,
		ProfileSet:                          cmd.Flags().Changed("health-profile"),
		FailOn:                              agentFailOn,
		FailOnSet:                           failOnSet,
		MinimumScore:                        agentFailScore,
		MinimumScoreSet:                     failScoreSet,
		ConfirmedMinSeverity:                agentConfirmedMinSeverity,
		ConfirmedMinSeveritySet:             cmd.Flags().Changed("confirmed-min-severity"),
		FPCriticalRequiresHighConfidence:    agentFPCriticalRequiresHighConfidence,
		FPCriticalRequiresHighConfidenceSet: cmd.Flags().Changed("fp-critical-requires-high-confidence"),
	})
	if failScoreSet && !failOnSet && policy.FailOn == healthcheck.FailOnNever {
		policy.FailOn = healthcheck.FailOnCritical
	}
	return healthcheck.NormalizePolicy(policy)
}

func runConsultation(ctx context.Context, client llm.Client, history []llm.Message) {
	scan := bufio.NewScanner(os.Stdin)
	fmt.Print("\n> ")
	for scan.Scan() {
		question := scan.Text()
		if question == "exit" || question == "quit" {
			break
		}
		if question == "" {
			fmt.Print("> ")
			continue
		}
		history = append(history, llm.Message{
			Role:    "user",
			Content: question,
		})
		answer, _, err := client.Chat(ctx, history)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			history = append(history, llm.Message{Role: "assistant", Content: answer})
			fmt.Println(answer)
		}
		fmt.Print("\n> ")
	}
}

// writeAgentGHASummary writes the actionable summary (TP/NR only) to the
// GitHub Actions Step Summary. This runs automatically when GITHUB_ACTIONS=true,
// so workflows no longer need to `cat report.md >> $GITHUB_STEP_SUMMARY`.
func writeAgentGHASummary(state *graph.AgentState) {
	summaryFile := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryFile == "" {
		return
	}
	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ⚠ Failed to write GHA Step Summary: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(state.SummaryMarkdown)
	fmt.Fprintf(os.Stderr, "   ✓ GHA Step Summary written (actionable findings only)\n")
}
