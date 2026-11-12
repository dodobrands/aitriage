// Package hostrun coordinates the deferred host-agent triage workflow. It is
// the neutral, transport-independent core that the MCP run tools call: it owns
// the run store, drives the shared pipeline through the deferred host-agent
// llm.Client, and advances the run one host answer at a time.
//
// The MCP layer (internal/agent/mcp) is a thin adapter over this package, so
// the whole workflow is unit- and integration-testable without any transport.
package hostrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/hostagent"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/pipeline"
	"github.com/dodobrands/aitriage/internal/agent/runstore"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// Manager owns one project's run store and executes host-agent runs.
type Manager struct {
	store   *runstore.Store
	version string
}

// NewManager binds a manager to a canonical project root. version is the running
// AITriage build identity, recorded in each run manifest for compatibility.
func NewManager(projectRoot, version string) (*Manager, error) {
	s, err := runstore.NewStore(projectRoot)
	if err != nil {
		return nil, err
	}
	if version == "" {
		version = "dev"
	}
	return &Manager{store: s, version: version}, nil
}

// StartOptions configures a new run.
type StartOptions struct {
	// ProjectPath is the selected project or subproject to scan. Empty means the
	// manager's confined root. It must resolve inside that root.
	ProjectPath string
	Scan        pipeline.ScanOptions
	Target      pipeline.Target
	Policy      healthcheck.Policy
	LLM         pipeline.LLMIdentity
	HostClient  string // "codex" | "claude-code"
	// Intent is the user's declared intent: "audit" (default) or "audit_and_fix".
	// It must come only from the actual user command and is never auto-escalated.
	Intent string
	// RequireFullScanners fails the run closed (before AI triage) if any mandatory
	// external scanner did not run. It is set for the container runtime, where the
	// full scanner bundle is guaranteed; native/dev mode leaves it false and the
	// run is recorded as "partial" coverage rather than a full audit.
	RequireFullScanners bool
}

// snapshot is the deterministic input persisted at scan time so a run rebuilds
// an identical AgentState on every replay pass.
type snapshot struct {
	ProjectPath string               `json:"project_path"`
	Scan        pipeline.ScanOptions `json:"scan"`
	Target      pipeline.Target      `json:"target"`
	LLM         pipeline.LLMIdentity `json:"llm"`
	Rich        llm.RichScanResult   `json:"rich"`
}

// PendingRequest is the exact next request the host agent must answer. Identity
// is RequestID (a content fingerprint); Ordinal is a display-only discovery
// index. Multiple requests may be pending at once when graph.Run classified
// batches in parallel; the manager surfaces them one deterministic request at a
// time, and PendingTotal reports how many remain.
type PendingRequest struct {
	RequestID    string        `json:"request_id"`
	Ordinal      int           `json:"ordinal"`
	Messages     []llm.Message `json:"messages"`
	NextStep     string        `json:"next_step"`
	PendingTotal int           `json:"pending_total"`
}

// FinalResult is produced once graph.Run completes and artifacts are written.
type FinalResult struct {
	Gate          healthcheck.Verdict `json:"gate"`
	Health        healthcheck.Result  `json:"health"`
	TriageStatus  string              `json:"triage_status"`
	ArtifactPaths map[string]string   `json:"artifact_paths"`
	// ScannerCoverage is "full" when every required external scanner ran, else
	// "partial". MissingScanners lists any mandatory scanner that did not run.
	ScannerCoverage string   `json:"scanner_coverage,omitempty"`
	MissingScanners []string `json:"missing_scanners,omitempty"`
	// FixableFindingIDs are the canonical IDs the user may approve for fixing —
	// confirmed True Positives only (never FP or Needs Manual Review).
	FixableFindingIDs []string `json:"fixable_finding_ids"`
	// VerifiedTP is set on a verification result: approved TP ID -> "resolved" |
	// "still_present". AllApprovedResolved is true only when every approved TP is
	// resolved. The overall project Gate is reported separately above.
	VerifiedTP          map[string]string `json:"verified_tp,omitempty"`
	AllApprovedResolved bool              `json:"all_approved_resolved,omitempty"`
}

// FixContext is the self-contained handoff returned once a run is approved for
// fixing. The host agent needs nothing else — no file hunting, no chat memory —
// to follow the existing AI Remediation Prompt and then verify.
type FixContext struct {
	SummaryPath   string   `json:"summary_path"`
	FixSpecPath   string   `json:"fixspec_path"`
	TriagePath    string   `json:"triage_path"`
	ApprovedTPIDs []string `json:"approved_tp_ids"`
	NextAction    string   `json:"next_action"`
}

// Progress is the uniform response of every workflow step.
type Progress struct {
	RunID   string          `json:"run_id"`
	Status  runstore.Status `json:"status"`
	Pending *PendingRequest `json:"pending_request,omitempty"`
	Result  *FinalResult    `json:"result,omitempty"`
	Fix     *FixContext     `json:"fix_context,omitempty"`
	Turns   int             `json:"turns"`
	Note    string          `json:"note,omitempty"`
}

const fixNextAction = "follow_ai_remediation_prompt_then_verify"

// fixContext builds the handoff for a run in the fixing state.
func fixContext(runID string, approvedTP []string) *FixContext {
	return &FixContext{
		SummaryPath:   artifactRelPath(runID, "summary.md"),
		FixSpecPath:   artifactRelPath(runID, "fixspec.md"),
		TriagePath:    artifactRelPath(runID, "triage-findings.json"),
		ApprovedTPIDs: approvedTP,
		NextAction:    fixNextAction,
	}
}

// Start scans the project, persists the deterministic snapshot, and advances
// the pipeline to the first host request (or straight to the final result if
// graph.Run needed no model calls).
func (m *Manager) Start(ctx context.Context, opts StartOptions) (*Progress, error) {
	run, err := m.create(ctx, opts, "")
	if err != nil {
		return nil, err
	}
	return m.advance(ctx, run)
}

// startLinked creates a verification run linked to parentRunID and advances it.
func (m *Manager) startLinked(ctx context.Context, opts StartOptions, parentRunID string) (*Progress, error) {
	run, err := m.create(ctx, opts, parentRunID)
	if err != nil {
		return nil, err
	}
	if err := run.SetLink("verification", parentRunID); err != nil {
		return nil, err
	}
	return m.advance(ctx, run)
}

// create scans the project and persists the deterministic snapshot for a new
// run. parentRunID is empty for a triage run and set for a verification run.
func (m *Manager) create(ctx context.Context, opts StartOptions, parentRunID string) (*runstore.Run, error) {
	projectPath, err := m.resolveProjectPath(opts.ProjectPath)
	if err != nil {
		return nil, err
	}
	// The local host-agent workflow is defined to be equivalent to CI, so the
	// full external scanner set is always run: RunExternal is forced on and can
	// never be silently zero-valued off by a caller.
	scan := opts.Scan
	scan.RunExternal = true

	pipeOpts := pipeline.Options{
		ProjectPath: projectPath,
		Scan:        scan,
		Policy:      opts.Policy,
		LLM:         opts.LLM,
		Target:      opts.Target,
	}
	rich := pipeline.Scan(ctx, pipeOpts)

	git := runstore.CollectGitInfo(projectPath)
	run, err := m.store.Create(opts.HostClient, m.currentVersions(), opts.Policy, git, opts.Intent)
	if err != nil {
		return nil, err
	}
	cacheDir := m.effectiveCacheDir()
	ensureCacheEnv(cacheDir)
	_ = run.SetCacheDir(cacheDir)

	// Scanner execution manifest — record exactly what ran BEFORE any AI triage.
	missing := rich.MissingRequiredScanners()
	coverage := "full"
	if len(missing) > 0 {
		coverage = "partial"
	}
	_ = run.SetScanners(rich.ScannerExecutions, coverage)
	// Fail-closed: in a mode that guarantees the full bundle (container runtime),
	// a missing/failed mandatory scanner is a hard error and never proceeds to AI
	// triage — a partial scan must not be presented as a full audit.
	if opts.RequireFullScanners && len(missing) > 0 {
		_ = run.Fail(fmt.Sprintf("incomplete scanner bundle: %s did not run", strings.Join(missing, ", ")))
		_ = run.AppendAudit(runstore.AuditEvent{Event: "scanner_bundle_incomplete", Status: run.Status(), Note: strings.Join(missing, ",")})
		return nil, fmt.Errorf("full audit aborted: required scanner(s) not available: %s. Run `aitriage setup --full` to install the scanner runtime", strings.Join(missing, ", "))
	}

	snap := snapshot{ProjectPath: projectPath, Scan: scan, Target: opts.Target, LLM: opts.LLM, Rich: rich}
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	if err := run.SaveScan(data); err != nil {
		return nil, err
	}

	// Deterministic evidence: persist the same aitriage.sarif that
	// `aitriage agent --sarif-out` writes, from the raw scan report without
	// the findings project decisions dismissed. This is separate from AI
	// triage and is written once at scan time.
	if sarif, serr := pipeline.SARIF(pipeOpts, rich); serr == nil {
		_ = run.WriteArtifact("aitriage.sarif", sarif)
	}
	return run, nil
}

// Submit validates and stores a host answer, then advances the pipeline.
func (m *Manager) Submit(ctx context.Context, runID string, resp hostagent.Response) (*Progress, error) {
	run, err := m.store.Open(runID)
	if err != nil {
		return nil, err
	}
	if run.Status().IsTerminalPublic() {
		return m.statusOf(run)
	}
	resp.RunID = runID
	if err := run.SaveResponse(resp); err != nil {
		return nil, err
	}
	return m.advance(ctx, run)
}

// Continue resumes a run without accepting a new response (e.g. after an MCP
// restart). It replays confirmed answers and stops at the next missing one.
func (m *Manager) Continue(ctx context.Context, runID string) (*Progress, error) {
	run, err := m.store.Open(runID)
	if err != nil {
		return nil, err
	}
	return m.advance(ctx, run)
}

// Status returns the current run state without executing the pipeline.
func (m *Manager) Status(runID string) (*Progress, error) {
	run, err := m.store.Open(runID)
	if err != nil {
		return nil, err
	}
	return m.statusOf(run)
}

// advance rebuilds state from the snapshot and runs graph.Run through the
// deferred client, translating its outcome into a Progress.
func (m *Manager) advance(ctx context.Context, run *runstore.Run) (*Progress, error) {
	if run.Status().IsTerminalPublic() {
		return m.statusOf(run)
	}

	data, ok, err := run.LoadScan()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("run %s has no scan snapshot", run.ID())
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("decode scan snapshot: %w", err)
	}

	projectPath, err := m.resolveProjectPath(snap.ProjectPath)
	if err != nil {
		return nil, fmt.Errorf("run %s project path: %w", run.ID(), err)
	}
	pipeOpts := pipeline.Options{
		ProjectPath: projectPath,
		Scan:        snap.Scan,
		Policy:      run.Manifest().Policy,
		LLM:         snap.LLM,
		Target:      snap.Target,
	}
	state := pipeline.BuildState(pipeOpts, snap.Rich)

	// Resume-safe: re-point the shared cache at the run's recorded cache dir so a
	// fresh process (or MCP restart) uses the same verdict/artifact cache.
	if cd := run.CacheDir(); cd != "" {
		ensureCacheEnv(cd)
	} else {
		ensureCacheEnv(m.effectiveCacheDir())
	}

	stateFP := stateFingerprint(data)
	client := hostagent.New(run.ID(), stateFP, run)

	_ = run.SetStatus(runstore.StatusTriaging)

	res, err := pipeline.RunState(ctx, state, client)
	if err != nil {
		if awaiting, ok := hostagent.IsAwaiting(err); ok {
			if serr := run.SetStatus(runstore.StatusAwaitingAgent); serr != nil {
				return nil, serr
			}
			_ = run.AppendAudit(runstore.AuditEvent{Event: "awaiting_agent", Status: run.Status(), RequestID: awaiting.RequestID})
			return m.pendingProgress(run, awaiting)
		}
		// Real failure: record it safely and fail the run closed.
		_ = run.Fail(err.Error())
		_ = run.AppendAudit(runstore.AuditEvent{Event: "failed", Status: run.Status(), Note: "host-agent triage failed"})
		return nil, fmt.Errorf("host-agent triage failed: %w", err)
	}

	return m.finalize(run, res)
}

// finalize writes the canonical artifacts and moves the run to the approval
// gate. An incomplete triage can never reach this path because graph.Run only
// returns nil after every validated stage.
func (m *Manager) finalize(run *runstore.Run, res *pipeline.Result) (*Progress, error) {
	if err := run.SetStatus(runstore.StatusFinalized); err != nil {
		return nil, err
	}

	artifact, err := res.Artifact()
	if err != nil {
		_ = run.Fail(err.Error())
		return nil, err
	}
	triageJSON, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return nil, err
	}
	// CI-parity artifact names: identical to `aitriage agent` outputs, no aliases.
	writes := []struct {
		name string
		data []byte
	}{
		{"triage-findings.json", append(triageJSON, '\n')},
		{"report.md", []byte(res.Report)},
		{"summary.md", []byte(res.Summary)},
		{"fixspec.md", []byte(res.FixSpec)},
	}
	for _, w := range writes {
		if err := run.WriteArtifact(w.name, w.data); err != nil {
			return nil, err
		}
	}

	// A verification run does not re-enter the approval gate: it records the
	// after-fix gate into its parent and both runs complete.
	if run.Manifest().Kind == "verification" {
		return m.finalizeVerification(run, res)
	}

	// The user now decides whether to fix; source is never touched before that.
	if err := run.SetStatus(runstore.StatusAwaitingUserApproval); err != nil {
		return nil, err
	}
	_ = run.AppendAudit(runstore.AuditEvent{Event: "finalized", Status: run.Status(), Note: artifact.TriageStatus})

	fixable := fixableIDs(res.State)
	mf := run.Manifest()
	final := &FinalResult{
		Gate:              res.Gate,
		Health:            res.Health,
		TriageStatus:      artifact.TriageStatus,
		ScannerCoverage:   mf.ScannerCoverage,
		MissingScanners:   scannerCoverageGaps(mf.Scanners),
		FixableFindingIDs: fixable,
		ArtifactPaths: map[string]string{
			"triage":  artifactRelPath(run.ID(), "triage-findings.json"),
			"report":  artifactRelPath(run.ID(), "report.md"),
			"summary": artifactRelPath(run.ID(), "summary.md"),
			"fixspec": artifactRelPath(run.ID(), "fixspec.md"),
			"sarif":   artifactRelPath(run.ID(), "aitriage.sarif"),
		},
	}
	// audit_and_fix: the user's single command IS the approval. Auto-approve the
	// confirmed True Positives (only), so the host receives the fix context in one
	// step. With no TP there is nothing to fix — stay at the approval gate.
	if run.Intent() == "audit_and_fix" && len(fixable) > 0 {
		appr, err := m.Approve(run.ID(), fixable)
		if err != nil {
			return nil, err
		}
		appr.Result = final
		return appr, nil
	}

	return &Progress{
		RunID:  run.ID(),
		Status: run.Status(),
		Result: final,
		Turns:  run.Manifest().Turns,
	}, nil
}

func (m *Manager) pendingProgress(run *runstore.Run, awaiting *hostagent.ErrAwaitingHostResponse) (*Progress, error) {
	req, ok, err := run.PendingRequest()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("run %s is awaiting a response but no pending request was found", run.ID())
	}
	total, err := run.PendingCount()
	if err != nil {
		return nil, err
	}
	return &Progress{
		RunID:  run.ID(),
		Status: run.Status(),
		Turns:  run.Manifest().Turns,
		Pending: &PendingRequest{
			RequestID:    req.RequestID,
			Ordinal:      req.Ordinal,
			Messages:     req.Messages,
			NextStep:     awaiting.NextStep,
			PendingTotal: total,
		},
	}, nil
}

func (m *Manager) statusOf(run *runstore.Run) (*Progress, error) {
	p := &Progress{RunID: run.ID(), Status: run.Status(), Turns: run.Manifest().Turns}
	// In fixing/verifying, return the self-contained fix context so the host can
	// resume after a restart without hunting for files or recalling chat.
	if run.Status() == runstore.StatusFixing || run.Status() == runstore.StatusVerifying {
		if ab, ok, _ := run.ReadArtifact("approval.json"); ok {
			var a Approval
			if json.Unmarshal(ab, &a) == nil {
				p.Fix = fixContext(run.ID(), a.SelectedIDs)
			}
		}
	}
	if req, ok, err := run.PendingRequest(); err != nil {
		return nil, err
	} else if ok && run.Status() == runstore.StatusAwaitingAgent {
		total, err := run.PendingCount()
		if err != nil {
			return nil, err
		}
		p.Pending = &PendingRequest{
			RequestID:    req.RequestID,
			Ordinal:      req.Ordinal,
			Messages:     req.Messages,
			NextStep:     req.NextStep,
			PendingTotal: total,
		}
	}
	return p, nil
}

// scannerCoverageGaps lists mandatory scanners whose recorded status is not a
// success (completed / not_applicable), for user-facing coverage reporting.
func scannerCoverageGaps(execs []external.ScannerExecution) []string {
	var gaps []string
	for _, e := range execs {
		switch e.Status {
		case external.StatusCompleted, external.StatusNotApplicable:
		default:
			gaps = append(gaps, e.Scanner+":"+string(e.Status))
		}
	}
	return gaps
}

// artifactRelPath is the single source of truth for a run artifact's
// project-relative path. All AITriage scan/run artifacts live under
// aitriage-reports/; nothing is written to or reported from .aitriage/.
func artifactRelPath(runID, name string) string {
	return "aitriage-reports/" + runID + "/" + name
}

// effectiveCacheDir returns the verdict/artifact cache directory for a run.
// It honours a user-provided cache-dir env override (parity with how CI enables
// caching) and otherwise defaults to <root>/aitriage-reports/cache — never
// .aitriage/ and never a parallel cache implementation.
func (m *Manager) effectiveCacheDir() string {
	for _, k := range []string{"AITRIAGE_CACHE_DIR", "AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return filepath.Join(m.store.ProjectRoot(), "aitriage-reports", "cache")
}

// resolveProjectPath canonicalizes a selected subproject and confines it to the
// manager root. The MCP PathGuard performs the first check; this second check
// keeps the transport-independent manager safe for direct callers and replay.
func (m *Manager) resolveProjectPath(input string) (string, error) {
	root := m.store.ProjectRoot()
	input = strings.TrimSpace(input)
	if input == "" || input == "." {
		return root, nil
	}
	candidate := input
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("project path %q is not accessible", input)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("project path %q escapes the configured root", input)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("project path %q is not a directory", input)
	}
	return resolved, nil
}

func (m *Manager) projectPathForRun(run *runstore.Run) (string, error) {
	data, ok, err := run.LoadScan()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("run %s has no scan snapshot", run.ID())
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return "", fmt.Errorf("decode scan snapshot: %w", err)
	}
	return m.resolveProjectPath(snap.ProjectPath)
}

// ensureCacheEnv points the shared graph verdict/artifact cache at cacheDir for
// this process, unless the environment already selects a cache dir. This reuses
// the exact CI cache code (which reads AITRIAGE_CACHE_DIR) rather than a new
// cache path.
func ensureCacheEnv(cacheDir string) {
	for _, k := range []string{"AITRIAGE_CACHE_DIR", "AITRIAGE_VERDICT_CACHE_DIR", "AITRIAGE_ARTIFACT_CACHE_DIR"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return // respect an explicit user/CI override
		}
	}
	_ = os.Setenv("AITRIAGE_CACHE_DIR", cacheDir)
}

func stateFingerprint(snapshotBytes []byte) string {
	sum := sha256.Sum256(snapshotBytes)
	return hex.EncodeToString(sum[:])
}

func (m *Manager) currentVersions() runstore.Versions {
	pv := hostagent.CurrentPromptVersions()
	return runstore.Versions{
		AITriage:     m.version,
		ScannerOrch:  "run-all-scanners-v1",
		SecureCoder:  pv.SecureCoder,
		Graph:        fmt.Sprintf("triage-schema-%d/%s/%s/%s", graph.TriageArtifactSchemaVersion, pv.PoC, pv.Report, pv.FixSpec),
		TriageSchema: graph.TriageArtifactSchemaVersion,
	}
}

// fixableIDs returns the canonical IDs of confirmed True Positives only. The
// Operating Contract authorises implementing fixes ONLY for TP; False Positives
// and Needs Manual Review findings are never auto-fixable.
func fixableIDs(state *graph.AgentState) []string {
	if state == nil {
		return nil
	}
	var ids []string
	for _, d := range state.FindingDispositions {
		if d.Disposition != "True Positive" {
			continue
		}
		id := d.FindingID
		if id == "" && d.FindingIndex >= 0 && d.FindingIndex < len(state.EnrichedFindings) {
			id = state.EnrichedFindings[d.FindingIndex].VulnID
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
