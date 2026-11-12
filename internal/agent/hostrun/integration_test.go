package hostrun

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/hostagent"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/pipeline"
	"github.com/dodobrands/aitriage/internal/agent/runstore"
	"github.com/dodobrands/aitriage/internal/engine/history"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner"
)

// fakeHost answers deferred SecureCoder requests the way a host coding agent's
// model would, delegating purely off the request messages. It leaves every
// finding for manual review so the graph completes without PoC turns, which
// keeps the integration deterministic while still exercising every real stage
// (threat model, classification, report, fix spec) through the deferred client.
func fakeHostAnswer(messages []llm.Message) string {
	system := ""
	user := ""
	if len(messages) > 0 {
		system = messages[0].Content
	}
	if len(messages) > 1 {
		user = messages[len(messages)-1].Content
	}

	switch {
	case strings.Contains(system, "Threat Model & Finding Classification"):
		return `{"component_overview":"test app","priority_areas":["input handling"]}`
	case strings.Contains(system, "Finding Classification"):
		return classifyAllForReview(user)
	case strings.Contains(system, "PoC Verification"):
		return `[]`
	default:
		// Report / summary / fix spec are free-form markdown.
		return "## Security Report\n\n### Summary\nNo exploitable issues confirmed.\n\nAll reviewed findings were left for manual review.\n"
	}
}

// classifyAllForReview builds a valid finding_dispositions response leaving
// every finding in the classification prompt for manual review. The answer
// must be one the triage accepts: a reply that classifies nothing (or only
// unverifiable False Positives) leaves the triage incomplete. The rationale
// quotes the fixture's credential, as a model reviewing it would, and the
// verdict cache never stores such a verdict: runs in this package share one
// cache directory once the manager sets it, and must not reuse each other's
// verdicts.
func classifyAllForReview(user string) string {
	marker := strings.Index(user, "## Findings to classify")
	if marker < 0 {
		return `{"finding_dispositions":[]}`
	}
	start := strings.Index(user[marker:], "[")
	if start < 0 {
		return `{"finding_dispositions":[]}`
	}
	dec := json.NewDecoder(strings.NewReader(user[marker+start:]))
	var items []map[string]any
	_ = dec.Decode(&items)

	var sb strings.Builder
	sb.WriteString(`{"finding_dispositions":[`)
	for i, it := range items {
		if i > 0 {
			sb.WriteString(",")
		}
		fid, _ := it["finding_id"].(string)
		fp, _ := it["fingerprint"].(string)
		b, _ := json.Marshal(map[string]any{
			"finding_index": i,
			"finding_id":    fid,
			"fingerprint":   fp,
			"disposition":   "Needs Manual Review",
			"confidence":    "medium",
			"rationale":     "a person should confirm whether AKIAIOSFODNN7EXAMPLE is a live credential",
		})
		sb.Write(b)
	}
	sb.WriteString("]}")
	return sb.String()
}

// drive runs a workflow to a terminal-ish point, answering every deferred
// request via the fake host. It stops when there is no pending request.
func drive(t *testing.T, m *Manager, first *Progress) *Progress {
	t.Helper()
	prog := first
	for i := 0; i < 200; i++ {
		if prog.Pending == nil {
			return prog
		}
		ans := fakeHostAnswer(prog.Pending.Messages)
		next, err := m.Submit(context.Background(), prog.RunID, hostagent.Response{
			RequestID: prog.Pending.RequestID,
			Content:   ans,
		})
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
		prog = next
	}
	t.Fatal("workflow did not converge within turn budget")
	return nil
}

func newProjectWithFinding(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// A lockfile keeps the deterministic hygiene rules quiet; the .js file carries
	// a hardcoded secret so there is at least one finding to triage.
	must(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{}`), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte("const k = \"AKIA"+"Z7Q4XWVB3NMK2PLT\";\n"), 0o644))
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagerSelectsConfinedSubproject(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "synthetic", "fastapi-terrible")
	sibling := filepath.Join(root, "synthetic", "nextjs-terrible")
	must(t, os.MkdirAll(selected, 0o755))
	must(t, os.MkdirAll(sibling, 0o755))
	must(t, os.WriteFile(filepath.Join(selected, "app.py"), []byte("FASTAPI_ONLY_MARKER = 'AKIA"+"Z7Q4XWVB3NMK2PLT'\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(sibling, "app.js"), []byte("const NEXTJS_ONLY_MARKER = 'AKIA"+"Z7Q4XWVB3NMK2PLT';\n"), 0o644))

	m, err := NewManager(root, "test")
	if err != nil {
		t.Fatal(err)
	}
	start, err := m.Start(context.Background(), StartOptions{
		ProjectPath: filepath.Join("synthetic", "fastapi-terrible"),
		HostClient:  "codex",
		Policy:      healthcheck.DefaultPolicy(),
		Scan:        pipeline.ScanOptions{RunExternal: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if start.Pending == nil {
		t.Fatalf("expected a deferred SecureCoder request, got status %s", start.Status)
	}

	var prompt strings.Builder
	for _, msg := range start.Pending.Messages {
		prompt.WriteString(msg.Content)
	}
	if !strings.Contains(prompt.String(), "FASTAPI_ONLY_MARKER") {
		t.Fatal("selected subproject content is missing from the SecureCoder request")
	}
	if strings.Contains(prompt.String(), "NEXTJS_ONLY_MARKER") {
		t.Fatal("sibling project leaked into the selected subproject SecureCoder request")
	}

	run, err := m.store.Open(start.RunID)
	if err != nil {
		t.Fatal(err)
	}
	gotProject, err := m.projectPathForRun(run)
	if err != nil {
		t.Fatal(err)
	}
	wantProject, err := filepath.EvalSymlinks(selected)
	if err != nil {
		t.Fatal(err)
	}
	if gotProject != wantProject {
		t.Fatalf("run selected project = %q, want %q", gotProject, wantProject)
	}
	if _, err := os.Stat(filepath.Join(root, "aitriage-reports", start.RunID)); err != nil {
		t.Fatalf("run bundle must live under root aitriage-reports: %v", err)
	}
	if _, err := os.Stat(filepath.Join(selected, "aitriage-reports")); !os.IsNotExist(err) {
		t.Fatalf("selected subproject must not receive a second reports directory (err=%v)", err)
	}
}

func TestManagerRejectsSubprojectEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	m, err := NewManager(root, "test")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"../", outside} {
		if _, err := m.resolveProjectPath(path); err == nil {
			t.Errorf("resolveProjectPath(%q) must reject a path outside the configured root", path)
		}
	}

	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := m.resolveProjectPath("escape"); err == nil {
		t.Error("resolveProjectPath must reject a symlink escape")
	}
}

// TestHostRunFullLifecycle is the keystone integration test: a full deferred
// run completes through every SecureCoder stage answered by the fake host,
// finalizes with a canonical artifact + gate, reaches the approval gate, and a
// linked verification run completes after approval.
func TestHostRunFullLifecycle(t *testing.T) {
	dir := newProjectWithFinding(t)
	m, err := NewManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	start, err := m.Start(context.Background(), StartOptions{
		HostClient: "codex",
		Policy:     healthcheck.DefaultPolicy(),
		Scan:       pipeline.ScanOptions{RunExternal: false},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if start.Pending == nil {
		t.Fatal("expected at least one deferred request for a project with findings")
	}
	// The deferred request must carry the exact, non-empty SecureCoder prompt.
	if len(start.Pending.Messages) == 0 || start.Pending.Messages[0].Content == "" {
		t.Fatal("pending request has empty prompt (host would get nothing to answer)")
	}

	final := drive(t, m, start)
	if final.Result == nil {
		t.Fatalf("run did not finalize: status=%s", final.Status)
	}
	if final.Status != "awaiting_user_approval" {
		t.Fatalf("finalized run should await approval, got %s", final.Status)
	}
	// Canonical artifact + gate must be present.
	if _, ok, _ := openArtifact(t, m, final.RunID, "triage-findings.json"); !ok {
		t.Fatal("triage-findings.json artifact missing")
	}

	// summary.md must carry the SAME full AI Remediation Prompt / Operating
	// Contract as CI — the host follows it, not a rewritten prompt.
	summary := mustArtifact(t, m, final.RunID, "summary.md")
	for _, marker := range []string{"AI Remediation Prompt", "OPERATING CONTRACT", "Phase 0"} {
		if !strings.Contains(string(summary), marker) {
			t.Errorf("summary.md missing Operating Contract marker %q", marker)
		}
	}

	// Approval boundary: unknown IDs rejected.
	if _, err := m.Approve(final.RunID, []string{"NOT-A-REAL-ID"}); err == nil {
		t.Fatal("Approve must reject an unknown finding ID")
	}

	// Approve with the fixable TP set (may be empty when there are no TP) → fixing,
	// and the response must carry a self-contained fix context.
	appr, err := m.Approve(final.RunID, final.Result.FixableFindingIDs)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if appr.Status != "fixing" {
		t.Fatalf("after approval status = %s, want fixing", appr.Status)
	}
	if appr.Fix == nil || appr.Fix.SummaryPath == "" || appr.Fix.FixSpecPath == "" || appr.Fix.NextAction == "" {
		t.Fatalf("approve must return a self-contained fix context, got %+v", appr.Fix)
	}
	// The edit must happen after approval. Verification rejects retroactive or
	// absent source changes, so write a deterministic post-approval fix marker.
	must(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte("const k = process.env.APP_KEY;\n"), 0o644))

	// Verify starts a linked run; drive it to completion.
	vstart, err := m.Verify(context.Background(), final.RunID, StartOptions{Policy: healthcheck.DefaultPolicy()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	vfinal := drive(t, m, vstart)
	if vfinal.Status != "completed" {
		t.Fatalf("verification run status = %s, want completed", vfinal.Status)
	}
	// Parent verification.json recorded.
	if _, ok, _ := openArtifact(t, m, final.RunID, "verification.json"); !ok {
		t.Fatal("parent verification.json missing after verify")
	}
}

// TestApproveRequiresGate proves approval is rejected outside the approval gate.
func TestApproveRequiresGate(t *testing.T) {
	dir := newProjectWithFinding(t)
	m, _ := NewManager(dir, "test")
	start, err := m.Start(context.Background(), StartOptions{Policy: healthcheck.DefaultPolicy(), Scan: pipeline.ScanOptions{RunExternal: false}})
	if err != nil {
		t.Fatal(err)
	}
	// While still awaiting the agent, approval must fail.
	if start.Pending != nil {
		if _, err := m.Approve(start.RunID, nil); err == nil {
			t.Fatal("Approve must fail before the run reaches the approval gate")
		}
	}
}

// TestVerifyRequiresApproval proves verification cannot run without an approval
// record (no source-change verification without a recorded user decision).
func TestVerifyRequiresApproval(t *testing.T) {
	dir := newProjectWithFinding(t)
	m, _ := NewManager(dir, "test")
	start, _ := m.Start(context.Background(), StartOptions{Policy: healthcheck.DefaultPolicy(), Scan: pipeline.ScanOptions{RunExternal: false}})
	final := drive(t, m, start)
	if final.Result == nil {
		t.Skip("run needed no triage turns; not applicable")
	}
	if _, err := m.Verify(context.Background(), final.RunID, StartOptions{Policy: healthcheck.DefaultPolicy()}); err == nil {
		t.Fatal("Verify must fail without an approval record")
	}
}

// TestApproveRejectsProjectDriftSinceAudit proves approval can never be
// back-dated after an agent has already edited source. The user must approve
// the exact audited tree before any modification.
func TestApproveRejectsProjectDriftSinceAudit(t *testing.T) {
	dir := newProjectWithFinding(t)
	m, err := NewManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	start, err := m.Start(context.Background(), StartOptions{Policy: healthcheck.DefaultPolicy(), Scan: pipeline.ScanOptions{RunExternal: false}})
	if err != nil {
		t.Fatal(err)
	}
	final := drive(t, m, start)
	if final.Status != runstore.StatusAwaitingUserApproval {
		t.Fatalf("status = %s, want awaiting approval", final.Status)
	}
	must(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte("const k = process.env.APP_KEY;\n"), 0o644))

	if _, err := m.Approve(final.RunID, final.Result.FixableFindingIDs); err == nil || !strings.Contains(err.Error(), "changed after audit") {
		t.Fatalf("retroactive approval error = %v, want source-drift rejection", err)
	}
	run, err := m.store.Open(final.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status() != runstore.StatusAwaitingUserApproval {
		t.Fatalf("rejected approval changed status to %s", run.Status())
	}
	if _, ok, err := run.ReadArtifact("approval.json"); err != nil || ok {
		t.Fatalf("rejected approval created approval.json: ok=%v err=%v", ok, err)
	}
}

// TestVerifyRejectsNoPostApprovalChanges proves a verification run cannot
// claim success when the project tree is byte-identical to the approved tree.
func TestVerifyRejectsNoPostApprovalChanges(t *testing.T) {
	dir := newProjectWithFinding(t)
	m, err := NewManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	start, err := m.Start(context.Background(), StartOptions{Policy: healthcheck.DefaultPolicy(), Scan: pipeline.ScanOptions{RunExternal: false}})
	if err != nil {
		t.Fatal(err)
	}
	final := drive(t, m, start)
	if _, err := m.Approve(final.RunID, final.Result.FixableFindingIDs); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(context.Background(), final.RunID, StartOptions{Policy: healthcheck.DefaultPolicy()}); err == nil || !strings.Contains(err.Error(), "no project changes after") {
		t.Fatalf("verification error = %v, want no-post-approval-change rejection", err)
	}
	run, err := m.store.Open(final.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status() != runstore.StatusFixing {
		t.Fatalf("rejected verification changed status to %s", run.Status())
	}
}

// TestArtifactsOnlyInReportsDir is the storage-layout regression: after a raw
// scan history write AND a full host-agent run, the legacy .aitriage/ directory
// must NOT exist and every AITriage artifact must live under aitriage-reports/.
func TestArtifactsOnlyInReportsDir(t *testing.T) {
	dir := newProjectWithFinding(t)

	// Raw scan history goes to aitriage-reports/history (not .aitriage).
	if _, err := history.Save(dir, scanner.ScanReport{ProjectPath: dir, SecurityScore: 100}); err != nil {
		t.Fatalf("history save: %v", err)
	}

	// Full host-agent run writes the whole bundle under aitriage-reports/<run>.
	m, err := NewManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	start, err := m.Start(context.Background(), StartOptions{Policy: healthcheck.DefaultPolicy(), Scan: pipeline.ScanOptions{RunExternal: false}})
	if err != nil {
		t.Fatal(err)
	}
	final := drive(t, m, start)
	if final.Result == nil {
		t.Fatalf("run did not finalize: %s", final.Status)
	}

	// 1. Legacy .aitriage/ must never be created anywhere under the project.
	if _, err := os.Stat(filepath.Join(dir, ".aitriage")); !os.IsNotExist(err) {
		t.Fatalf(".aitriage must not exist (err=%v)", err)
	}

	// 2. aitriage-reports/ must hold the run bundle and the scan history.
	reports := filepath.Join(dir, "aitriage-reports")
	if _, err := os.Stat(filepath.Join(reports, "history")); err != nil {
		t.Fatalf("scan history not under aitriage-reports/history: %v", err)
	}
	for _, f := range []string{"manifest.json", "triage-findings.json", "report.md", "summary.md", "fixspec.md", "aitriage.sarif", "scan.json", "audit.log"} {
		if _, err := os.Stat(filepath.Join(reports, final.RunID, f)); err != nil {
			t.Errorf("expected %s under the run bundle: %v", f, err)
		}
	}

	// 3. Every AITriage-created file lives under aitriage-reports/ — walk the
	// whole project and prove nothing was written to a stray location.
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".aitriage" {
			t.Errorf("stray legacy .aitriage directory at %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// clientFunc adapts a function to llm.Client for the direct-path oracle.
type clientFunc func(ctx context.Context, msgs []llm.Message) (string, llm.Usage, error)

func (f clientFunc) Chat(ctx context.Context, msgs []llm.Message) (string, llm.Usage, error) {
	return f(ctx, msgs)
}

// TestDirectVsDeferredParity is the characterization test: the same scripted
// model answers, fed once through the direct shared pipeline (the CLI/CI oracle)
// and once through the deferred host-agent path, must produce byte-identical
// report.md, summary.md and fixspec.md and the same gate verdict. Both paths
// share one cache dir so cache behaviour is identical; neither path copies CLI
// logic — both call the same pipeline/graph.
func TestDirectVsDeferredParity(t *testing.T) {
	// Shared cache dir → identical cache behaviour for both paths.
	t.Setenv("AITRIAGE_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))

	dir := newProjectWithFinding(t)
	// Both paths must use the SAME canonical root; the host-agent store resolves
	// symlinks (/var -> /private/var on macOS), so resolve it for the direct path
	// too — otherwise only the finding file paths differ, not the logic.
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	mock := clientFunc(func(_ context.Context, msgs []llm.Message) (string, llm.Usage, error) {
		return fakeHostAnswer(msgs), llm.Usage{}, nil
	})

	// Direct path: the shared runner, exactly as `aitriage agent` uses it. The
	// deferred path forces the complete scanner orchestration, so the oracle must
	// request the same coverage contract.
	direct, err := pipeline.Run(context.Background(), pipeline.Options{
		ProjectPath: canonical,
		Scan:        pipeline.ScanOptions{RunExternal: true},
		Policy:      AuditPolicy(dir),
	}, mock)
	if err != nil {
		t.Fatalf("direct pipeline.Run: %v", err)
	}

	// Deferred path: the host-agent workflow answering the same requests.
	m, err := NewManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	start, err := m.Start(context.Background(), StartOptions{Policy: AuditPolicy(dir), Scan: pipeline.ScanOptions{RunExternal: false}})
	if err != nil {
		t.Fatal(err)
	}
	final := drive(t, m, start)
	if final.Result == nil {
		t.Fatalf("deferred run did not finalize: %s", final.Status)
	}

	report := mustArtifact(t, m, final.RunID, "report.md")
	summary := mustArtifact(t, m, final.RunID, "summary.md")
	fixspec := mustArtifact(t, m, final.RunID, "fixspec.md")

	if string(report) != direct.Report {
		t.Errorf("report.md differs between direct and deferred paths")
	}
	if string(summary) != direct.Summary {
		t.Errorf("summary.md differs between direct and deferred paths")
	}
	if string(fixspec) != direct.FixSpec {
		t.Errorf("fixspec.md differs between direct and deferred paths")
	}
	if final.Result.Gate.Passed != direct.Gate.Passed {
		t.Errorf("gate verdict differs: direct=%v deferred=%v", direct.Gate.Passed, final.Result.Gate.Passed)
	}
}

func mustArtifact(t *testing.T, m *Manager, runID, name string) []byte {
	t.Helper()
	b, ok, err := openArtifact(t, m, runID, name)
	if err != nil || !ok {
		t.Fatalf("artifact %s missing: ok=%v err=%v", name, ok, err)
	}
	return b
}

func openArtifact(t *testing.T, m *Manager, runID, name string) ([]byte, bool, error) {
	t.Helper()
	run, err := m.store.Open(runID)
	if err != nil {
		t.Fatalf("open run: %v", err)
	}
	return run.ReadArtifact(name)
}

// TestScannerFailClosedAndCoverage proves the scanner execution contract: with
// mandatory scanners unavailable, a full-required run fails closed BEFORE any AI
// triage and records the manifest, while a non-required (native/dev) run records
// "partial" coverage and still proceeds.
func TestScannerFailClosedAndCoverage(t *testing.T) {
	// Force all external scanners to be "missing" deterministically.
	t.Setenv("PATH", "")

	dir := newProjectWithFinding(t)
	m, err := NewManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	// Fail-closed: required full bundle, scanners missing → hard error, no triage.
	_, err = m.Start(context.Background(), StartOptions{
		Policy:              healthcheck.DefaultPolicy(),
		RequireFullScanners: true,
	})
	if err == nil {
		t.Fatal("full-required run must fail closed when mandatory scanners are missing")
	}
	if !strings.Contains(err.Error(), "scanner") {
		t.Errorf("error should explain the missing scanner bundle, got: %v", err)
	}

	// Non-required (native/dev): records partial coverage and proceeds to triage.
	start, err := m.Start(context.Background(), StartOptions{Policy: healthcheck.DefaultPolicy()})
	if err != nil {
		t.Fatalf("native run should proceed, got: %v", err)
	}
	if start.Pending == nil && start.Result == nil {
		t.Fatal("native run should reach a pending request or a result")
	}
	// The run bundle records the scanner manifest with partial coverage.
	run, err := m.store.Open(start.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Manifest().ScannerCoverage != "partial" {
		t.Errorf("coverage = %q, want partial (scanners missing)", run.Manifest().ScannerCoverage)
	}
	if len(run.Manifest().Scanners) == 0 {
		t.Fatal("scanner execution manifest must be recorded even when scanners are missing")
	}
}
