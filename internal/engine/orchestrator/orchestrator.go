package orchestrator

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dodobrands/aitriage/internal/agent/architect"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/entropy"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
	"github.com/dodobrands/aitriage/rules"
)

// Options configuration for the scan engine.
type Options struct {
	ProjectPath  string
	ProbeHost    string
	ForceStack   string
	RunExternal  bool
	FullPortScan bool // scan all 65535 ports instead of common ones
}

// redactScannerError returns a short, safe scanner error string for the
// execution manifest: it strips absolute paths and caps length so no secret or
// full environment dump reaches persisted evidence.
func redactScannerError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	msg = absPathRegex.ReplaceAllString(msg, "<path>")
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

var absPathRegex = regexp.MustCompile(`(/[^\s:]+){2,}`)

const externalScannerTimeout = 10 * time.Minute

// RunAllScanners executes all SAST, NFR, Deploy, Git, Network and architecture diagram generators concurrently.
func RunAllScanners(ctx context.Context, opts Options) llm.RichScanResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	// Keep collection fields non-nil even when a scanner legitimately returns no
	// findings. Callers use nil to distinguish "scanner did not initialize" from
	// "scanner completed with zero findings".
	result := llm.RichScanResult{
		ProjectPath: opts.ProjectPath,
		NFR:         []nfr.NFRFinding{},
	}

	// 1: Core SAST
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		r, err := scanner.Scan(ctx, opts.ProjectPath, scanner.ScanOptions{
			ForceStack: opts.ForceStack,
		})
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.ScannerExecutions = append(result.ScannerExecutions, external.ScannerExecution{
				Scanner: "aitriage", Status: external.StatusFailed,
				DurationMs: time.Since(start).Milliseconds(), Error: redactScannerError(err),
			})
		} else {
			result.Report = r
			result.ScannerExecutions = append(result.ScannerExecutions, external.ScannerExecution{
				Scanner: "aitriage", Status: external.StatusCompleted,
				Findings: len(r.Results), DurationMs: time.Since(start).Milliseconds(),
			})
		}
	}()

	// 2: External Scanners — every scanner records a typed execution status so a
	// full audit can never silently skip a mandatory scanner. A missing binary is
	// recorded as "missing" (not omitted); an error as "failed".
	// The trusted taint config is generated once, from the compiled-in rule
	// catalog, into an owner-only temp file. It is built up-front so that a
	// failure to load the mandatory taint rules fails the full audit closed (via
	// the semgrep execution status) rather than silently downgrading coverage.
	var taintCfgPath string
	var taintRuleIDs []string
	var taintErr error
	if opts.RunExternal {
		if dir, err := os.MkdirTemp("", "aitriage-taint-"); err != nil {
			taintErr = fmt.Errorf("create trusted rules dir: %w", err)
		} else {
			defer func() { _ = os.RemoveAll(dir) }()
			taintCfgPath, taintRuleIDs, taintErr = rules.WriteTaintConfig(dir)
		}
	}

	if opts.RunExternal {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var swg sync.WaitGroup

			record := func(ex external.ScannerExecution) {
				mu.Lock()
				result.ScannerExecutions = append(result.ScannerExecutions, ex)
				mu.Unlock()
			}
			addFindings := func(f []external.UnifiedFinding) {
				mu.Lock()
				result.External = append(result.External, f...)
				mu.Unlock()
			}
			// run executes one scanner with a hard upper bound, records its status,
			// and appends findings. Request cancellation still propagates through the
			// parent context; an abandoned Web/MCP run cannot leak child processes.
			run := func(name, label string, fn func(context.Context) ([]external.UnifiedFinding, error)) {
				defer swg.Done()
				if !external.IsInstalled(name) {
					record(external.ScannerExecution{Scanner: label, Status: external.StatusMissing})
					fmt.Fprintf(os.Stderr, "   ▶ %s — MISSING (not installed)\n", label)
					return
				}
				version := external.ToolVersion(ctx, name)
				start := time.Now()
				scanCtx, cancel := context.WithTimeout(ctx, externalScannerTimeout)
				defer cancel()
				findings, err := fn(scanCtx)
				dur := time.Since(start).Milliseconds()
				if err != nil {
					status := external.StatusFailed
					if scanCtx.Err() == context.DeadlineExceeded {
						status = external.StatusTimedOut
					}
					record(external.ScannerExecution{Scanner: label, Status: status, Version: version, DurationMs: dur, Error: redactScannerError(err)})
					fmt.Fprintf(os.Stderr, "   ▶ %s ✗ FAILED: %v\n", label, err)
					return
				}
				findings = external.FilterTestLikeFindings(findings)
				// Authoritative scope gate: vendored trees and ignored files are
				// not this project's code, whatever the tool decided to read.
				findings = external.FilterOutOfScope(opts.ProjectPath, findings)
				addFindings(findings)
				record(external.ScannerExecution{Scanner: label, Status: external.StatusCompleted, Version: version, Findings: len(findings), DurationMs: dur})
				fmt.Fprintf(os.Stderr, "   ▶ %s ✓ %d findings (%dms)\n", label, len(findings), dur)
			}

			swg.Add(1)
			go run("semgrep", "semgrep", func(scanCtx context.Context) ([]external.UnifiedFinding, error) {
				// Mandatory taint rules must be loadable; otherwise the full audit
				// fails closed instead of running Semgrep without them.
				if taintErr != nil {
					return nil, fmt.Errorf("mandatory taint rules unavailable: %w", taintErr)
				}
				// Registry "auto" rules and the trusted AITriage taint rules run
				// simultaneously in one Semgrep pass.
				return external.RunSemgrepConfigs(scanCtx, opts.ProjectPath, taintRuleIDs, "auto", taintCfgPath)
			})
			swg.Add(1)
			go run("gitleaks", "gitleaks", func(scanCtx context.Context) ([]external.UnifiedFinding, error) {
				return external.RunGitleaks(scanCtx, opts.ProjectPath)
			})
			swg.Add(1)
			go run("bandit", "bandit", func(scanCtx context.Context) ([]external.UnifiedFinding, error) {
				return external.RunBandit(scanCtx, opts.ProjectPath)
			})
			for _, scanType := range []string{"fs", "config"} {
				st := scanType
				swg.Add(1)
				go run("trivy", "trivy_"+st, func(scanCtx context.Context) ([]external.UnifiedFinding, error) {
					return external.RunTrivy(scanCtx, opts.ProjectPath, st)
				})
			}

			swg.Wait()
		}()
	}

	// 3: NFR Checks (now using embedded filesystem)
	wg.Add(1)
	go func() {
		defer wg.Done()
		nfrFindings, err := nfr.CheckNFR(opts.ProjectPath)
		if err == nil {
			if nfrFindings == nil {
				nfrFindings = []nfr.NFRFinding{}
			}
			mu.Lock()
			result.NFR = nfrFindings
			mu.Unlock()
		}
	}()

	// 4: DeployAudit (IaC)
	wg.Add(1)
	go func() {
		defer wg.Done()
		findings, err := deployaudit.AuditDeployFiles(opts.ProjectPath)
		if err == nil {
			mu.Lock()
			result.Deploy = findings
			mu.Unlock()
		}
	}()

	// 5: Git Deep Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		critFiles := entropy.FindCriticalFiles(opts.ProjectPath)
		historyLeaks := entropy.ScanGitHistory(opts.ProjectPath)

		// Git history is scanned with the same scope rules as everything else:
		// a secret inside a vendored dependency is that dependency's problem,
		// and an ignored file is not part of the delivered application.
		scope := external.NewScopeFilter(opts.ProjectPath)
		inScopeLeaks := historyLeaks[:0]
		for _, leak := range historyLeaks {
			if scope.InScope(leak.FilePath) {
				inScopeLeaks = append(inScopeLeaks, leak)
			}
		}
		historyLeaks = inScopeLeaks

		inScopeCritical := critFiles[:0]
		for _, file := range critFiles {
			if scope.InScope(file.Path) {
				inScopeCritical = append(inScopeCritical, file)
			}
		}
		critFiles = inScopeCritical

		if len(critFiles) > 0 || len(historyLeaks) > 0 {
			mu.Lock()
			result.CriticalFiles = critFiles
			result.HistoryLeaks = historyLeaks
			mu.Unlock()
		}
	}()

	// 6: Architecture Diagram
	wg.Add(1)
	go func() {
		defer wg.Done()
		diag, err := architect.GenerateMermaidDiagram(opts.ProjectPath)
		if err == nil {
			mu.Lock()
			result.Diagram = diag
			mu.Unlock()
		}
	}()

	// 7: Network Probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		var netFindings []network.NetworkFinding

		// Probe Docker Compose hosts if present
		if composeFindings := network.ProbeDockerCompose(opts.ProjectPath, opts.FullPortScan); len(composeFindings) > 0 {
			netFindings = append(netFindings, composeFindings...)
		}

		// Probe specific target if provided
		if opts.ProbeHost != "" {
			if targetFindings := network.ProbeHost(opts.ProbeHost, opts.FullPortScan); len(targetFindings) > 0 {
				netFindings = append(netFindings, targetFindings...)
			}
		}

		if len(netFindings) > 0 {
			mu.Lock()
			// Deduplicate if needed, though ProbeDockerCompose and ProbeHost might have different targets
			result.Network = netFindings
			mu.Unlock()
		}
	}()

	wg.Wait()
	sort.Slice(result.ScannerExecutions, func(i, j int) bool {
		return result.ScannerExecutions[i].Scanner < result.ScannerExecutions[j].Scanner
	})
	applyFullHealthCheck(&result)
	return result
}

// applyFullHealthCheck recomputes the score and gate verdict over every scanner
// that ran, not just the built-in engine.
//
// scanner.Scan can only see its own results, so the health check it returns
// covers the core engine alone. Used as-is, a repository whose only problems
// were found by Semgrep, Trivy, Gitleaks, Bandit, the NFR checks or the deploy
// audit would be scored 100/100 and pass the gate — a live SQL injection could
// be reported in the finding list while the verdict said PASSED.
//
// Network findings are deliberately excluded: an open port describes the machine
// AITriage runs on, not the repository being audited.
//
// Nothing here has been triaged: a deterministic scan produces hypotheses, so
// every finding is marked as needing review. AI triage, when it runs, recomputes
// this with real dispositions.
// RecomputeHealthCheck re-derives the score and gate verdict after a caller has
// changed which findings are in play — applying a baseline, for example. Without
// it the verdict would describe a finding set that is no longer the one reported.
func RecomputeHealthCheck(result *llm.RichScanResult) {
	applyFullHealthCheck(result)
}

func applyFullHealthCheck(result *llm.RichScanResult) {
	in := healthcheck.FromCoreResults(result.Report.Results)

	for _, f := range result.External {
		source := strings.TrimSpace(f.Source)
		if source == "" {
			source = "external"
		}
		class := strings.TrimSpace(f.RuleID)
		if class == "" {
			class = strings.TrimSpace(f.VulnerabilityClass)
		}
		in.Findings = append(in.Findings, healthcheck.Finding{
			Source:      source,
			Class:       class,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			NeedsReview: true,
		})
	}

	for _, f := range result.NFR {
		in.Findings = append(in.Findings, healthcheck.Finding{
			Source:      "nfr",
			Class:       f.RuleID,
			Severity:    f.Severity,
			NeedsReview: true,
		})
	}

	for _, f := range result.Deploy {
		in.Findings = append(in.Findings, healthcheck.Finding{
			Source:      "deploy",
			Class:       f.Issue,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			NeedsReview: true,
		})
	}

	evaluated := healthcheck.ApplyPolicy(healthcheck.Evaluate(in), result.Report.HealthCheck.Policy)
	result.Report.HealthCheck = evaluated
	result.Report.SecurityScore = evaluated.Score
	result.Report.SecurityGrade = evaluated.Grade
	result.Report.HasCriticalFailures = evaluated.HasCriticalFailures
}
