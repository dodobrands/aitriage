package pipeline

import (
	"fmt"
	"os"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// applyProjectDecisions applies the dismissals recorded in
// .aitriage-suppressions.json (`aitriage ignore add`, the Web UI, IDE tools)
// at the point the Web server applies them: after scanning, before scoring
// and AI triage. Without it a risk accepted from the terminal kept failing CI,
// because only the Web server ever read the file.
//
// orchestrator.ApplySuppressions does the dismissing: external, NFR and deploy
// findings are removed, built-in findings stay in the inventory marked
// audit-ignored. The summary returned here records why, per reason, so the
// report can show what was waived. The scan slices are detached first, so the
// caller's own copy of the result (for example a persisted host-agent
// snapshot) is never modified in place.
func applyProjectDecisions(rich *llm.RichScanResult, projectPath string) graph.SuppressionSummary {
	var summary graph.SuppressionSummary
	if rich.ProjectPath == "" {
		rich.ProjectPath = projectPath
	}
	root := rich.ProjectPath

	store, err := suppression.Load(projectPath)
	switch {
	case err != nil:
		// Fail closed: the decisions are not applied, so the findings stay
		// open, and the reason is reported instead of silently ignored.
		summary.LoadError = err.Error()
		fmt.Fprintf(os.Stderr, "   ⚠️ %s not applied: %v\n", suppression.File, err)
	case len(store.Entries) > 0:
		detachScanFindings(rich)
		tallyStoreDecisions(rich, store, root, &summary)
		orchestrator.ApplySuppressions(rich, store)
	}
	tallyAuditLogDecisions(rich, &summary)
	return summary
}

// detachScanFindings gives the result its own finding slices.
// ApplySuppressions filters them in place, which would otherwise rewrite the
// backing arrays the caller still holds.
func detachScanFindings(rich *llm.RichScanResult) {
	rich.Report.Results = cloneSlice(rich.Report.Results)
	rich.External = cloneSlice(rich.External)
	rich.NFR = cloneSlice(rich.NFR)
	rich.Deploy = cloneSlice(rich.Deploy)
}

func cloneSlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	return append(make([]T, 0, len(in)), in...)
}

// tallyStoreDecisions counts, per reason, the findings the decisions file
// dismisses, using the same matching as orchestrator.ApplySuppressions, and
// remembers the decision behind each built-in finding for its rationale.
func tallyStoreDecisions(rich *llm.RichScanResult, store *suppression.Store, root string, summary *graph.SuppressionSummary) {
	record := func(entry suppression.Entry) {
		addDecision(summary, firstReason(entry.Reason))
	}
	for _, r := range rich.Report.Results {
		if r.Status != core.Absent {
			continue
		}
		item := baseline.Relativize(root, baseline.FromCore([]core.CheckResult{r}))[0]
		if entry, ok := store.SuppressesInProject(root, item); ok {
			record(entry)
			if summary.Core == nil {
				summary.Core = map[string]graph.SuppressionDecision{}
			}
			summary.Core[graph.CoreDecisionKey(r.ID, r.File, r.Line)] = graph.SuppressionDecision{Reason: firstReason(entry.Reason), Note: entry.Note}
		}
	}
	for _, f := range rich.External {
		if entry, ok := store.SuppressesInProject(root, baseline.Relativize(root, baseline.FromExternal([]external.UnifiedFinding{f}))[0]); ok {
			record(entry)
		}
	}
	for _, f := range rich.NFR {
		if entry, ok := store.SuppressesInProject(root, baseline.Relativize(root, baseline.FromNFR([]nfr.NFRFinding{f}))[0]); ok {
			record(entry)
		}
	}
	for _, f := range rich.Deploy {
		if entry, ok := store.SuppressesInProject(root, baseline.Relativize(root, baseline.FromDeploy([]deployaudit.DeployFinding{f}))[0]); ok {
			record(entry)
		}
	}
}

// tallyAuditLogDecisions counts built-in findings dismissed in the AITriage
// audit log (Web UI / TUI) rather than in the decisions file. The scanner
// already marked them; they are dismissals all the same.
func tallyAuditLogDecisions(rich *llm.RichScanResult, summary *graph.SuppressionSummary) {
	for _, r := range rich.Report.Results {
		if r.Status != core.Absent || (r.AuditStatus != core.AuditStatusIgnored && r.AuditStatus != core.AuditStatusTriage) {
			continue
		}
		key := graph.CoreDecisionKey(r.ID, r.File, r.Line)
		if _, decided := summary.Core[key]; decided {
			continue
		}
		if summary.Core == nil {
			summary.Core = map[string]graph.SuppressionDecision{}
		}
		summary.Core[key] = graph.SuppressionDecision{Reason: graph.SuppressionReasonAuditLog, Note: string(r.AuditStatus)}
		addDecision(summary, graph.SuppressionReasonAuditLog)
	}
}

func addDecision(summary *graph.SuppressionSummary, reason string) {
	if summary.ByReason == nil {
		summary.ByReason = map[string]int{}
	}
	summary.ByReason[reason]++
	summary.Total++
}

// firstReason maps an entry written without a reason to the store default.
func firstReason(reason string) string {
	if reason == "" {
		return suppression.ReasonFalsePositive
	}
	return reason
}
