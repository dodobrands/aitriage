package orchestrator

import (
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// A baseline must cover every scanner that can raise a finding, or it does not
// solve the problem it exists for: on a real project most of the noise comes
// from the bundled Semgrep, Trivy, Gitleaks and Bandit, not from the built-in
// engine. Network findings are excluded — they describe the machine AITriage
// runs on, not the repository, and are never scored.

// BaselineItems flattens a scan result into the source-agnostic findings a
// baseline stores.
func BaselineItems(result *llm.RichScanResult) []baseline.Item {
	if result == nil {
		return nil
	}
	items := baseline.FromCore(result.Report.Results)
	items = append(items, baseline.FromExternal(result.External)...)
	items = append(items, baseline.FromNFR(result.NFR)...)
	items = append(items, baseline.FromDeploy(result.Deploy)...)
	return items
}

// ApplyBaseline removes accepted findings from every source and recomputes the
// score and verdict, so the reported set, the score and the gate all describe
// the same thing: what is new.
func ApplyBaseline(result *llm.RichScanResult, accepted *baseline.Baseline) int {
	if result == nil || accepted == nil || len(accepted.Findings) == 0 {
		return 0
	}

	hidden := 0

	coreFiltered := baseline.Filter(result.Report.Results, accepted)
	hidden += len(coreFiltered.Baseline)
	result.Report.Results = coreFiltered.New

	external, externalAccepted := baseline.FilterExternal(result.External, accepted)
	hidden += externalAccepted
	result.External = external

	nfrKept, nfrAccepted := baseline.FilterNFR(result.NFR, accepted)
	hidden += nfrAccepted
	result.NFR = nfrKept

	deployKept, deployAccepted := baseline.FilterDeploy(result.Deploy, accepted)
	hidden += deployAccepted
	result.Deploy = deployKept

	RecomputeHealthCheck(result)
	return hidden
}

// ApplySuppressions marks dismissed findings as audit-ignored rather than
// deleting them.
//
// A dismissal is a decision, not a disappearance: the finding must stay in the
// report with the reason attached, so a reviewer can see what was waved through
// and disagree. Only the score and the gate stop counting it.
func ApplySuppressions(result *llm.RichScanResult, store *suppression.Store) int {
	if result == nil || store == nil {
		return 0
	}

	suppressed := 0

	for i, r := range result.Report.Results {
		if r.Status != core.Absent {
			continue
		}
		item := baseline.FromCore([]core.CheckResult{r})[0]
		if _, ok := store.Suppresses(item); ok {
			result.Report.Results[i].AuditStatus = core.AuditStatusIgnored
			suppressed++
		}
	}

	keptExternal := result.External[:0]
	for _, f := range result.External {
		if _, ok := store.Suppresses(baseline.FromExternal([]external.UnifiedFinding{f})[0]); ok {
			suppressed++
			continue
		}
		keptExternal = append(keptExternal, f)
	}
	result.External = keptExternal

	keptNFR := result.NFR[:0]
	for _, f := range result.NFR {
		if _, ok := store.Suppresses(baseline.FromNFR([]nfr.NFRFinding{f})[0]); ok {
			suppressed++
			continue
		}
		keptNFR = append(keptNFR, f)
	}
	result.NFR = keptNFR

	keptDeploy := result.Deploy[:0]
	for _, f := range result.Deploy {
		if _, ok := store.Suppresses(baseline.FromDeploy([]deployaudit.DeployFinding{f})[0]); ok {
			suppressed++
			continue
		}
		keptDeploy = append(keptDeploy, f)
	}
	result.Deploy = keptDeploy

	if suppressed > 0 {
		RecomputeHealthCheck(result)
	}
	return suppressed
}
