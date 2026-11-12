package graph

import (
	"fmt"
	"os"
	"strings"
)

// ── Layer 3: Category / Severity Gating (SecureCoder-aware) ───────────────────
//
// Mirrors Datadog Bits AI: run the (costly) LLM only on a security-relevant
// subset. To stay faithful to SecureCoder's "evaluate EVERY finding" promise,
// findings gated OUT are NOT silently dropped — they receive a deterministic
// disposition derived from the SecureCoder ruleset and, when context is
// insufficient, default to Needs Manual Review (NEVER a silent False Positive).
//
// Gating is OFF by default so the default behaviour remains "every finding via
// LLM". Enable it for large repos with AITRIAGE_GATING=on.

const (
	dispositionSourceLLM           = "llm"
	dispositionSourceCache         = "cache"
	dispositionSourceDeterministic = "deterministic"
	dispositionSourceNRFallback    = "nr-fallback"
	// dispositionSourceTriageFailed marks a finding the model never
	// classified because the provider failed or every reply about it was
	// unusable; the run's triage is incomplete.
	dispositionSourceTriageFailed = "triage-failed"
	// dispositionSourceSuppressed marks a finding dismissed by a recorded
	// project decision; it is never sent to the LLM.
	dispositionSourceSuppressed = "suppressed"
	// dispositionSourceNetworkProbe marks a port-probe result about the
	// scanning host; it is never sent to the LLM and never scored.
	dispositionSourceNetworkProbe = "network-probe"
)

// isUnclassifiedSource reports whether a disposition carries no model verdict
// at all, as opposed to a model that was unsure.
func isUnclassifiedSource(source string) bool {
	return source == dispositionSourceNRFallback || source == dispositionSourceTriageFailed
}

type gatingConfig struct {
	enabled       bool
	llmSeverities map[string]bool
}

func defaultGatingConfig() gatingConfig {
	return gatingConfig{
		enabled:       strings.EqualFold(strings.TrimSpace(os.Getenv("AITRIAGE_GATING")), "on"),
		llmSeverities: map[string]bool{"CRITICAL": true, "HIGH": true},
	}
}

// shouldTriageWithLLM reports whether a finding warrants a full LLM triage.
// When gating is disabled, every finding is sent to the LLM.
func (g gatingConfig) shouldTriageWithLLM(f EnrichedFinding) bool {
	if !g.enabled {
		return true
	}
	return g.llmSeverities[strings.ToUpper(strings.TrimSpace(f.Severity))]
}

// deterministicDisposition classifies a gated-out finding without an LLM call.
// It is deliberately conservative: it never returns False Positive, so a
// low-severity finding is never auto-suppressed. It keeps penalising the Health
// Check until a human (or a future LLM pass) reviews it.
func deterministicDisposition(f EnrichedFinding) FindingDisposition {
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if sev == "" {
		sev = "UNKNOWN"
	}
	return FindingDisposition{
		Disposition:       "Needs Manual Review",
		Rationale:         fmt.Sprintf("Severity %s is below the LLM triage threshold (gating). Not auto-suppressed; manual review recommended per the SecureCoder ruleset.", sev),
		Confidence:        "low",
		DispositionSource: dispositionSourceDeterministic,
	}
}
