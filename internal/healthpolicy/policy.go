package healthpolicy

import (
	"log/slog"
	"strings"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

type Overrides struct {
	Profile         string
	ProfileSet      bool
	FailOn          string
	FailOnSet       bool
	MinimumScore    int
	MinimumScoreSet bool

	ConfirmedMinSeverity    string
	ConfirmedMinSeveritySet bool

	FPCriticalRequiresHighConfidence    bool
	FPCriticalRequiresHighConfidenceSet bool

	IaCFindings    string
	IaCFindingsSet bool
}

// FromConfig converts .aitriage.yaml policy settings plus legacy top-level
// fields into the single runtime security-gate policy used by scan/agent/CI.
func FromConfig(cfg *config.Config) healthcheck.Policy {
	if cfg == nil {
		return healthcheck.DefaultPolicy()
	}

	policy := healthcheck.PolicyForProfile(cfg.HealthCheck.Profile)

	if cfg.HealthCheck.FailOn != "" {
		policy.FailOn = cfg.HealthCheck.FailOn
	} else if cfg.StrictMode {
		policy.FailOn = healthcheck.FailOnAny
	}

	if cfg.HealthCheck.MinimumScore != nil {
		policy.MinimumScore = *cfg.HealthCheck.MinimumScore
	} else if cfg.FailScore > 0 {
		policy.MinimumScore = cfg.FailScore
	}
	if cfg.HealthCheck.MaxCritical != nil {
		policy.MaxCritical = *cfg.HealthCheck.MaxCritical
	}
	if cfg.HealthCheck.MaxHigh != nil {
		policy.MaxHigh = *cfg.HealthCheck.MaxHigh
	}
	if cfg.HealthCheck.MaxMedium != nil {
		policy.MaxMedium = *cfg.HealthCheck.MaxMedium
	}
	if len(cfg.HealthCheck.BlockSources) > 0 {
		policy.BlockSources = cfg.HealthCheck.BlockSources
	}
	if len(cfg.HealthCheck.BlockClasses) > 0 {
		policy.BlockClasses = cfg.HealthCheck.BlockClasses
	}
	if raw := strings.TrimSpace(cfg.HealthCheck.ConfirmedMinSeverity); raw != "" {
		if _, ok := healthcheck.ParseConfirmedMinSeverity(raw); !ok {
			// NormalizePolicy falls back to LOW, the strictest floor; say so
			// instead of silently gating differently from what was written.
			slog.Warn("Unknown health_check.confirmed_min_severity; using LOW", "value", raw)
		}
		policy.ConfirmedMinSeverity = raw
	}
	if v := cfg.HealthCheck.FPCriticalRequiresHighConfidence; v != nil {
		policy.FPCriticalRequiresHighConfidence = *v
	}
	if raw := strings.TrimSpace(cfg.HealthCheck.IaCFindings); raw != "" {
		if _, ok := healthcheck.ParseIaCFindings(raw); !ok {
			// NormalizePolicy falls back to block, the strict reading; say so
			// instead of silently gating differently from what was written.
			slog.Warn("Unknown health_check.iac_findings; using block", "value", raw)
		}
		policy.IaCFindings = raw
	}

	return healthcheck.NormalizePolicy(policy)
}

func HasConfiguredGate(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	hc := cfg.HealthCheck
	return cfg.StrictMode ||
		cfg.FailScore > 0 ||
		hc.Profile != "" ||
		hc.FailOn != "" ||
		hc.MinimumScore != nil ||
		hc.MaxCritical != nil ||
		hc.MaxHigh != nil ||
		hc.MaxMedium != nil ||
		len(hc.BlockSources) > 0 ||
		len(hc.BlockClasses) > 0
}

// ApplyOverrides applies explicit CLI/action inputs on top of the config policy.
func ApplyOverrides(policy healthcheck.Policy, overrides Overrides) healthcheck.Policy {
	if overrides.ProfileSet {
		next := healthcheck.PolicyForProfile(overrides.Profile)
		// Settings that no profile defines survive a profile switch.
		next.BlockSources = policy.BlockSources
		next.BlockClasses = policy.BlockClasses
		next.ConfirmedMinSeverity = policy.ConfirmedMinSeverity
		next.FPCriticalRequiresHighConfidence = policy.FPCriticalRequiresHighConfidence
		next.IaCFindings = policy.IaCFindings
		policy = next
	}
	if overrides.FailOnSet {
		policy.FailOn = overrides.FailOn
	}
	if overrides.MinimumScoreSet {
		policy.MinimumScore = overrides.MinimumScore
	}
	if overrides.ConfirmedMinSeveritySet {
		policy.ConfirmedMinSeverity = overrides.ConfirmedMinSeverity
	}
	if overrides.FPCriticalRequiresHighConfidenceSet {
		policy.FPCriticalRequiresHighConfidence = overrides.FPCriticalRequiresHighConfidence
	}
	if overrides.IaCFindingsSet {
		policy.IaCFindings = overrides.IaCFindings
	}
	return healthcheck.NormalizePolicy(policy)
}
