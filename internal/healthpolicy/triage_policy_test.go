package healthpolicy

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

func TestFromConfigReadsTriagePolicySettings(t *testing.T) {
	on := true
	policy := FromConfig(&config.Config{HealthCheck: config.HealthCheckPolicyConfig{
		FailOn:                           healthcheck.FailOnConfirmed,
		ConfirmedMinSeverity:             "high",
		FPCriticalRequiresHighConfidence: &on,
	}})
	if policy.ConfirmedMinSeverity != healthcheck.SeverityHigh {
		t.Fatalf("confirmed_min_severity = %q, want HIGH", policy.ConfirmedMinSeverity)
	}
	if !policy.FPCriticalRequiresHighConfidence {
		t.Fatal("fp_critical_requires_high_confidence was not applied")
	}

	defaults := FromConfig(&config.Config{})
	if defaults.ConfirmedMinSeverity != healthcheck.SeverityLow || defaults.FPCriticalRequiresHighConfidence {
		t.Fatalf("defaults = %+v, want LOW and the confidence policy off", defaults)
	}
}

func TestApplyOverridesTriagePolicySettings(t *testing.T) {
	policy := FromConfig(&config.Config{HealthCheck: config.HealthCheckPolicyConfig{
		FailOn:               healthcheck.FailOnConfirmed,
		ConfirmedMinSeverity: "MEDIUM",
	}})

	policy = ApplyOverrides(policy, Overrides{
		ConfirmedMinSeverity:                "critical",
		ConfirmedMinSeveritySet:             true,
		FPCriticalRequiresHighConfidence:    true,
		FPCriticalRequiresHighConfidenceSet: true,
	})
	if policy.ConfirmedMinSeverity != healthcheck.SeverityCritical || !policy.FPCriticalRequiresHighConfidence {
		t.Fatalf("policy = %+v, want the CLI overrides applied", policy)
	}

	// A profile switch resets the profile's thresholds, not settings no
	// profile defines.
	policy = ApplyOverrides(policy, Overrides{Profile: healthcheck.PolicyStrict, ProfileSet: true})
	if policy.ConfirmedMinSeverity != healthcheck.SeverityCritical || !policy.FPCriticalRequiresHighConfidence {
		t.Fatalf("policy = %+v, want triage settings kept across a profile switch", policy)
	}
}
