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

// iac_findings: report by default, block when configured, block on a typo
// (the strict reading); a CLI override wins and survives a profile switch.
func TestIaCFindingsPolicySetting(t *testing.T) {
	if got := FromConfig(&config.Config{}).IaCFindings; got != healthcheck.IaCFindingsReport {
		t.Fatalf("default iac_findings = %q, want report", got)
	}
	for value, want := range map[string]string{"block": healthcheck.IaCFindingsBlock, "Report": healthcheck.IaCFindingsReport, "blok": healthcheck.IaCFindingsBlock} {
		if got := FromConfig(&config.Config{HealthCheck: config.HealthCheckPolicyConfig{IaCFindings: value}}).IaCFindings; got != want {
			t.Errorf("iac_findings: %s = %q, want %q", value, got, want)
		}
	}
	policy := FromConfig(&config.Config{HealthCheck: config.HealthCheckPolicyConfig{IaCFindings: "report"}})
	policy = ApplyOverrides(policy, Overrides{IaCFindings: "block", IaCFindingsSet: true})
	if policy.IaCFindings != healthcheck.IaCFindingsBlock {
		t.Fatalf("override = %q, want block", policy.IaCFindings)
	}
	policy = ApplyOverrides(policy, Overrides{Profile: healthcheck.PolicyStrict, ProfileSet: true})
	if policy.IaCFindings != healthcheck.IaCFindingsBlock {
		t.Fatalf("after a profile switch iac_findings = %q, want block kept", policy.IaCFindings)
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
