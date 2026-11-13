package config

import "testing"

// At 150 findings per request weaker models silently dropped part of every
// batch; the default is now small enough to be answered completely.
func TestDefaultLLMBatchSizeIs40(t *testing.T) {
	t.Setenv("AITRIAGE_BATCH_SIZE", "")
	cfg := LoadConfig(t.TempDir())
	if cfg.LLM.BatchSize != 40 {
		t.Fatalf("default batch size = %d, want 40", cfg.LLM.BatchSize)
	}

	t.Setenv("AITRIAGE_BATCH_SIZE", "12")
	if got := LoadConfig(t.TempDir()).LLM.BatchSize; got != 12 {
		t.Fatalf("AITRIAGE_BATCH_SIZE override = %d, want 12", got)
	}
}

func TestLoadConfigTriagePolicySettings(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, ".aitriage.yaml", `
health_check:
  fail_on: confirmed
  confirmed_min_severity: HIGH
  fp_critical_requires_high_confidence: true
`)

	cfg := LoadConfig(dir)
	if cfg.HealthCheck.ConfirmedMinSeverity != "HIGH" {
		t.Fatalf("confirmed_min_severity = %q, want HIGH", cfg.HealthCheck.ConfirmedMinSeverity)
	}
	if cfg.HealthCheck.FPCriticalRequiresHighConfidence == nil || !*cfg.HealthCheck.FPCriticalRequiresHighConfidence {
		t.Fatalf("fp_critical_requires_high_confidence = %v, want true", cfg.HealthCheck.FPCriticalRequiresHighConfidence)
	}
}

func TestLoadConfigIaCFindingsSetting(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, ".aitriage.yaml", `
health_check:
  iac_findings: block
`)
	if got := LoadConfig(dir).HealthCheck.IaCFindings; got != "block" {
		t.Fatalf("iac_findings = %q, want block", got)
	}
}

func TestLoadConfigQualityFindingsSetting(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, ".aitriage.yaml", `
health_check:
  quality_findings: block
`)
	if got := LoadConfig(dir).HealthCheck.QualityFindings; got != "block" {
		t.Fatalf("quality_findings = %q, want block", got)
	}
	if got := LoadConfig(t.TempDir()).HealthCheck.QualityFindings; got != "" {
		t.Fatalf("quality_findings without a config = %q, want unset", got)
	}
}
