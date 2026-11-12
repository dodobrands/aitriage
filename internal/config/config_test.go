package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigHealthCheckPolicyBlock(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `.aitriage.yaml`, `
health_check:
  profile: standard
  fail_on: any
  minimum_score: 85
  max_critical: 0
  max_high: 0
  max_medium: 2
  block_sources:
    - gitleaks
  block_classes:
    - hardcoded-secret
`)

	cfg := LoadConfig(dir)

	if cfg.HealthCheck.Profile != "standard" {
		t.Fatalf("profile = %q; want standard", cfg.HealthCheck.Profile)
	}
	if cfg.HealthCheck.FailOn != "any" {
		t.Fatalf("fail_on = %q; want any", cfg.HealthCheck.FailOn)
	}
	if cfg.HealthCheck.MinimumScore == nil || *cfg.HealthCheck.MinimumScore != 85 {
		t.Fatalf("minimum_score = %v; want 85", cfg.HealthCheck.MinimumScore)
	}
	if cfg.HealthCheck.MaxCritical == nil || *cfg.HealthCheck.MaxCritical != 0 {
		t.Fatalf("max_critical = %v; want explicit 0", cfg.HealthCheck.MaxCritical)
	}
	if cfg.HealthCheck.MaxHigh == nil || *cfg.HealthCheck.MaxHigh != 0 {
		t.Fatalf("max_high = %v; want explicit 0", cfg.HealthCheck.MaxHigh)
	}
	if cfg.HealthCheck.MaxMedium == nil || *cfg.HealthCheck.MaxMedium != 2 {
		t.Fatalf("max_medium = %v; want 2", cfg.HealthCheck.MaxMedium)
	}
	if len(cfg.HealthCheck.BlockSources) != 1 || cfg.HealthCheck.BlockSources[0] != "gitleaks" {
		t.Fatalf("block_sources = %#v", cfg.HealthCheck.BlockSources)
	}
	if len(cfg.HealthCheck.BlockClasses) != 1 || cfg.HealthCheck.BlockClasses[0] != "hardcoded-secret" {
		t.Fatalf("block_classes = %#v", cfg.HealthCheck.BlockClasses)
	}
}

func TestLoadConfigTrivyScannerOptions(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `.aitriage.yaml`, `
scanners:
  trivy:
    ignore_unfixed: true
    severity: [CRITICAL, HIGH]
`)

	cfg := LoadConfig(dir)

	if !cfg.Scanners.Trivy.IgnoreUnfixed {
		t.Fatal("scanners.trivy.ignore_unfixed was not loaded")
	}
	if got := cfg.Scanners.Trivy.Severity; len(got) != 2 || got[0] != "CRITICAL" || got[1] != "HIGH" {
		t.Fatalf("scanners.trivy.severity = %#v; want [CRITICAL HIGH]", got)
	}
}

func writeConfig(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
