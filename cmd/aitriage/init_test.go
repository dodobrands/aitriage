package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"gopkg.in/yaml.v3"
)

// The generated .aitriage.yaml must parse, describe ignore.paths in the
// .gitignore syntax every scanner now applies, and not list directories that
// are out of scope anyway: such entries kept them excluded even under
// AITRIAGE_SCAN_VENDORED=true.
func TestInitConfigTemplateMatchesIgnoreSemantics(t *testing.T) {
	template := generateAitrageConfig([]detectedStack{{Name: "go", Confidence: 100}})

	var cfg config.Config
	if err := yaml.Unmarshal([]byte(template), &cfg); err != nil {
		t.Fatalf("generated config is not valid YAML: %v\n%s", err, template)
	}
	if len(cfg.Ignore.Paths) != 0 || len(cfg.Ignore.Rules) != 0 {
		t.Errorf("ignore.paths/rules = %q/%q, want both empty by default", cfg.Ignore.Paths, cfg.Ignore.Rules)
	}
	if cfg.HealthCheck.FailOn != "critical" || cfg.HealthCheck.Profile != "baseline" {
		t.Errorf("health_check = %+v, want profile baseline and fail_on critical", cfg.HealthCheck)
	}
	// quality_findings is shown as a comment: a new configuration follows the
	// default (block) instead of pinning a mode.
	if cfg.HealthCheck.QualityFindings != "" || !strings.Contains(template, "# quality_findings: report") {
		t.Errorf("quality_findings = %q, want it unset and shown as a commented-out opt-in:\n%s", cfg.HealthCheck.QualityFindings, template)
	}
	for _, want := range []string{".gitignore syntax", "relative to the project root", "confirmed", "gitleaks:generic-api-key"} {
		if !strings.Contains(template, want) {
			t.Errorf("generated config does not mention %q:\n%s", want, template)
		}
	}
	// The model comment names each provider's default, and the OpenAI
	// default that AITriage 1.16 moves to.
	if want := "# empty: gemini-3.5-flash-lite (gemini), claude-sonnet-5-5 (anthropic), gpt-4o (openai; gpt-6-luna from AITriage 1.16)"; !strings.Contains(template, want) {
		t.Errorf("generated config does not name the default models %q:\n%s", want, template)
	}
}

// The generated .aitriageignore must not take the project's own files out of
// scope: a committed build/ directory is scanned, and Trivy reports dependency
// CVEs against lockfiles, which a "*.lock" entry used to drop from every report.
func TestInitIgnoreFileKeepsLockfilesAndBuildInScope(t *testing.T) {
	t.Setenv("AITRIAGE_RESPECT_GITIGNORE", "")
	t.Setenv("AITRIAGE_SCAN_VENDORED", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".aitriageignore"), []byte(generateIgnoreFile()), 0o644); err != nil {
		t.Fatal(err)
	}
	external.ResetScopeFilterCache()
	t.Cleanup(external.ResetScopeFilterCache)
	scope := external.NewScopeFilter(root)

	for _, path := range []string{"yarn.lock", "poetry.lock", "services/api/Cargo.lock", "build/package/Dockerfile", "src/app.js"} {
		if !scope.InScope(path) {
			t.Errorf("%s is out of scope with the generated .aitriageignore; it must be scanned", path)
		}
	}
	for _, path := range []string{"static/app.min.js", "static/app.js.map", "coverage/lcov.info"} {
		if scope.InScope(path) {
			t.Errorf("%s is in scope; the generated .aitriageignore should exclude it", path)
		}
	}
}

// TestInitWritesModernCursorRuleNotLegacy proves `aitriage init` generates a
// modern Cursor project rule (.cursor/rules/aitriage.mdc) with rule frontmatter
// and NOT the deprecated .cursorrules, and that the rule carries no embedded MCP
// server block (MCP lives in .cursor/mcp.json, written by install-cursor).
func TestInitWritesModernCursorRuleNotLegacy(t *testing.T) {
	prevForce, prevMCP := initForce, initMCP
	initForce, initMCP = false, false
	t.Cleanup(func() { initForce, initMCP = prevForce, prevMCP })

	root := t.TempDir()
	if err := runInit(nil, []string{root}); err != nil {
		t.Fatalf("init: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, ".cursorrules")); !os.IsNotExist(err) {
		t.Errorf("init must not write the deprecated .cursorrules (err=%v)", err)
	}

	mdcPath := filepath.Join(root, ".cursor", "rules", "aitriage.mdc")
	data, err := os.ReadFile(mdcPath)
	if err != nil {
		t.Fatalf("modern Cursor rule not written: %v", err)
	}
	rule := string(data)
	if !strings.HasPrefix(rule, "---\n") || !strings.Contains(rule, "alwaysApply: true") {
		t.Errorf("Cursor rule missing .mdc frontmatter:\n%s", rule)
	}
	if !strings.Contains(rule, agentContractHeading) {
		t.Errorf("Cursor rule missing the shared security contract:\n%s", rule)
	}
	// The rule must NOT embed an MCP server config, and must not carry the stale
	// `serve sse` invocation that the old .cursorrules shipped.
	for _, banned := range []string{`"mcp"`, "mcpServers", `"sse"`, "serve\", \"sse"} {
		if strings.Contains(rule, banned) {
			t.Errorf("Cursor rule must not embed MCP config (%q found):\n%s", banned, rule)
		}
	}
}
