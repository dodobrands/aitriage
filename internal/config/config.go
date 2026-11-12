package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Ignore      IgnoreConfig            `yaml:"ignore,omitempty"`
	CustomRules []CustomRule            `yaml:"rules,omitempty"`
	LLM         LLMConfig               `yaml:"llm,omitempty"`
	StrictMode  bool                    `yaml:"strict_mode,omitempty"` // Legacy: fail on ANY finding
	FailScore   int                     `yaml:"fail_score,omitempty"`  // Legacy: fail if Health Check score < this value
	HealthCheck HealthCheckPolicyConfig `yaml:"health_check,omitempty"`
	Scanners    ScannersConfig          `yaml:"scanners,omitempty"`
}

// ScannersConfig holds options for the bundled external scanners.
type ScannersConfig struct {
	Trivy TrivyScannerConfig `yaml:"trivy,omitempty"`
}

// TrivyScannerConfig is the subset of Trivy's own flags a project may set.
type TrivyScannerConfig struct {
	// IgnoreUnfixed reports only vulnerabilities that already have a fixed
	// version (trivy fs --ignore-unfixed).
	IgnoreUnfixed bool `yaml:"ignore_unfixed,omitempty"`
	// Severity limits what Trivy reports, e.g. [CRITICAL, HIGH]
	// (trivy --severity). It applies to dependency and IaC scans alike.
	Severity []string `yaml:"severity,omitempty"`
}

type HealthCheckPolicyConfig struct {
	Profile      string   `yaml:"profile,omitempty"`
	FailOn       string   `yaml:"fail_on,omitempty"`
	MinimumScore *int     `yaml:"minimum_score,omitempty"`
	MaxCritical  *int     `yaml:"max_critical,omitempty"`
	MaxHigh      *int     `yaml:"max_high,omitempty"`
	MaxMedium    *int     `yaml:"max_medium,omitempty"`
	BlockSources []string `yaml:"block_sources,omitempty"`
	BlockClasses []string `yaml:"block_classes,omitempty"`
	// ConfirmedMinSeverity (LOW | MEDIUM | HIGH | CRITICAL) limits
	// fail_on: confirmed to confirmed findings at or above that severity.
	ConfirmedMinSeverity string `yaml:"confirmed_min_severity,omitempty"`
	// FPCriticalRequiresHighConfidence keeps a CRITICAL finding as Needs
	// Manual Review unless the model dismisses it with high confidence.
	FPCriticalRequiresHighConfidence *bool `yaml:"fp_critical_requires_high_confidence,omitempty"`
	// IaCFindings (report | block) decides whether IaC misconfigurations
	// (Trivy config results) count toward the score and the gate. report,
	// the default for now, triages and reports them without gating.
	IaCFindings string `yaml:"iac_findings,omitempty"`
}

// DefaultLLMBatchSize is how many findings one classification request carries
// when nothing else is configured. Larger batches made weaker models omit
// items, and every omission became an unclassified Needs Review finding.
const DefaultLLMBatchSize = 40

type LLMConfig struct {
	Provider        string `yaml:"provider"`
	Model           string `yaml:"model"`
	APIKey          string `yaml:"api_key"`
	BaseURL         string `yaml:"base_url"`
	Timeout         int    `yaml:"timeout"`
	DisableThinking bool   `yaml:"disable_thinking"` // Send thinking:{type:disabled} for reasoning models
	BatchSize       int    `yaml:"batch_size,omitempty"`
}

type CustomRule struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Stack      string   `yaml:"stack"`
	Extensions []string `yaml:"extensions,omitempty"`
	Target     string   `yaml:"target"`
	Pattern    string   `yaml:"pattern"`
	Condition  string   `yaml:"condition,omitempty"`
	Files      []string `yaml:"files,omitempty"`
	Suggestion string   `yaml:"suggestion"`
	Severity   string   `yaml:"severity,omitempty"`
}

type IgnoreConfig struct {
	Rules []string `yaml:"rules,omitempty"`
	Paths []string `yaml:"paths,omitempty"`
}

// LoadConfig looks for aitriage.yaml or .aitriage.yaml in the given root string.
// After loading, it applies env var overrides for LLM config (env > yaml).
func LoadConfig(rootPath string) *Config {
	possibleFiles := configFileNames

	var configData []byte
	var err error
	var found bool

	for _, file := range possibleFiles {
		fullPath := filepath.Join(rootPath, file)
		configData, err = os.ReadFile(fullPath)
		if err == nil {
			found = true
			break
		}
	}

	cfg := &Config{}
	if found {
		// Expand $VAR and ${VAR} patterns before parsing.
		// This allows users to reference env vars in config: api_key: $GEMINI_API_KEY
		expandedData := os.ExpandEnv(string(configData))
		err = yaml.Unmarshal([]byte(expandedData), cfg)
		if err != nil {
			slog.Warn("Failed to parse configuration file", "error", err)
		}
	}

	// Auto-load custom generated rules from .aitriage/custom_rules.yaml
	customRulesPath := filepath.Join(rootPath, ".aitriage", "custom_rules.yaml")
	if customData, err := os.ReadFile(customRulesPath); err == nil {
		var customRules []CustomRule
		if err := yaml.Unmarshal(customData, &customRules); err == nil {
			cfg.CustomRules = append(cfg.CustomRules, customRules...)
		} else {
			slog.Warn("Failed to parse custom_rules.yaml", "error", err)
		}
	}

	// Auto-detect LLM provider from env vars if not set in YAML.
	// Priority: GEMINI_API_KEY > ANTHROPIC_API_KEY > OPENAI_API_KEY
	applyEnvLLMConfig(&cfg.LLM)

	return cfg
}

// applyEnvLLMConfig fills in missing LLM config fields from environment variables.
// CLI flags applied later in agent.go will still override these.
func applyEnvLLMConfig(llm *LLMConfig) {
	// API key env overrides (only if not set in yaml)
	if llm.APIKey == "" {
		// Generic container-safe handoff. The host CLI forwards only this name to
		// Docker; the secret value never appears in docker argv.
		if v := os.Getenv("AITRIAGE_LLM_API_KEY"); v != "" {
			llm.APIKey = v
		}
	}
	if llm.APIKey == "" {
		for _, env := range []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY"} {
			if v := os.Getenv(env); v != "" {
				llm.APIKey = v
				// Auto-set provider if not specified
				if llm.Provider == "" {
					switch env {
					case "GEMINI_API_KEY", "GOOGLE_API_KEY":
						llm.Provider = "gemini"
					case "ANTHROPIC_API_KEY":
						llm.Provider = "anthropic"
					case "OPENAI_API_KEY":
						llm.Provider = "openai"
					case "GROQ_API_KEY":
						llm.Provider = "groq"
					}
				}
				break
			}
		}
	}
	// Explicit env overrides for provider/model/base_url
	if v := os.Getenv("AITRIAGE_LLM_PROVIDER"); v != "" {
		llm.Provider = v
	}
	if v := os.Getenv("AITRIAGE_LLM_MODEL"); v != "" {
		llm.Model = v
	}
	if v := os.Getenv("AITRIAGE_LLM_BASE_URL"); v != "" {
		llm.BaseURL = v
	}
	// Disable thinking/reasoning for reasoning models (Z.ai GLM, Xiaomi MiMo, etc.)
	// Sends {"thinking":{"type":"disabled"}} in the request body.
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_LLM_DISABLE_THINKING")); v != "" {
		llm.DisableThinking = v == "1" || strings.EqualFold(v, "true")
	}
	// Request timeout (seconds). Prevents hung reasoning calls from blocking forever.
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_LLM_TIMEOUT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			llm.Timeout = n
		}
	}
	// LLM batch size (findings per classification request).
	if v := strings.TrimSpace(os.Getenv("AITRIAGE_BATCH_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			llm.BatchSize = n
		}
	}
	if llm.BatchSize <= 0 {
		llm.BatchSize = DefaultLLMBatchSize
	}
}

// IsRuleIgnored reports whether ignore.rules silences a rule of the built-in
// engine. Ids compare case-insensitively; a qualified entry such as
// "gitleaks:B105" applies to that scanner only, not to the built-in engine.
func (c *Config) IsRuleIgnored(ruleID string) bool {
	if c == nil {
		return false
	}
	for _, entry := range c.Ignore.Rules {
		if ParseRuleRef(entry).Matches(ruleID, CoreRuleSources...) {
			return true
		}
	}
	return false
}
