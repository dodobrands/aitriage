package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dodobrands/aitriage/internal/models"
	"gopkg.in/yaml.v3"
)

// RequiredTaintRuleIDs is the mandatory taint-rule set that a full audit must be
// able to load and execute. A missing or malformed entry fails the audit closed:
// a full audit must never silently run without its mandatory taint coverage.
var RequiredTaintRuleIDs = []string{
	"FAST-OPEN-REDIRECT",
	"FAST-PATH-TRAVERSAL",
	"FAST-SQLI",
	"FAST-SSRF",
	"FAST-XSS",
}

// taintRuleOptions holds the Semgrep `options:` block of a taint rule.
// models.Rule has no options field, and the strict catalog decoder rejects
// unknown keys, so the options live here, keyed by rule id.
//
// taint_assume_safe_functions makes Semgrep assume that a call does not pass
// taint from its arguments to its result. It keeps service-built values
// (build_url(request_param), a lookup by id) from being reported, at the cost
// of missing taint through a helper. FAST-XSS and FAST-PATH-TRAVERSAL do not
// set it: an identity helper named like escape() must not hide XSS, and
// os.path.join() must carry taint into a path.
var taintRuleOptions = map[string]map[string]any{
	"FAST-OPEN-REDIRECT": {"taint_assume_safe_functions": true},
	"FAST-SQLI":          {"taint_assume_safe_functions": true},
	"FAST-SSRF":          {"taint_assume_safe_functions": true},
}

// TaintRules returns every taint-mode rule in the embedded (trusted) catalog.
// Only the compiled-in rules/ tree is consulted — never a path inside the
// project under scan — so the rules executed by Semgrep cannot be substituted by
// a user-controlled file.
func TaintRules() ([]models.Rule, error) {
	var taint []models.Rule
	seen := map[string]bool{}
	err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		data, err := fs.ReadFile(FS, path)
		if err != nil {
			return fmt.Errorf("read embedded rule %s: %w", path, err)
		}
		var rs models.Ruleset
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return fmt.Errorf("parse embedded rule %s: %w", path, err)
		}
		for _, r := range rs.Rules {
			if !r.IsTaint() || seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			taint = append(taint, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(taint, func(i, j int) bool { return taint[i].ID < taint[j].ID })
	return taint, nil
}

// semgrepTaintRule is the minimal, Semgrep-valid projection of a taint rule. Our
// engine-only fields (stack, extensions, target, condition, suggestion, …) are
// deliberately dropped: Semgrep rejects unknown keys, so only the taint schema is
// emitted. Source/sink/sanitizer nodes are copied verbatim.
type semgrepTaintRule struct {
	ID         string            `yaml:"id"`
	Mode       string            `yaml:"mode"`
	Languages  []string          `yaml:"languages"`
	Severity   string            `yaml:"severity"`
	Message    string            `yaml:"message"`
	Metadata   map[string]string `yaml:"metadata,omitempty"`
	Options    map[string]any    `yaml:"options,omitempty"`
	Sources    []yaml.Node       `yaml:"pattern-sources"`
	Sanitizers []yaml.Node       `yaml:"pattern-sanitizers,omitempty"`
	Sinks      []yaml.Node       `yaml:"pattern-sinks"`
}

type semgrepConfig struct {
	Rules []semgrepTaintRule `yaml:"rules"`
}

// semgrepSeverity maps AITriage severities to the Semgrep enum (ERROR/WARNING/INFO).
func semgrepSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "HIGH", "ERROR":
		return "ERROR"
	case "MEDIUM", "WARNING":
		return "WARNING"
	default:
		return "INFO"
	}
}

// TaintSemgrepConfig builds a self-contained, Semgrep-valid YAML config from the
// trusted taint rules. It fails closed: an error is returned if a mandatory rule
// is absent or if any taint rule is missing its sources or sinks, so a full audit
// cannot proceed with incomplete mandatory coverage. The returned ids are the
// exact rule ids emitted (used to normalize Semgrep's check_id back to the
// canonical rule id).
func TaintSemgrepConfig() (config []byte, ids []string, err error) {
	trs, err := TaintRules()
	if err != nil {
		return nil, nil, fmt.Errorf("load taint rules: %w", err)
	}

	have := map[string]bool{}
	for _, r := range trs {
		have[r.ID] = true
	}
	for _, req := range RequiredTaintRuleIDs {
		if !have[req] {
			return nil, nil, fmt.Errorf("mandatory taint rule %q missing from trusted catalog", req)
		}
	}

	var cfg semgrepConfig
	for _, r := range trs {
		if len(r.PatternSources) == 0 || len(r.PatternSinks) == 0 {
			return nil, nil, fmt.Errorf("taint rule %q must define both pattern-sources and pattern-sinks", r.ID)
		}
		langs := r.Languages
		if len(langs) == 0 {
			langs = []string{"python"}
		}
		msg := r.Message
		if msg == "" {
			msg = r.Suggestion
		}
		if msg == "" {
			msg = r.Name
		}
		cfg.Rules = append(cfg.Rules, semgrepTaintRule{
			ID:         r.ID,
			Mode:       "taint",
			Languages:  langs,
			Severity:   semgrepSeverity(r.Severity),
			Message:    msg,
			Metadata:   r.Metadata,
			Options:    taintRuleOptions[r.ID],
			Sources:    r.PatternSources,
			Sanitizers: r.PatternSanitizers,
			Sinks:      r.PatternSinks,
		})
		ids = append(ids, r.ID)
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal taint config: %w", err)
	}
	return out, ids, nil
}

// WriteTaintConfig writes the trusted taint Semgrep config into dir with
// owner-only permissions and returns its absolute path plus the emitted rule ids.
// The file is derived entirely from compiled-in bytes, so it cannot be tampered
// with by the scanned project.
func WriteTaintConfig(dir string) (path string, ids []string, err error) {
	out, ids, err := TaintSemgrepConfig()
	if err != nil {
		return "", nil, err
	}
	path = filepath.Join(dir, "aitriage-taint.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", nil, fmt.Errorf("write taint config: %w", err)
	}
	return path, ids, nil
}
