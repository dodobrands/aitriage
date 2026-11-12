package engine

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/regions"
	"github.com/dodobrands/aitriage/internal/scanner/ast"
	"github.com/dodobrands/aitriage/rules"
	"gopkg.in/yaml.v3"
)

// Re-export Rule for convenience or just use models.Rule
type Rule = models.Rule

func (e *Engine) compileRule(r *models.Rule) {
	if r.Pattern != "" && r.Target != "ast" {
		c, err := regexp.Compile(r.Pattern)
		if err == nil {
			r.CompiledPattern = c
		} else {
			slog.Warn("Rule pattern is not valid RE2; matching it as a literal string", "rule", r.ID, "error", err)
		}
	}
	if r.PatternNot != "" {
		c, err := regexp.Compile(r.PatternNot)
		if err == nil {
			r.CompiledNot = c
		} else {
			slog.Warn("Rule pattern-not is not valid RE2; ignoring it", "rule", r.ID, "error", err)
		}
	}
	for i := range r.Patterns {
		e.compileRule(&r.Patterns[i])
	}
	for i := range r.PatternEither {
		e.compileRule(&r.PatternEither[i])
	}
}

// loadEmbeddedRules walks the rules.FS embedded filesystem and parses
// every .yaml file it finds, merging all rule sets into a single slice.
// This makes rules/ the single source of truth — no duplication needed.
func loadEmbeddedRules() ([]models.Rule, error) {
	var allRules []models.Rule
	seen := make(map[string]bool) // deduplicate by rule ID

	err := fs.WalkDir(rules.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		slog.Debug("Walking rules FS", "path", path, "isDir", d.IsDir())
		// Skip non-YAML files (README.md, embed.go, etc.)
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		data, err := fs.ReadFile(rules.FS, path)
		if err != nil {
			slog.Warn("Failed to read rule file", "path", path, "error", err)
			return nil // skip broken files, don't crash
		}

		var rs models.Ruleset
		if err := yaml.Unmarshal(data, &rs); err != nil {
			slog.Warn("Failed to parse rule file", "path", path, "error", err)
			return nil
		}

		for _, r := range rs.Rules {
			// Skip rules that are documentation-only (entropy-analysis is handled in Go code)
			if r.Target == "entropy-analysis" {
				continue
			}
			// Taint-mode rules are executed by the bundled Semgrep, not by this
			// regex/AST engine. Skipping them here keeps the engine from ever
			// attempting a regex/AST match on a rule that has no pattern.
			if r.IsTaint() {
				continue
			}
			if !seen[r.ID] {
				seen[r.ID] = true
				allRules = append(allRules, r)
			}
		}

		return nil
	})

	slog.Debug("Embedded rules loaded", "count", len(allRules))
	return allRules, err
}

// loadPackRules loads rule YAML files from installed rule packs in ~/.aitriage/packs/.
func loadPackRules() ([]models.Rule, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil // silently skip if no home dir
	}
	packsDir := filepath.Join(home, ".aitriage", "packs")
	if _, err := os.Stat(packsDir); os.IsNotExist(err) {
		return nil, nil // no packs installed
	}

	var allRules []models.Rule
	seen := make(map[string]bool)

	err = filepath.WalkDir(packsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		// Skip manifest.json and non-rule files
		if d.Name() == "manifest.json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var rs models.Ruleset
		if err := yaml.Unmarshal(data, &rs); err != nil {
			slog.Warn("Failed to parse pack rule file", "path", path, "error", err)
			return nil
		}

		for _, r := range rs.Rules {
			if r.Target == "entropy-analysis" {
				continue
			}
			if r.IsTaint() {
				continue
			}
			if !seen[r.ID] {
				seen[r.ID] = true
				allRules = append(allRules, r)
			}
		}
		return nil
	})

	return allRules, err
}

type Engine struct {
	Rules  []models.Rule
	Config *config.Config
}

func NewEngine(cfg *config.Config) (*Engine, error) {
	loadedRules, err := loadEmbeddedRules()
	if err != nil {
		slog.Error("Failed to load embedded rules", "error", err)
		return nil, fmt.Errorf("failed to load embedded rules: %w", err)
	}

	e := &Engine{Config: cfg}

	// Built-in rules carry an explicit severity (enforced by rules/catalog_test.go).
	for i := range loadedRules {
		resolveSeverity(&loadedRules[i], false)
		e.compileRule(&loadedRules[i])
	}

	// Load rule packs from ~/.aitriage/packs/
	if packRules, err := loadPackRules(); err == nil && len(packRules) > 0 {
		seen := make(map[string]bool, len(loadedRules))
		for _, r := range loadedRules {
			seen[r.ID] = true
		}
		for i, r := range packRules {
			if !seen[r.ID] {
				seen[r.ID] = true
				resolveSeverity(&packRules[i], true)
				e.compileRule(&packRules[i])
				loadedRules = append(loadedRules, packRules[i])
			}
		}
		slog.Debug("Loaded rule packs", "count", len(packRules))
	}

	// Add Custom Rules from Config
	if cfg != nil {
		for _, cr := range cfg.CustomRules {
			r := Rule{
				ID:         cr.ID,
				Name:       cr.Name,
				Stack:      cr.Stack,
				Extensions: cr.Extensions,
				Target:     cr.Target,
				Pattern:    cr.Pattern,
				Condition:  cr.Condition,
				Files:      cr.Files,
				Suggestion: cr.Suggestion,
				Severity:   cr.Severity,
			}
			resolveSeverity(&r, true)
			e.compileRule(&r)
			loadedRules = append(loadedRules, r)
		}
	}

	e.Rules = loadedRules
	return e, nil
}

// severities lists the values a rule severity may take.
var severities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}

// resolveSeverity normalizes a rule's severity. Built-in rules must declare it
// in the `severity` field. Rules from packs and project configuration predate
// that field, so for them a legacy "SEVERITY: " prefix of the suggestion is
// still honoured (and removed from the text). Anything else falls back to LOW
// with a warning, so a rule never runs with an empty severity.
func resolveSeverity(r *models.Rule, legacyPrefix bool) {
	sev := strings.ToUpper(strings.TrimSpace(r.Severity))
	if sev == "" && legacyPrefix {
		if prefix, rest, ok := strings.Cut(r.Suggestion, ": "); ok && severities[strings.ToUpper(prefix)] {
			sev, r.Suggestion = strings.ToUpper(prefix), rest
		}
	}
	if !severities[sev] {
		slog.Warn("Rule has no valid severity; using LOW", "rule", r.ID, "severity", r.Severity)
		sev = "LOW"
	}
	r.Severity = sev
}

// Run executes the engine against a ProjectContext using a Single-Pass O(N) architecture.
func (e *Engine) Run(ctx *core.ProjectContext) []core.CheckResult {
	var results []core.CheckResult
	var mu sync.Mutex

	var projectRules []Rule
	var fileRules []Rule

	// 1. Filter and categorize rules
	for _, rule := range e.Rules {
		if ctx.Config != nil && ctx.Config.IsRuleIgnored(rule.ID) {
			continue
		}
		if rule.Stack != "universal" && rule.Stack != ctx.Stack {
			continue
		}

		if rule.Condition == "missing_lockfile" || rule.Condition == "missing" || rule.Condition == "required_pattern" {
			projectRules = append(projectRules, rule)
		} else {
			fileRules = append(fileRules, rule)
		}
	}

	// 2. Evaluate Project Rules (File metadata only)
	var wgProj sync.WaitGroup
	for _, rule := range projectRules {
		wgProj.Add(1)
		go func(r Rule) {
			defer wgProj.Done()
			e.evaluateProjectRule(r, ctx, &results, &mu)
		}(rule)
	}
	wgProj.Wait()

	// 3. Single-Pass Execution: Loop over N files and evaluate M rules + Heuristics
	var wgFile sync.WaitGroup
	for _, file := range ctx.Files {
		if file.IsBinary {
			continue
		}

		wgFile.Add(1)
		go func(f *core.FileInfo) {
			defer wgFile.Done()

			// A. Mapped File Rules
			for _, rule := range fileRules {
				if !e.matchesExtension(rule, f) {
					continue
				}

				evidence, line := e.evaluateFile(rule, f)
				if evidence != "" {
					mu.Lock()
					results = append(results, core.CheckResult{
						ID:         rule.ID,
						Name:       rule.Name,
						Status:     core.Absent,
						Evidence:   fmt.Sprintf("Rule %s found issue in %s", rule.ID, f.Path),
						Suggestion: rule.Suggestion,
						Framework:  ctx.Stack,
						Severity:   rule.Severity,
						Line:       line,
						File:       f.Path,
					})
					mu.Unlock()
				}
			}

			// B. Entropy Checks
			if !f.IsTest {
				if entropyRes := e.evaluateEntropy(f); len(entropyRes) > 0 {
					mu.Lock()
					results = append(results, entropyRes...)
					mu.Unlock()
				}
			}

			// C. Entropy Pattern Heuristics
			if entrRes := e.evaluateEntropyPattern(f); len(entrRes) > 0 {
				mu.Lock()
				results = append(results, entrRes...)
				mu.Unlock()
			}
		}(file)
	}

	wgFile.Wait()
	return results
}

func (e *Engine) matchesExtension(r Rule, f *core.FileInfo) bool {
	for _, ext := range r.Extensions {
		if strings.EqualFold(ext, f.Extension) || strings.EqualFold(ext, filepath.Base(f.Path)) {
			return true
		}
	}
	return false
}

// matchesExcludedPath returns true if the file's project-relative path contains
// any of the rule's ExcludePaths fragments. Matching the absolute path would
// let the checkout location decide: a project cloned under .../seed-service/
// or .../scripts/ would silently lose the rule for every file.
func matchesExcludedPath(r Rule, f *core.FileInfo) bool {
	rel := projectRelPath(f)
	for _, frag := range r.ExcludePaths {
		if strings.Contains(rel, frag) {
			return true
		}
	}
	return false
}

// projectRelPath returns the file's path relative to the project root with
// forward slashes, falling back to Path for FileInfo values built without one.
func projectRelPath(f *core.FileInfo) string {
	if f.RelPath != "" {
		return f.RelPath
	}
	return filepath.ToSlash(f.Path)
}

func (e *Engine) evaluateProjectRule(rule Rule, ctx *core.ProjectContext, results *[]core.CheckResult, mu *sync.Mutex) {
	if rule.Condition == "missing_lockfile" {
		// Only ecosystems the project actually uses are considered. A PHP
		// project must have composer.lock; it must not be asked for go.sum.
		missing := missingLockEcosystems(rule, ctx.RootPath, ctx.ScanRoot)
		hasLock := len(missing) == 0

		if !hasLock {
			mu.Lock()
			*results = append(*results, core.CheckResult{
				ID: rule.ID, Name: rule.Name, Status: core.Absent,
				Evidence:   "No lockfile for " + strings.Join(missing, ", ") + " in " + ctx.RootPath,
				Suggestion: rule.Suggestion, Framework: rule.Stack, Severity: rule.Severity,
			})
			mu.Unlock()
		}
		return
	}

	if rule.Condition == "missing" && rule.Target == "filename" {
		found := false
		for _, ext := range rule.Extensions {
			files := ctx.FindFilesByExtension(ext)
			for _, f := range files {
				base := f.Path[strings.LastIndex(f.Path, "/")+1:]
				if rule.CompiledPattern != nil && rule.CompiledPattern.MatchString(base) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		if !found {
			mu.Lock()
			*results = append(*results, core.CheckResult{
				ID: rule.ID, Name: rule.Name, Status: core.Absent,
				Evidence:   "Missing required file matching: " + rule.Pattern,
				Suggestion: rule.Suggestion, Framework: rule.Stack, Severity: rule.Severity,
			})
			mu.Unlock()
		}
		return
	}

	if rule.Condition == "required_pattern" && rule.CompiledPattern != nil {
		found := false
		examined := 0 // number of candidate target files actually present
		for _, ext := range rule.Extensions {
			files := ctx.FindFilesByExtension(ext)
			for _, f := range files {
				if rule.ExcludeTests && f.IsTest {
					continue
				}
				if matchesExcludedPath(rule, f) {
					continue
				}
				examined++
				if rule.Regions != "" {
					if _, ok := e.regionMatch(rule, f, false); ok {
						found = true
						break
					}
					continue
				}
				var b []byte
				switch rule.Target {
				case "code":
					b, _ = f.GetStrippedContent()
				case "docs":
					b, _ = f.GetDocsOnlyContent()
				default:
					b, _ = f.GetContent()
				}
				if rule.CompiledPattern.Match(b) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		// A required-pattern rule only fires when the target file EXISTS but lacks
		// the pattern. With no target file present (e.g. no Dockerfile at all),
		// there is nothing to require — otherwise every project without that file
		// would be flagged, blocking clean scans.
		if examined > 0 && !found {
			mu.Lock()
			*results = append(*results, core.CheckResult{
				ID: rule.ID, Name: rule.Name, Status: core.Absent,
				Evidence:   "Required pattern not found: " + rule.Pattern,
				Suggestion: rule.Suggestion, Framework: rule.Stack, Severity: rule.Severity,
			})
			mu.Unlock()
		}
	}
}

// entropyAllowedExts — code and .env files, where the keyword-guarded assignment
// heuristic (`api_key = "…"`) is meaningful.
var entropyAllowedExts = map[string]bool{
	".go": true, ".py": true,
	".ts": true, ".tsx": true, ".js": true, ".jsx": true,
	".env": true,
}

// secretConfigExts — structured config where vendor-format signatures still run
// (a leaked AWS key or connection string in YAML/JSON is a real leak) but the
// noisier assignment heuristic is not applied.
var secretConfigExts = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".tf": true, ".ini": true, ".cfg": true, ".conf": true,
	".properties": true, ".xml": true,
}

// leakSinkRegexCache avoids recompiling the per-variable leak regex repeatedly.
func (e *Engine) evaluateEntropy(f *core.FileInfo) []core.CheckResult {
	// Skip test files — fixtures legitimately contain dummy tokens.
	if f.IsTest {
		return nil
	}
	if isVendoredPath(projectRelPath(f)) {
		return nil
	}

	base := strings.ToLower(filepath.Base(f.Path))
	isEnv := strings.Contains(base, ".env")
	scanAssign := entropyAllowedExts[f.Extension] || isEnv
	scanSignatures := scanAssign || secretConfigExts[f.Extension]
	if !scanSignatures {
		return nil
	}

	content, err := f.GetContent()
	if err != nil {
		return nil
	}
	src := string(content)
	lowerSrc := strings.ToLower(src)

	var results []core.CheckResult
	for _, h := range detectSecretHits(src, scanAssign) {
		id, name, severity := h.id, h.name, h.severity
		suggestion := "CRITICAL: hardcoded credential in source. Remove it, load the value from a secret manager or environment variable, and rotate the exposed credential."

		// Escalate when the secret is not only hardcoded but written to a log/print sink.
		if h.varName != "" && (strings.Contains(lowerSrc, "log") || strings.Contains(lowerSrc, "print") || strings.Contains(lowerSrc, "console")) {
			leakRe := regexp.MustCompile(`(?i)(?:log|print|console)\w*\s*\([^)]*` + regexp.QuoteMeta(h.varName) + `[^)]*\)`)
			if leakRe.MatchString(src) {
				id, name, severity = "SECRET-LEAK-LOG", "Hardcoded Secret Leaked to Logger", "CRITICAL"
				suggestion = "CRITICAL: secret is hardcoded AND passed to a log/print sink. Remove the secret, remove the log statement, and rotate the credential immediately."
			}
		}

		// Inline suppression: honour both the specific id and the legacy alias.
		if e.isLineIgnored(f, h.line, id) || e.isLineIgnored(f, h.line, "ENTROPY-SECRET") {
			continue
		}

		results = append(results, core.CheckResult{
			ID:         id,
			Name:       name,
			Status:     core.Absent,
			File:       f.Path,
			Line:       h.line,
			Evidence:   fmt.Sprintf("%s (%s)", name, h.evidence),
			Suggestion: suggestion,
			Severity:   severity,
		})
	}
	return results
}

// isVendoredPath reports whether a project-relative path is inside a
// dependency/VCS directory where hits are noise rather than the user's own
// leaked credentials. Only segments inside the project count, so a checkout
// under a directory such as /agent/build/ is still scanned. A committed build/
// directory is the project's own (container and CI files live there); build
// output is excluded through .gitignore instead, as in the scope filter.
func isVendoredPath(relPath string) bool {
	p := "/" + strings.TrimPrefix(filepath.ToSlash(relPath), "/")
	for _, seg := range []string{"/node_modules/", "/vendor/", "/.git/", "/dist/", "/.next/"} {
		if strings.Contains(p, seg) {
			return true
		}
	}
	return false
}

// evaluateEntropyPattern runs the file-level scaffolding-residue heuristic
// (ENTR-SLOP-01, see slop.go).
func (e *Engine) evaluateEntropyPattern(f *core.FileInfo) []core.CheckResult {
	if !slopExtensions[strings.ToLower(filepath.Ext(f.Path))] || isVendoredPath(projectRelPath(f)) {
		return nil
	}
	content, err := f.GetContent()
	if err != nil {
		return nil
	}
	src := string(content)
	count, line := countScaffoldingResidue(src, f.Path)
	if !excessiveResidue(count, lineCount(src)) {
		return nil
	}
	if e.isLineIgnored(f, line, "ENTR-SLOP-01") {
		return nil
	}
	return []core.CheckResult{{
		ID: "ENTR-SLOP-01", Name: "Excessive AI Scaffolding Residue", Status: core.Absent,
		File: f.Path, Line: line,
		Evidence:   fmt.Sprintf("Found %d scaffolding markers (TODO/FIXME notes, placeholder or temporary names); the first is on line %d.", count, line),
		Suggestion: "LOW: Code contains a high volume of scaffolding residue. Finish or remove the TODO/FIXME notes and placeholder code; this is a code-quality signal, not a vulnerability.",
		Severity:   "LOW",
	}}
}

func (e *Engine) evaluateFile(rule Rule, f *core.FileInfo) (string, int) {
	if rule.ExcludeTests && f.IsTest {
		return "", 0
	}
	if matchesExcludedPath(rule, f) {
		return "", 0
	}

	// 1. Handle logical Patterns (AND)
	if len(rule.Patterns) > 0 {
		var firstEvidence string
		var firstLine int
		for _, subRule := range rule.Patterns {
			ev, line := e.evaluateFile(subRule, f)
			if line == 0 {
				return "", 0 // One failed, all fail
			}
			if firstLine == 0 {
				firstEvidence, firstLine = ev, line
			}
		}
		return firstEvidence, firstLine
	}

	// 2. Handle logical PatternEither (OR)
	if len(rule.PatternEither) > 0 {
		for _, subRule := range rule.PatternEither {
			ev, line := e.evaluateFile(subRule, f)
			if line != 0 {
				return ev, line // One matched, we are good
			}
		}
		return "", 0
	}

	// Region-aware regex rules run over the raw file and filter matches by
	// where they start (code, comment, string literal).
	if rule.Regions != "" && rule.Target != "ast" && rule.Target != "condition" && rule.Pattern != "" {
		if !conditionAllows(rule, f) {
			return "", 0
		}
		if rule.CompiledNot != nil {
			if text, err := f.GetNonCommentContent(); err != nil || rule.CompiledNot.Match(text) {
				return "", 0
			}
		}
		if line, ok := e.regionMatch(rule, f, true); ok {
			return fmt.Sprintf("Rule %s triggered on %s", rule.ID, f.Path), line
		}
		return "", 0
	}

	// 3. Handle logical PatternNot
	if rule.PatternNot != "" {
		notRule := rule
		notRule.Pattern = rule.PatternNot
		notRule.CompiledPattern = rule.CompiledNot
		notRule.PatternNot = ""
		notRule.CompiledNot = nil
		_, line := e.evaluateFile(notRule, f)
		if line != 0 {
			return "", 0 // Matched the negative pattern
		}
		// If we are just a PatternNot, we need something else to match positively?
		// Semgrep usually uses PatternNot alongside other patterns.
		// If it's alone, it's weird, but we'll return 1 to indicate "valid" if not matched.
		if rule.Pattern == "" {
			return "PatternNot validated: not present", 1
		}
	}

	// 4. Base Pattern Match
	var targetStr string
	var err error

	switch rule.Target {
	case "code", "code_only", "": // Default is code
		b, err2 := f.GetStrippedContent()
		err = err2
		targetStr = string(b)
	case "docs":
		b, err2 := f.GetDocsOnlyContent()
		err = err2
		targetStr = string(b)
	case "all":
		b, err2 := f.GetContent()
		err = err2
		targetStr = string(b)
	case "condition":
		if rule.Condition == "large_file" {
			b, _ := f.GetContent()
			lines := strings.Count(string(b), "\n")
			if lines > 1500 {
				return fmt.Sprintf("File %s has %d lines (God File)", f.Path, lines), 1
			}
		}
		return "", 0
	case "ast":
		tree, err2 := f.GetTree()
		b, err3 := f.GetContent()
		if err2 == nil && err3 == nil {
			if !conditionAllows(rule, f) {
				return "", 0
			}
			lang, _ := ast.GetLanguage(f.Extension)
			matches, astErr := ast.MatchInTree(lang, tree, b, rule.Pattern)
			if astErr != nil {
				slog.Debug("AST rule query failed", "rule", rule.ID, "file", f.Path, "error", astErr)
			}
			for _, m := range matches {
				line := 1
				if m.Node != nil {
					line = int(m.Node.StartPosition().Row) + 1 // tree-sitter rows are 0-indexed
				}
				// An inline directive silences one occurrence, not the file.
				if !e.isLineIgnored(f, line, rule.ID) {
					return fmt.Sprintf("Rule %s triggered on %s", rule.ID, f.Path), line
				}
			}
			return "", 0
		}
		if err2 != nil {
			err = err2
		} else {
			err = err3
		}
	default:
		// Fallback to code if unknown
		b, _ := f.GetStrippedContent()
		targetStr = string(b)
	}

	if err != nil {
		return "", 0
	}

	if token, ok := strings.CutPrefix(rule.Condition, "not_contains:"); ok &&
		strings.Contains(strings.ToLower(targetStr), strings.ToLower(token)) {
		return "", 0
	}
	if token, ok := strings.CutPrefix(rule.Condition, "contains:"); ok &&
		!strings.Contains(strings.ToLower(targetStr), strings.ToLower(token)) {
		return "", 0
	}

	// Pattern Match
	if rule.Target == "ast" {
		return "", 0
	}

	if rule.Pattern != "" {
		// Prefer regex if already compiled, or try literal match if very simple
		if rule.CompiledPattern != nil {
			loc := rule.CompiledPattern.FindStringIndex(targetStr)
			if loc != nil {
				lineNumber := strings.Count(targetStr[:loc[0]], "\n") + 1
				if e.isLineIgnored(f, lineNumber, rule.ID) {
					return "", 0
				}
				return fmt.Sprintf("Rule %s triggered on %s", rule.ID, f.Path), lineNumber
			}
		} else {
			// Literal match fallback
			idx := strings.Index(targetStr, rule.Pattern)
			if idx != -1 {
				lineNumber := strings.Count(targetStr[:idx], "\n") + 1
				if e.isLineIgnored(f, lineNumber, rule.ID) {
					return "", 0
				}
				return fmt.Sprintf("Rule %s triggered on %s", rule.ID, f.Path), lineNumber
			}
		}
	}

	return "", 0
}

// regionMatch returns the line of the first match of the rule's pattern that
// starts in an allowed region and, when honourIgnore is set, is not silenced
// by an inline directive. Later matches are considered when earlier ones are
// rejected, so a comment or an ignored occurrence cannot hide a real one.
func (e *Engine) regionMatch(rule Rule, f *core.FileInfo, honourIgnore bool) (int, bool) {
	if rule.CompiledPattern == nil {
		return 0, false
	}
	content, err := f.GetContent()
	if err != nil {
		return 0, false
	}
	kinds, err := f.GetRegions()
	if err != nil || len(kinds) != len(content) {
		return 0, false
	}
	line, pos := 1, 0
	for _, loc := range rule.CompiledPattern.FindAllIndex(content, maxMatchesPerFile) {
		line += bytes.Count(content[pos:loc[0]], []byte{'\n'})
		pos = loc[0]
		if loc[0] < len(kinds) && !regionAllows(rule.Regions, kinds[loc[0]]) {
			continue
		}
		if honourIgnore && e.isLineIgnored(f, line, rule.ID) {
			continue
		}
		return line, true
	}
	return 0, false
}

// maxMatchesPerFile bounds the work spent on one pattern in one file.
const maxMatchesPerFile = 10000

// regionAllows reports whether a match starting in region kind counts for the
// rule's region filter.
func regionAllows(filter string, kind regions.Kind) bool {
	switch filter {
	case RegionsCode:
		return kind == regions.Code
	case RegionsCodeAndStrings:
		return kind != regions.Comment
	case RegionsComments:
		return kind == regions.Comment
	default: // RegionsAll
		return true
	}
}

// Region filters a rule may declare in its `regions` field.
const (
	RegionsCode           = "code"
	RegionsCodeAndStrings = "code_and_strings"
	RegionsComments       = "comments"
	RegionsAll            = "all"
)

// conditionAllows evaluates the file-level conditions of a rule over the file
// without its comments: `not_contains:A|B` drops the file when any token is
// present, `contains:A|B` keeps it only when one is. A comment that mentions
// a token neither suppresses nor enables a rule.
func conditionAllows(rule Rule, f *core.FileInfo) bool {
	negate := false
	tokens, ok := strings.CutPrefix(rule.Condition, "contains:")
	if !ok {
		if tokens, ok = strings.CutPrefix(rule.Condition, "not_contains:"); !ok {
			return true
		}
		negate = true
	}
	text, err := f.GetNonCommentContent()
	if err != nil {
		return false
	}
	lower := bytes.ToLower(text)
	found := false
	for _, token := range strings.Split(tokens, "|") {
		if token != "" && bytes.Contains(lower, []byte(strings.ToLower(token))) {
			found = true
			break
		}
	}
	return found != negate
}

// isLineIgnored reports whether an inline directive silences ruleID at line.
// The directive grammar lives in the suppression package, which also applies it
// to findings from the external scanners, so both read a comment identically.
func (e *Engine) isLineIgnored(f *core.FileInfo, line int, ruleID string) bool {
	content, err := f.GetContent()
	if err != nil {
		return false
	}
	return suppression.Suppressed(content, line, ruleID, config.CoreRuleSources...)
}

// missingLockEcosystems returns the names of package ecosystems that the project
// demonstrably uses (their manifest is present) but has not pinned with a
// lockfile. A project using no known ecosystem returns nothing: there is no
// dependency set to pin, so there is nothing to report.
func missingLockEcosystems(rule Rule, rootPath, scanRoot string) []string {
	ecosystems := rule.Ecosystems
	if len(ecosystems) == 0 {
		// Legacy rule shape: a flat list of lockfiles, any one of which counts.
		for _, lockFile := range rule.Files {
			if fileExistsAt(rootPath, lockFile) {
				return nil
			}
		}
		if len(rule.Files) == 0 {
			return nil
		}
		return []string{"dependencies"}
	}

	var missing []string
	for _, eco := range ecosystems {
		manifestPresent := false
		for _, manifest := range eco.Manifests {
			if fileExistsAt(rootPath, manifest) {
				manifestPresent = true
				break
			}
		}
		if !manifestPresent {
			continue // the project does not use this ecosystem
		}

		if !hasLockfile(eco, rootPath, scanRoot) {
			missing = append(missing, eco.Name)
		}
	}
	return missing
}

func hasLockfile(eco models.Ecosystem, rootPath, scanRoot string) bool {
	dir := rootPath
	for {
		for _, lockFile := range eco.Lockfiles {
			if fileExistsAt(dir, lockFile) && (dir == rootPath || npmWorkspaceContains(dir, rootPath)) {
				return true
			}
		}
		if !eco.WorkspaceRoot || !isStrictlyInside(dir, scanRoot) {
			return false
		}
		dir = filepath.Dir(dir)
	}
}

func isStrictlyInside(dir, root string) bool {
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func fileExistsAt(rootPath, name string) bool {
	_, err := os.Stat(filepath.Join(rootPath, name))
	return err == nil
}
