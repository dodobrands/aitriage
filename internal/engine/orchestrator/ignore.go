package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// ignore.rules used to reach only the YAML rules of the built-in engine: the
// engine's own heuristics (ENTR-SLOP-01, SECRET-*), the external scanners'
// rule ids (B105, generic-api-key, CVE-…), NFR checks, deploy issues and
// network findings all ignored it, so a project could not silence any of them.
// Inline "aitriage-ignore" comments had the same gap: only the built-in engine
// read them. applyProjectSuppressions closes both, once, after every scanner
// has finished.

// applyProjectSuppressions removes the findings the project has told AITriage
// not to report and records what it removed:
//   - ignore.rules entries apply to every source. A bare id matches any
//     source; "gitleaks:generic-api-key", "trivy:CVE-2024-1234" or
//     "semgrep:<check-id>" match only that scanner.
//   - Inline directives apply to external-scanner and deploy-audit findings on
//     the directive's line or the line below it, or anywhere in the file for a
//     file-level directive. The built-in engine reads them itself while it
//     scans.
//
// Removal is what ignore.rules has always meant ("rule IDs the scanner should
// completely ignore"): unlike a dismissal recorded with "aitriage ignore add",
// the decision lives in the configuration and has no per-finding review trail.
// The counts keep it visible.
func applyProjectSuppressions(result *llm.RichScanResult) {
	if result == nil {
		return
	}
	rules := config.NewRuleMatcher(ignoreRules(result))
	files := &sourceFiles{root: result.ProjectPath, cache: map[string][]byte{}}

	ignored := map[string]int{}
	// The built-in engine already applied ignore.rules while scanning; carry
	// its counts over so the total covers every source.
	for entry, count := range result.Report.IgnoredByConfig {
		ignored[entry] += count
	}
	inline := map[string]int{}

	if !rules.Empty() {
		keptCore := result.Report.Results[:0]
		for _, finding := range result.Report.Results {
			if entry, ok := rules.Match(finding.ID, config.CoreRuleSources...); ok {
				ignored[entry]++
				continue
			}
			keptCore = append(keptCore, finding)
		}
		result.Report.Results = keptCore
	}

	keptExternal := result.External[:0]
	for _, finding := range result.External {
		sources := externalRuleSources(finding)
		if entry, ok := rules.Match(finding.RuleID, sources...); ok {
			ignored[entry]++
			continue
		}
		if files.suppressed(finding.File, finding.Line, finding.RuleID, sources...) {
			inline[sources[0]+":"+finding.RuleID]++
			continue
		}
		keptExternal = append(keptExternal, finding)
	}
	result.External = keptExternal

	keptNFR := result.NFR[:0]
	for _, finding := range result.NFR {
		if entry, ok := rules.Match(finding.RuleID, config.NFRRuleSources...); ok {
			ignored[entry]++
			continue
		}
		keptNFR = append(keptNFR, finding)
	}
	result.NFR = keptNFR

	keptDeploy := result.Deploy[:0]
	for _, finding := range result.Deploy {
		if entry, ok := rules.Match(finding.Issue, config.DeployRuleSources...); ok {
			ignored[entry]++
			continue
		}
		if files.suppressed(finding.File, finding.Line, finding.Issue, config.DeployRuleSources...) {
			inline["deploy:"+finding.Issue]++
			continue
		}
		keptDeploy = append(keptDeploy, finding)
	}
	result.Deploy = keptDeploy

	keptNetwork := result.Network[:0]
	for _, finding := range result.Network {
		if entry, ok := rules.Match(networkRuleID(finding.Port), config.NetworkRuleSources...); ok {
			ignored[entry]++
			continue
		}
		keptNetwork = append(keptNetwork, finding)
	}
	result.Network = keptNetwork

	if len(ignored) > 0 {
		result.IgnoredByConfig = ignored
	}
	if len(inline) > 0 {
		result.SuppressedInline = inline
	}
}

// ignoreRules returns ignore.rules from the configuration the built-in engine
// loaded for this scan, or reads it when the engine did not run.
func ignoreRules(result *llm.RichScanResult) []string {
	if result.Report.Config != nil {
		return result.Report.Config.Ignore.Rules
	}
	if strings.TrimSpace(result.ProjectPath) == "" {
		return nil
	}
	return config.LoadIgnore(result.ProjectPath).Rules
}

// externalRuleSources names the source an external finding answers to in a
// qualified reference. The first name keys the inline-suppression count.
func externalRuleSources(finding external.UnifiedFinding) []string {
	if source := strings.ToLower(strings.TrimSpace(finding.Source)); source != "" {
		return []string{source}
	}
	return []string{"external"}
}

// networkRuleID is the id a network finding is reported under, the one AI
// triage and its artifacts show ("port-53"), so the same string ignores it.
func networkRuleID(port int) string {
	return fmt.Sprintf("port-%d", port)
}

// maxInlineScanBytes bounds what is read when looking for directives; the
// built-in engine does not analyse larger files either.
const maxInlineScanBytes = 10 << 20

// sourceFiles reads each file findings point at once, for inline directives.
type sourceFiles struct {
	root  string
	cache map[string][]byte
}

func (s *sourceFiles) suppressed(file string, line int, ruleID string, sources ...string) bool {
	if strings.TrimSpace(file) == "" {
		return false
	}
	content, ok := s.cache[file]
	if !ok {
		content = readSourceFile(s.root, file)
		s.cache[file] = content
	}
	return len(content) > 0 && suppression.Suppressed(content, line, ruleID, sources...)
}

// readSourceFile resolves a path the way the tools report it: absolute, or
// relative to the project root, or else relative to the working directory.
// Unreadable, irregular and oversized files yield nothing, so a finding in
// them simply stays reported.
func readSourceFile(root, file string) []byte {
	path := file
	if !filepath.IsAbs(path) && root != "" {
		if candidate := filepath.Join(root, path); fileExists(candidate) {
			path = candidate
		}
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxInlineScanBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
