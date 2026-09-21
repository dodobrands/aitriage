package external

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner/pathpolicy"
)

var generatedArtifactDirs = map[string]struct{}{
	"aitriage-reports": {},
	".aitriage":        {}, // legacy layout
	".aitriage-cache":  {}, // legacy layout
}

// FilterTestLikeFindings applies the same non-production path policy to every
// external scanner. Scanning may still inspect tests for tool completeness,
// but test assertions and fixture credentials must not consume AI triage turns
// or appear as production vulnerabilities.
func FilterTestLikeFindings(findings []UnifiedFinding) []UnifiedFinding {
	filtered := make([]UnifiedFinding, 0, len(findings))
	for _, finding := range findings {
		if pathpolicy.IsTestLike(finding.File) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

// isGeneratedArtifactPath is the defensive last line against scanners
// reporting AITriage's own generated files. Tool-level excludes prevent those
// files from being read; this filter also protects against scanner-specific
// path quirks or a future argument regression.
func isGeneratedArtifactPath(path string) bool {
	clean := strings.ReplaceAll(filepath.ToSlash(filepath.Clean(path)), `\`, "/")
	for _, part := range strings.Split(clean, "/") {
		if _, ok := generatedArtifactDirs[part]; ok {
			return true
		}
	}
	return false
}

func generatedArtifactPaths(root string) []string {
	paths := make([]string, 0, len(generatedArtifactDirs))
	for _, name := range []string{"aitriage-reports", ".aitriage", ".aitriage-cache"} {
		paths = append(paths, filepath.Join(root, name))
	}
	return paths
}

// newGitleaksConfig extends the built-in rules with a global path allowlist.
// Gitleaks v8 has no CLI directory-exclude flag, so the config is the only way
// to prevent generated reports from being read while keeping the default rules.
func newGitleaksConfig() (string, func(), error) {
	f, err := os.CreateTemp("", "aitriage-gitleaks-*.toml")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	content := fmt.Sprintf("[extend]\nuseDefault = true\n\n[allowlist]\n"+
		"description = \"AITriage out-of-scope paths\"\n"+
		"paths = ['''%s''']\n", GitleaksAllowlistPattern())
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return f.Name(), cleanup, nil
}
