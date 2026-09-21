package external

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	ignore "github.com/sabhiram/go-gitignore"
)

// AITriage's own engine has always honoured .gitignore and skipped vendored
// dependency trees. External scanners run as separate processes and knew none of
// it, so a project would be told that its committed-by-nobody .env is a critical
// leak and that a vendored AWS SDK is its own insecure code.
//
// This file is the single place that decides what is out of scope, and it is
// applied twice: as arguments to each tool (cheap, keeps the scan fast) and as a
// filter over the findings that come back (authoritative, tool-independent).

// vendoredDirs are directories holding third-party or generated code. A finding
// inside them is not something the project's authors can fix in their own
// source, so reporting it as their vulnerability is noise.
var vendoredDirs = []string{
	"vendor",
	"node_modules",
	"bower_components",
	"dist",
	"build",
	".next",
	".nuxt",
	"__pycache__",
	"venv",
	".venv",
	"site-packages",
	".git",
}

// generatedDirNames are AITriage's own artifact directories, kept separate
// because they are excluded even when vendored-code filtering is disabled.
var generatedDirNames = []string{"aitriage-reports", ".aitriage", ".aitriage-cache"}

// ExcludedDirNames returns every directory name external scanners should skip.
func ExcludedDirNames() []string {
	names := make([]string, 0, len(vendoredDirs)+len(generatedDirNames))
	names = append(names, generatedDirNames...)
	if scanVendoredCode() {
		return names
	}
	names = append(names, vendoredDirs...)
	return names
}

// scanVendoredCode reports whether the caller explicitly asked to scan vendored
// and generated trees anyway.
func scanVendoredCode() bool {
	return envFlag("AITRIAGE_SCAN_VENDORED")
}

// respectGitignore reports whether ignored files are out of scope. It is on by
// default: a file git does not track is not part of the delivered application.
// Set AITRIAGE_RESPECT_GITIGNORE=false to audit ignored files too, which is what
// you want when the question is "did a secret ever reach this working tree".
func respectGitignore() bool {
	if raw, ok := os.LookupEnv("AITRIAGE_RESPECT_GITIGNORE"); ok {
		if parsed, err := strconv.ParseBool(strings.TrimSpace(raw)); err == nil {
			return parsed
		}
	}
	return true
}

func envFlag(name string) bool {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	return err == nil && parsed
}

// ScopeFilter decides whether a scanned path is in scope for a project.
type ScopeFilter struct {
	root      string
	gitignore *ignore.GitIgnore
	aitriage  *ignore.GitIgnore
	skipDirs  map[string]struct{}
}

// filterCache keeps one filter per root: the ignore files are read once per
// scan rather than once per finding.
var (
	filterMu    sync.Mutex
	filterCache = map[string]*ScopeFilter{}
)

// NewScopeFilter builds the in-scope decision for a project root.
func NewScopeFilter(root string) *ScopeFilter {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}

	filterMu.Lock()
	defer filterMu.Unlock()
	if cached, ok := filterCache[abs]; ok {
		return cached
	}

	f := &ScopeFilter{root: abs, skipDirs: map[string]struct{}{}}
	for _, name := range ExcludedDirNames() {
		f.skipDirs[name] = struct{}{}
	}
	if respectGitignore() {
		if compiled, err := ignore.CompileIgnoreFile(filepath.Join(abs, ".gitignore")); err == nil {
			f.gitignore = compiled
		}
	}
	// .aitriageignore is always honoured: it exists for no other purpose.
	if compiled, err := ignore.CompileIgnoreFile(filepath.Join(abs, ".aitriageignore")); err == nil {
		f.aitriage = compiled
	}

	filterCache[abs] = f
	return f
}

// ResetScopeFilterCache clears memoized filters. Tests that write ignore files
// into a reused path need it; production scans do not.
func ResetScopeFilterCache() {
	filterMu.Lock()
	defer filterMu.Unlock()
	filterCache = map[string]*ScopeFilter{}
}

// InScope reports whether a path reported by a scanner belongs to the audited
// application. Paths are accepted in whatever shape a tool emits them: absolute,
// relative to the root, or relative to the current directory.
func (f *ScopeFilter) InScope(path string) bool {
	if f == nil {
		return true
	}
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	if clean == "" || clean == "." {
		return true
	}

	for _, segment := range strings.Split(clean, "/") {
		if _, skip := f.skipDirs[segment]; skip {
			return false
		}
	}

	rel := f.relativize(clean)
	if rel == "" {
		return true
	}
	if f.aitriage != nil && f.aitriage.MatchesPath(rel) {
		return false
	}
	if f.gitignore != nil && f.gitignore.MatchesPath(rel) {
		return false
	}
	return true
}

// relativize expresses a scanner-reported path relative to the project root so
// it can be matched against ignore patterns, which are root-relative.
func (f *ScopeFilter) relativize(clean string) string {
	root := filepath.ToSlash(f.root)
	if strings.HasPrefix(clean, root+"/") {
		return strings.TrimPrefix(clean, root+"/")
	}
	if clean == root {
		return ""
	}
	// Container runs report paths under the mounted source root rather than the
	// host path, so fall back to the tail after a known mount point.
	for _, mount := range []string{"/workspace/", "/src/", "/app/"} {
		if idx := strings.Index(clean, mount); idx >= 0 {
			return clean[idx+len(mount):]
		}
	}
	return strings.TrimPrefix(clean, "/")
}

// FilterOutOfScope drops findings that point outside the audited application.
// It runs after every external scanner, so a tool that ignores its exclusion
// arguments still cannot put vendored or ignored files into a report.
func FilterOutOfScope(root string, findings []UnifiedFinding) []UnifiedFinding {
	filter := NewScopeFilter(root)
	kept := make([]UnifiedFinding, 0, len(findings))
	for _, finding := range findings {
		// A project-level finding carries no file; it is always in scope.
		if strings.TrimSpace(finding.File) == "" || filter.InScope(finding.File) {
			kept = append(kept, finding)
		}
	}
	return kept
}

// SemgrepExcludeArgs renders the exclusion set as Semgrep --exclude arguments.
func SemgrepExcludeArgs() []string {
	args := make([]string, 0, len(ExcludedDirNames())*2)
	for _, name := range ExcludedDirNames() {
		args = append(args, "--exclude", name)
	}
	return args
}

// TrivySkipDirArgs renders the exclusion set as Trivy --skip-dirs arguments.
// Trivy matches on paths, so each name is given as a recursive glob.
func TrivySkipDirArgs(root string) []string {
	args := make([]string, 0, len(ExcludedDirNames())*4)
	for _, name := range ExcludedDirNames() {
		args = append(args, "--skip-dirs", filepath.Join(root, name))
		args = append(args, "--skip-dirs", filepath.Join("**", name))
	}
	return args
}

// GitleaksAllowlistPattern renders the exclusion set as one regex for the
// gitleaks config allowlist. Gitleaks v8 has no directory-exclude flag, so the
// generated config is the only way to keep it out of vendored trees.
func GitleaksAllowlistPattern() string {
	names := ExcludedDirNames()
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, strings.ReplaceAll(name, ".", "[.]"))
	}
	return `(^|/)(` + strings.Join(quoted, "|") + `)(/|$)`
}
