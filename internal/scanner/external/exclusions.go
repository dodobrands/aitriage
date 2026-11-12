package external

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/config"
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
//
// "build" is deliberately absent. Generated build output is git-ignored in
// practically every ecosystem's default .gitignore, and .gitignore is honoured
// by default; a build directory that is committed is the project's own, such as
// Go's build/package/Dockerfile and build/ci scripts, which hold exactly the
// container and pipeline configuration a security audit must see. "dist" stays:
// committed bundles (a JavaScript action's dist/index.js) inline third-party
// dependencies.
var vendoredDirs = []string{
	"vendor",
	"node_modules",
	"bower_components",
	"dist",
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
//
// It combines four sources, all matched against root-relative paths: vendored
// and generated directory names, .gitignore (unless disabled), .aitriageignore,
// and ignore.paths from the project configuration. The last two are always
// honoured: they exist for no other purpose. The three pattern sources share
// one matcher, config.PathMatcher, with the built-in engine's file walker, so
// both draw the same line.
type ScopeFilter struct {
	root      string
	realRoot  string // root with symlinks resolved, when that differs
	gitignore *config.PathMatcher
	aitriage  *config.PathMatcher
	paths     *config.PathMatcher
	skipDirs  map[string]struct{}
	stamp     scopeStamp
}

// scopeStamp identifies the inputs a filter was built from. A long-running
// process (the Web UI, watch mode) rebuilds the filter when one of them changes
// rather than applying stale ignore rules to a new scan.
type scopeStamp struct {
	ignoreFiles     string
	honourGitignore bool
	scanVendored    bool
}

func currentStamp(root string) scopeStamp {
	var b strings.Builder
	names := append([]string{".gitignore", ".aitriageignore"}, config.ConfigFileNames()...)
	for _, name := range names {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			b.WriteString("-;")
			continue
		}
		fmt.Fprintf(&b, "%d:%d;", info.Size(), info.ModTime().UnixNano())
	}
	return scopeStamp{ignoreFiles: b.String(), honourGitignore: respectGitignore(), scanVendored: scanVendoredCode()}
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
	stamp := currentStamp(abs)

	filterMu.Lock()
	defer filterMu.Unlock()
	if cached, ok := filterCache[abs]; ok && cached.stamp == stamp {
		return cached
	}

	f := &ScopeFilter{root: abs, skipDirs: map[string]struct{}{}, stamp: stamp}
	// Tools may report paths through the resolved root (macOS /var is
	// /private/var); those are still the project's own paths.
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		f.realRoot = real
	}
	for _, name := range ExcludedDirNames() {
		f.skipDirs[name] = struct{}{}
	}
	if stamp.honourGitignore {
		f.gitignore = config.ReadIgnoreFile(filepath.Join(abs, ".gitignore"))
	}
	f.aitriage = config.ReadIgnoreFile(filepath.Join(abs, ".aitriageignore"))
	f.paths = config.NewPathMatcher(config.LoadIgnore(abs).Paths)

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

// InScope reports whether a file reported by a scanner belongs to the audited
// application. Paths are accepted in whatever shape a tool emits them: absolute,
// or relative to the root. A relative path is always read as relative to the
// root, so a walker started from a relative root should pass filepath.Rel(root,
// path), not the walked path.
func (f *ScopeFilter) InScope(path string) bool {
	return f.inScope(path, false)
}

// DirInScope reports whether a walker should descend into a directory. False
// means nothing below it can be in scope; walkers use it to skip whole trees
// instead of asking InScope about every file inside. Paths follow the same
// rules as for InScope.
func (f *ScopeFilter) DirInScope(path string) bool {
	return f.inScope(path, true)
}

func (f *ScopeFilter) inScope(path string, dir bool) bool {
	if f == nil {
		return true
	}
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	if clean == "" || clean == "." {
		return true
	}

	rel := f.relativize(clean)
	if rel == "" {
		return true
	}

	// Directory names are judged below the project root only. A checkout
	// under /opt/atlassian/pipelines/agent/build or /home/dev/dist/app is not
	// generated code, and judging the whole absolute path dropped every
	// finding of such a project.
	for _, segment := range strings.Split(rel, "/") {
		if _, skip := f.skipDirs[segment]; skip {
			return false
		}
	}

	// Each source decides on its own: a negation in one never re-includes what
	// another excludes. A directory is pruned only when one source excludes it
	// with nothing below it that a negation of that source could re-include.
	if dir {
		return !f.paths.ExcludesTree(rel) && !f.aitriage.ExcludesTree(rel) && !f.gitignore.ExcludesTree(rel)
	}
	return !f.paths.Excludes(rel, false) && !f.aitriage.Excludes(rel, false) && !f.gitignore.Excludes(rel, false)
}

// containerMounts are the directories AITriage's container runs mount the
// project at: the GitHub Action workspace, the runtime's /workspace, the
// Docker escalation's /project, and two common conventions.
var containerMounts = []string{"/github/workspace", "/workspace", "/project", "/src", "/app"}

// relativize expresses a scanner-reported path relative to the project root so
// it can be matched against ignore patterns, which are root-relative.
func (f *ScopeFilter) relativize(clean string) string {
	for _, root := range []string{f.root, f.realRoot} {
		if root == "" {
			continue
		}
		root = filepath.ToSlash(root)
		if clean == root {
			return ""
		}
		if prefix := strings.TrimSuffix(root, "/") + "/"; strings.HasPrefix(clean, prefix) {
			return strings.TrimPrefix(clean, prefix)
		}
	}
	// Relative paths are reported against the project root: Trivy targets and
	// git history always are, and the other tools are when the root is the
	// working directory.
	if !strings.HasPrefix(clean, "/") {
		return clean
	}
	// A container run reports paths under the directory the project was
	// mounted at rather than the host path this filter was built for. Only a
	// path that starts with a mount point is read that way: "/src/" or "/app/"
	// deeper in a path is an ordinary directory of the project.
	for _, mount := range containerMounts {
		if strings.HasPrefix(clean, mount+"/") {
			return strings.TrimPrefix(clean, mount+"/")
		}
	}
	// A path that cannot be placed under the root is judged whole.
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

// toolPattern is an ignore.paths entry in a shape the bundled tools can apply.
type toolPattern struct {
	glob     string // the pattern without a leading or trailing slash
	anchored bool   // matches from the project root only
	dirOnly  bool   // matches a directory and its contents, never a file
	wildcard bool   // contains * or **
}

// toolPatterns returns the ignore.paths entries the bundled tools can be told
// about. An argument that excludes more than the scope filter loses coverage
// the post-filter can never restore, so anything doubtful is left to the
// post-filter alone:
//   - with a negated entry present, none are passed: an argument cannot say
//     "except";
//   - entries using ?, [ ], { } or backslash escapes are skipped, because the
//     tools read them differently from git and from each other.
//
// Anchoring comes from the scope filter's own parse, which follows git: an
// entry with a slash before its last character ("app/legacy/") is anchored at
// the root even without a leading slash. Every tool is told so explicitly,
// because not every tool anchors such an entry by itself.
func (f *ScopeFilter) toolPatterns() []toolPattern {
	if f == nil || f.paths.Empty() || f.paths.HasNegation() {
		return nil
	}
	var patterns []toolPattern
	for _, rule := range f.paths.Rules() {
		if strings.ContainsAny(rule.Glob, `?[]{}\`) {
			continue
		}
		patterns = append(patterns, toolPattern{
			glob: rule.Glob,
			// A leading "**/" matches at any depth, which every tool
			// already reads the same way without an anchor.
			anchored: rule.Anchored && !strings.HasPrefix(rule.Glob, "**/"),
			dirOnly:  rule.DirOnly,
			wildcard: strings.Contains(rule.Glob, "*"),
		})
	}
	return patterns
}

// SemgrepExcludeArgs renders the exclusion set as Semgrep --exclude arguments.
// ignore.paths entries are passed in their own .gitignore syntax, which is the
// syntax Semgrep's --exclude documents; an entry anchored at the root always
// carries a leading slash, so Semgrep never matches it at a deeper level.
func SemgrepExcludeArgs(root string) []string {
	args := make([]string, 0, len(ExcludedDirNames())*2)
	for _, name := range ExcludedDirNames() {
		args = append(args, "--exclude", name)
	}
	for _, tp := range NewScopeFilter(root).toolPatterns() {
		pattern := tp.glob
		if tp.anchored {
			pattern = "/" + pattern
		}
		if tp.dirOnly {
			pattern += "/"
		}
		args = append(args, "--exclude", pattern)
	}
	return args
}

// TrivySkipDirArgs renders the exclusion set as Trivy --skip-dirs and
// --skip-files arguments. Trivy matches doublestar globs against root-relative
// paths and converts absolute paths under the target to root-relative ones, so
// an unanchored entry becomes "**/entry" and an anchored one an absolute path.
func TrivySkipDirArgs(root string) []string {
	args := make([]string, 0, len(ExcludedDirNames())*4)
	for _, name := range ExcludedDirNames() {
		args = append(args, "--skip-dirs", filepath.Join(root, name))
		args = append(args, "--skip-dirs", filepath.Join("**", name))
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	for _, tp := range NewScopeFilter(root).toolPatterns() {
		target := tp.glob
		switch {
		case tp.anchored:
			target = filepath.ToSlash(filepath.Join(abs, tp.glob))
		case !strings.HasPrefix(target, "**/"):
			target = "**/" + target
		}
		args = append(args, "--skip-dirs", target)
		if !tp.dirOnly {
			args = append(args, "--skip-files", target)
		}
	}
	return args
}

// gitleaksAllowlistPaths returns the gitleaks allowlist path regexes for a
// scan of source: one for the vendored and generated directories and one per
// ignore.paths entry. Gitleaks v8 has no directory-exclude flag, so the
// generated config is the only way to keep it out of excluded trees.
//
// Gitleaks matches the allowlist against paths as it walks them, which start
// with the --source argument, and it skips a whole directory whose path
// matches, the source itself included. Every regex is therefore anchored at
// the source: a project checked out under /ci/build/app or /home/dev/vendor/app
// is still scanned, as the scope filter would keep its findings.
func gitleaksAllowlistPaths(source string) []string {
	anchor := `^(?:` + strings.Join(gitleaksPathPrefixes(source), "|") + `)`

	names := ExcludedDirNames()
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, strings.ReplaceAll(name, ".", "[.]"))
	}
	paths := []string{anchor + `(?:[^/]+/)*(?:` + strings.Join(quoted, "|") + `)(?:/|$)`}

	for _, tp := range NewScopeFilter(source).toolPatterns() {
		var b strings.Builder
		b.WriteString(anchor)
		if !tp.anchored {
			b.WriteString(`(?:[^/]+/)*`)
		}
		b.WriteString(globRegex(tp.glob))
		if tp.dirOnly {
			b.WriteString(`/`)
		} else {
			b.WriteString(`(?:/|$)`)
		}
		paths = append(paths, b.String())
	}
	return paths
}

// gitleaksPathPrefixes returns the quoted forms the source can take at the
// start of a walked path: as given, and absolute.
func gitleaksPathPrefixes(source string) []string {
	var prefixes []string
	seen := map[string]bool{}
	add := func(path string) {
		prefix := filepath.ToSlash(filepath.Clean(path))
		switch prefix {
		case ".":
			prefix = ""
		case "/":
		default:
			prefix += "/"
		}
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, regexp.QuoteMeta(prefix))
		}
	}
	add(source)
	if abs, err := filepath.Abs(source); err == nil {
		add(abs)
	}
	return prefixes
}

// globRegex translates a .gitignore glob into a regex body: "*" stays within a
// path segment, "**/" spans zero or more directories and a trailing "**"
// spans everything below.
func globRegex(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			b.WriteString(`(?:[^/]+/)*`)
			i += 2
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(`.*`)
			i++
		case glob[i] == '*':
			b.WriteString(`[^/]*`)
		default:
			b.WriteString(regexp.QuoteMeta(glob[i : i+1]))
		}
	}
	return b.String()
}

// banditExcludePaths renders the exclusion set for Bandit's -x option.
//
// Bandit drops a file when its path, as walked from the target, matches an
// entry with fnmatch (where "*" also crosses "/") or merely contains an entry
// as a substring. A bare name such as "vendor" would therefore also drop
// "src/vendors/". Every entry is written as a directory below the target
// ("<target>/vendor/" and "<target>/*/vendor/*"), which matches exactly the
// directories the scope filter drops and nothing else. Entries with wildcards
// are left to the post-filter: fnmatch cannot keep "*" inside one segment.
func banditExcludePaths(target string) []string {
	paths := generatedArtifactPaths(target)

	slashed := filepath.ToSlash(target)
	if slashed == "" {
		return paths
	}
	// For the filesystem root the base is empty and entries start with "/".
	base := strings.TrimRight(slashed, "/")
	// fnmatch would read these characters in the project path itself as
	// wildcards, and a comma would split the -x list.
	if strings.ContainsAny(base, "*?[],") {
		return paths
	}

	addDir := func(glob string, anchored bool) {
		if strings.Contains(glob, ",") {
			return
		}
		paths = append(paths, base+"/"+glob+"/")
		if !anchored {
			paths = append(paths, base+"/*/"+glob+"/*")
		}
	}
	if !scanVendoredCode() {
		for _, name := range vendoredDirs {
			addDir(name, false)
		}
	}
	for _, tp := range NewScopeFilter(target).toolPatterns() {
		if tp.wildcard {
			continue
		}
		addDir(tp.glob, tp.anchored)
	}
	return paths
}
