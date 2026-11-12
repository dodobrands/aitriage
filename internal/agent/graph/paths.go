package graph

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ── Project-relative paths ───────────────────────────────────────────────────
//
// Scanners report paths the way they were invoked: the built-in engine,
// Bandit, Gitleaks and the deploy audit return absolute paths when AITriage
// is given an absolute project path, Trivy returns paths relative to the scan
// target. In CI that put /github/workspace/... into every artifact, and two
// detectors of one defect could not even be compared. Every finding is
// expressed relative to the project root, with forward slashes, as it enters
// the triage graph; everything downstream (prompts, triage-findings.json,
// summary, report, fix spec) inherits that.

// ProjectRelativePath expresses a scanner-reported path relative to the
// project root, with forward slashes. A path outside the root stays absolute:
// rewriting it would point at a file that does not exist.
func ProjectRelativePath(projectPath, file string) string {
	return newPathResolver(projectPath).relative(file)
}

// pathResolver relativizes paths against one project root.
type pathResolver struct {
	// root is the absolute project root; roots also holds the root with
	// symlinks resolved (macOS reports /var as /private/var).
	root  string
	roots []string
	// bareRoots match a root mentioned in text without a path below it.
	bareRoots []*regexp.Regexp
}

func newPathResolver(projectPath string) pathResolver {
	abs, err := filepath.Abs(strings.TrimSpace(projectPath))
	if err != nil {
		abs = filepath.Clean(projectPath)
	}
	r := pathResolver{root: abs}
	candidates := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		candidates = append(candidates, real)
	}
	for _, root := range candidates {
		root = strings.TrimSuffix(filepath.ToSlash(root), "/")
		if root == "" {
			// The filesystem root: nothing to strip, every path is below it.
			continue
		}
		r.roots = append(r.roots, root)
		r.bareRoots = append(r.bareRoots, regexp.MustCompile(regexp.QuoteMeta(root)+`($|[\s"'),;:\]])`))
	}
	return r
}

func (r pathResolver) relative(file string) string {
	file = strings.TrimSpace(file)
	if file == "" {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(file))
	if filepath.IsAbs(file) {
		if rel, ok := r.underRoot(clean); ok {
			return rel
		}
		return clean
	}
	clean = strings.TrimPrefix(clean, "./")
	// A relative path is read against the project root (Trivy targets are).
	// A tool started from another working directory reports paths relative
	// to that directory instead; such a path is only recognised when it does
	// not also name a file under the root.
	if r.root != "" && !fileExists(filepath.Join(r.root, filepath.FromSlash(clean))) {
		if abs, err := filepath.Abs(file); err == nil {
			if rel, ok := r.underRoot(filepath.ToSlash(abs)); ok {
				return rel
			}
		}
	}
	return clean
}

// underRoot returns the part of an absolute slash path below the root.
func (r pathResolver) underRoot(clean string) (string, bool) {
	for _, root := range r.roots {
		if clean == root {
			return ".", true
		}
		if prefix := root + "/"; strings.HasPrefix(clean, prefix) {
			return strings.TrimPrefix(clean, prefix), true
		}
	}
	return "", false
}

// stripRoot removes the project root from free text such as a scanner
// message ("Rule X found issue in /github/workspace/main.py"), so messages
// carry the same project-relative paths as the findings.
func (r pathResolver) stripRoot(text string) string {
	for i, root := range r.roots {
		if !strings.Contains(text, root) {
			continue
		}
		text = strings.ReplaceAll(text, root+"/", "")
		// The root itself, not followed by more of a path, is the project.
		text = r.bareRoots[i].ReplaceAllString(text, ".$1")
	}
	return text
}

// absolute returns the filesystem path of a project-relative path.
func (r pathResolver) absolute(file string) string {
	if file == "" || filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(r.root, filepath.FromSlash(file))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
