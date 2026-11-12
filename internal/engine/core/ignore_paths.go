package core

import (
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ignore.paths used to be matched as a substring of each directory's absolute
// path. That excluded far more than anyone wrote: "vendor" also dropped
// "src/vendors/", ".git" dropped ".github/", and a project checked out under a
// directory whose name contained a pattern was not scanned at all. Patterns now
// follow .gitignore syntax (config.PathMatcher), which also means some paths the
// old rule hid are scanned again. For one release, legacyIgnoreWarner names each
// pattern that no longer hides what it used to, and the path to add to keep it
// hidden, so the change in results is never silent.

// warnLegacyIgnorePath reports one compatibility warning. Tests replace it to
// capture the warnings.
var warnLegacyIgnorePath = func(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// warnedLegacyPatterns remembers which root/pattern pairs were reported, so a
// long-running process (the Web UI, watch mode) warns once, not on every scan.
var warnedLegacyPatterns sync.Map

// legacyIgnoreWarner compares directories against the old substring rule.
type legacyIgnoreWarner struct {
	root     string
	patterns []string // entries as written
	needles  []string // the same entries trimmed of slashes, as the old rule used them
}

func newLegacyIgnoreWarner(root string, patterns []string) *legacyIgnoreWarner {
	w := &legacyIgnoreWarner{root: root}
	for _, raw := range patterns {
		needle := strings.Trim(raw, "/")
		// An empty needle matched every path under the old rule; it only comes
		// from an entry that is blank or a bare "/", which nobody writes on
		// purpose, so it is not worth a warning.
		if strings.TrimSpace(needle) == "" {
			continue
		}
		w.patterns = append(w.patterns, raw)
		w.needles = append(w.needles, needle)
	}
	return w
}

// checkRoot warns about patterns the old rule matched against the project
// directory itself: they excluded the entire project from the engine.
func (w *legacyIgnoreWarner) checkRoot(path string) {
	if w == nil {
		return
	}
	for i, needle := range w.needles {
		if strings.Contains(path, needle) {
			w.warnOnce(w.patterns[i], func() {
				warnLegacyIgnorePath(
					"ignore.paths pattern "+strconv.Quote(w.patterns[i])+" matched the project directory itself under the old substring rule, "+
						"so the built-in engine scanned nothing. Patterns now use .gitignore syntax relative to the project root, "+
						"and the project is scanned.",
					"pattern", w.patterns[i], "project", path)
			})
		}
	}
}

// checkDir warns about patterns the old rule matched for a directory that is
// now in scope. path is the walked path, which the old rule used; rel is the
// same directory relative to the root.
func (w *legacyIgnoreWarner) checkDir(path, rel string) {
	if w == nil {
		return
	}
	for i, needle := range w.needles {
		if !strings.Contains(path, needle) {
			continue
		}
		suggestion := filepath.ToSlash(rel) + "/"
		w.warnOnce(w.patterns[i], func() {
			warnLegacyIgnorePath(
				"ignore.paths pattern "+strconv.Quote(w.patterns[i])+" no longer excludes "+strconv.Quote(filepath.ToSlash(rel))+
					": patterns now use .gitignore syntax instead of substring matching. "+
					"Add "+strconv.Quote(suggestion)+" to ignore.paths if it should stay out of scope.",
				"pattern", w.patterns[i], "path", filepath.ToSlash(rel), "suggest", suggestion)
		})
	}
}

func (w *legacyIgnoreWarner) warnOnce(pattern string, warn func()) {
	if _, seen := warnedLegacyPatterns.LoadOrStore(w.root+"\x00"+pattern, true); !seen {
		warn()
	}
}
