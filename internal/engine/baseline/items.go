package baseline

import (
	"crypto/sha256"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// A baseline originally accepted only the built-in engine's findings, because
// that was the only scanner when it was written. Most of the noise on a real
// project now comes from the bundled Semgrep, Trivy, Gitleaks and Bandit — a PHP
// project's wall of CVEs from composer.lock, for instance — so a baseline that
// cannot hold them does not solve the problem it exists for.
//
// Item is the source-agnostic shape every scanner is mapped into before being
// accepted or matched.

// Baseline formats, oldest first. Every older format stays readable: an upgrade
// must never silently resurface findings a team already accepted.
//
//	"1" — core findings only, absolute paths
//	"2" — every scanner, absolute paths
//	"3" — every scanner, paths relative to the project root
//
// Absolute paths were a leak and a portability bug (issue #30): the file is
// meant to be committed, and it carried the author's home directory into the
// repository, where it also matched nothing on another machine or in CI.
const (
	SchemaVersion1 = "1"
	SchemaVersion2 = "2"
	SchemaVersion3 = "3"
)

// CurrentSchema is what new baselines are written as.
const CurrentSchema = SchemaVersion3

// Item is one finding, from any scanner, in the form a baseline stores.
type Item struct {
	// Source names the scanner: "core", "semgrep", "trivy", "gitleaks",
	// "bandit", "nfr", "deploy". Two scanners reporting the same line are
	// different findings, and accepting one must not hide the other.
	Source   string
	RuleID   string
	File     string
	Line     int
	Name     string
	Severity string
	// Evidence is the matched text. It is part of the fingerprint so a finding
	// survives moving up or down a file but not a change to what it found.
	Evidence string
}

// FingerprintItem identifies a finding stably across scans. The line number is
// deliberately excluded: edits above a finding must not resurface it.
func FingerprintItem(item Item) string {
	data := fmt.Sprintf("%s|%s|%s|%s", normalizeSource(item.Source), item.RuleID, item.File, item.Evidence)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:12])
}

// RelativePath expresses a scanner-reported path relative to the project root.
//
// Scanners report absolute paths, and storing those made the baseline file
// unusable anywhere but the machine that wrote it. A path already relative, or
// one outside the root, is returned cleaned but otherwise untouched — a finding
// is never dropped just because its path is unusual.
func RelativePath(root, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if root == "" || !filepath.IsAbs(path) {
		return filepath.ToSlash(filepath.Clean(path))
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(path))
	}
	rel, err := filepath.Rel(absRoot, filepath.Clean(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(filepath.Clean(path))
	}
	return filepath.ToSlash(rel)
}

// Relativize rewrites every item's path against the project root.
func Relativize(root string, items []Item) []Item {
	for i := range items {
		items[i].File = RelativePath(root, items[i].File)
	}
	return items
}

func normalizeSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		return "core"
	}
	// The built-in engine reports itself under both names depending on the path.
	if source == "aitriage" {
		return "core"
	}
	return source
}

// ── Adapters ─────────────────────────────────────────────────────────────────

// FromCore maps built-in engine results. Only absent checks are findings; a
// present check is a passed control and has nothing to accept.
func FromCore(results []core.CheckResult) []Item {
	items := make([]Item, 0, len(results))
	for _, r := range results {
		items = append(items, Item{
			Source:   "core",
			RuleID:   r.ID,
			File:     r.File,
			Line:     r.Line,
			Name:     r.Name,
			Severity: r.Severity,
			Evidence: r.Evidence,
		})
	}
	return items
}

// FromExternal maps findings from the bundled scanners.
func FromExternal(findings []external.UnifiedFinding) []Item {
	items := make([]Item, 0, len(findings))
	for _, f := range findings {
		items = append(items, Item{
			Source:   f.Source,
			RuleID:   f.RuleID,
			File:     f.File,
			Line:     f.Line,
			Name:     f.RuleID,
			Severity: f.Severity,
			// The message carries the identifying detail — which CVE, which
			// secret pattern — so it acts as the evidence for these scanners.
			Evidence: f.Message,
		})
	}
	return items
}

// FromNFR maps non-functional requirement findings. They are project-level and
// carry no file, which is itself stable: the rule either holds or it does not.
func FromNFR(findings []nfr.NFRFinding) []Item {
	items := make([]Item, 0, len(findings))
	for _, f := range findings {
		items = append(items, Item{
			Source:   "nfr",
			RuleID:   f.RuleID,
			Name:     f.Name,
			Severity: f.Severity,
			Evidence: f.Message,
		})
	}
	return items
}

// FromDeploy maps infrastructure-as-code findings.
func FromDeploy(findings []deployaudit.DeployFinding) []Item {
	items := make([]Item, 0, len(findings))
	for _, f := range findings {
		items = append(items, Item{
			Source:   "deploy",
			RuleID:   f.Issue,
			File:     f.File,
			Line:     f.Line,
			Name:     f.Issue,
			Severity: f.Severity,
			Evidence: f.Evidence,
		})
	}
	return items
}

// ── Accepting and matching ───────────────────────────────────────────────────

// NewFromItems builds a source-aware baseline from findings of any scanner.
func NewFromItems(items []Item) *Baseline {
	b := newEmpty()
	b.Version = CurrentSchema
	for _, item := range items {
		fp := FingerprintItem(item)
		b.Findings[fp] = Finding{
			Source:   normalizeSource(item.Source),
			RuleID:   item.RuleID,
			File:     item.File,
			Line:     item.Line,
			Name:     item.Name,
			Severity: item.Severity,
			Hash:     fp,
		}
	}
	return b
}

// Accepts reports whether a finding is already in the baseline.
//
// Older formats are matched as well as the current one. This is what keeps an
// upgrade from resurfacing everything a team had already accepted:
//
//   - "1" predates the source field, so its keys use the original core-only
//     fingerprint, and only core findings can match them.
//   - "1" and "2" stored absolute paths, so a finding whose path is now relative
//     is also tried against the absolute form the file would have recorded.
//     That needs the project root: Accepts does not know it and matches an
//     absolute entry only exactly; AcceptsInProject does.
func (b *Baseline) Accepts(item Item) bool {
	return b.accepts("", item)
}

// AcceptsInProject is Accepts for a known project root, so baselines written
// before paths were made relative still match.
func (b *Baseline) AcceptsInProject(root string, item Item) bool {
	return b.accepts(root, item)
}

func (b *Baseline) accepts(root string, item Item) bool {
	if b == nil || len(b.Findings) == 0 {
		return false
	}
	if _, ok := b.Findings[FingerprintItem(item)]; ok {
		return true
	}

	legacyPaths := []string{}
	if root != "" && item.File != "" && !filepath.IsAbs(item.File) && b.Version != CurrentSchema {
		legacyPaths = append(legacyPaths, filepath.Join(root, item.File))
	}

	for _, path := range legacyPaths {
		aged := item
		aged.File = path
		if _, ok := b.Findings[FingerprintItem(aged)]; ok {
			return true
		}
		if b.Version == SchemaVersion1 && normalizeSource(item.Source) == "core" {
			legacy := Fingerprint(core.CheckResult{ID: item.RuleID, File: path, Evidence: item.Evidence})
			if _, ok := b.Findings[legacy]; ok {
				return true
			}
		}
	}
	// An old file can also travel to a checkout with a different root. Its
	// stored file path is enough to reconstruct the old fingerprint, including
	// the evidence from the current finding, without accepting a different rule
	// or a different file (see LegacyPathMatches).
	if b.Version == SchemaVersion1 || b.Version == SchemaVersion2 {
		for key, finding := range b.Findings {
			if finding.RuleID != item.RuleID || !LegacyPathMatches(root, finding.File, item.File) {
				continue
			}
			if b.Version == SchemaVersion2 && normalizeSource(finding.Source) != normalizeSource(item.Source) {
				continue
			}
			aged := item
			aged.File = finding.File
			if b.Version == SchemaVersion2 && FingerprintItem(aged) == key {
				return true
			}
			if b.Version == SchemaVersion1 && normalizeSource(item.Source) == "core" &&
				Fingerprint(core.CheckResult{ID: item.RuleID, File: finding.File, Evidence: item.Evidence}) == key {
				return true
			}
		}
	}

	if b.Version == SchemaVersion1 && normalizeSource(item.Source) == "core" {
		legacy := Fingerprint(core.CheckResult{ID: item.RuleID, File: item.File, Evidence: item.Evidence})
		if _, ok := b.Findings[legacy]; ok {
			return true
		}
	}
	return false
}

// LegacyPathMatches reports whether oldAbsolute, a path an older project file
// recorded before paths were made project-relative, names currentRelative, a
// path relative to the project at root.
//
// A path recorded under root names exactly its path relative to root. One
// recorded elsewhere comes from a checkout that has since moved, and the root
// it was recorded under is unknown: currentRelative must end it, and must be
// the longest tail of it that names a path in the project, because a longer
// tail that exists there is the file it was recorded for. A record for
// app/config.php therefore never matches config.php at the root, or another
// file that merely shares its name or a shorter tail of its path, while
// app/config.php exists. Without a root the relative path cannot be told and
// nothing matches.
//
// Matching by tail alone let an entry recorded without evidence, which stands
// for every finding of its rule in its file, cover every file of that name.
func LegacyPathMatches(root, oldAbsolute, currentRelative string) bool {
	old := pathpkg.Clean(strings.ReplaceAll(oldAbsolute, `\`, "/"))
	rel := pathpkg.Clean(strings.ReplaceAll(currentRelative, `\`, "/"))
	if root == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") ||
		strings.HasPrefix(rel, "/") || strings.Contains(rel, ":") {
		return false
	}
	windowsAbsolute := len(old) >= 3 && old[1] == ':' && old[2] == '/'
	if !strings.HasPrefix(old, "/") && !windowsAbsolute {
		return false
	}
	if !strings.HasSuffix(old, "/"+rel) {
		return false
	}
	if recorded, ok := underRoot(root, old); ok {
		return recorded == rel
	}
	oldRoot := strings.Split(strings.TrimSuffix(old, "/"+rel), "/")
	if windowsAbsolute {
		oldRoot = oldRoot[1:] // the drive is no directory of the project
	}
	tail := rel
	for i := len(oldRoot) - 1; i >= 0; i-- {
		if oldRoot[i] == "" {
			continue
		}
		tail = oldRoot[i] + "/" + tail
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(tail))); err == nil {
			return false
		}
	}
	return true
}

// underRoot returns path, slash-separated and absolute, relative to root when
// it lies under root as given, as an absolute path or with symbolic links
// resolved.
func underRoot(root, path string) (string, bool) {
	roots := []string{root}
	if abs, err := filepath.Abs(root); err == nil {
		roots = append(roots, abs)
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			roots = append(roots, resolved)
		}
	}
	for _, r := range roots {
		prefix := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(r)), "/") + "/"
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix), true
		}
	}
	return "", false
}

// ItemFilterResult separates a scan into what is new and what was accepted.
type ItemFilterResult struct {
	New      []Item
	Accepted []Item
}

// FilterItems splits findings from any scanner against the baseline.
func FilterItems(items []Item, b *Baseline) ItemFilterResult {
	if b == nil || len(b.Findings) == 0 {
		return ItemFilterResult{New: items}
	}
	var out ItemFilterResult
	for _, item := range items {
		if b.Accepts(item) {
			out.Accepted = append(out.Accepted, item)
		} else {
			out.New = append(out.New, item)
		}
	}
	return out
}
