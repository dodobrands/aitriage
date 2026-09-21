package baseline

import (
	"crypto/sha256"
	"fmt"
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

// SchemaVersion2 is the source-aware baseline format. Version "1" files remain
// readable: their entries are matched with the original core-only fingerprint,
// so upgrading AITriage never silently resurfaces an accepted finding.
const SchemaVersion2 = "2"

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
	b.Version = SchemaVersion2
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
// A version "1" baseline was written before findings carried a source, so its
// keys use the original core-only fingerprint. Those keys are still honoured for
// core findings, which is what keeps an upgrade from resurfacing everything a
// team had already accepted.
func (b *Baseline) Accepts(item Item) bool {
	if b == nil || len(b.Findings) == 0 {
		return false
	}
	if _, ok := b.Findings[FingerprintItem(item)]; ok {
		return true
	}
	if b.Version == Version && normalizeSource(item.Source) == "core" {
		legacy := Fingerprint(core.CheckResult{ID: item.RuleID, File: item.File, Evidence: item.Evidence})
		if _, ok := b.Findings[legacy]; ok {
			return true
		}
	}
	return false
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

// AcceptedExternal returns the bundled-scanner findings that are not in the
// baseline, preserving the caller's own type so nothing downstream changes.
func FilterExternal(findings []external.UnifiedFinding, b *Baseline) (kept []external.UnifiedFinding, accepted int) {
	if b == nil || len(b.Findings) == 0 {
		return findings, 0
	}
	kept = make([]external.UnifiedFinding, 0, len(findings))
	for _, f := range findings {
		item := FromExternal([]external.UnifiedFinding{f})[0]
		if b.Accepts(item) {
			accepted++
			continue
		}
		kept = append(kept, f)
	}
	return kept, accepted
}

// FilterNFR returns the NFR findings that are not in the baseline.
func FilterNFR(findings []nfr.NFRFinding, b *Baseline) (kept []nfr.NFRFinding, accepted int) {
	if b == nil || len(b.Findings) == 0 {
		return findings, 0
	}
	kept = make([]nfr.NFRFinding, 0, len(findings))
	for _, f := range findings {
		if b.Accepts(FromNFR([]nfr.NFRFinding{f})[0]) {
			accepted++
			continue
		}
		kept = append(kept, f)
	}
	return kept, accepted
}

// FilterDeploy returns the deploy findings that are not in the baseline.
func FilterDeploy(findings []deployaudit.DeployFinding, b *Baseline) (kept []deployaudit.DeployFinding, accepted int) {
	if b == nil || len(b.Findings) == 0 {
		return findings, 0
	}
	kept = make([]deployaudit.DeployFinding, 0, len(findings))
	for _, f := range findings {
		if b.Accepts(FromDeploy([]deployaudit.DeployFinding{f})[0]) {
			accepted++
			continue
		}
		kept = append(kept, f)
	}
	return kept, accepted
}
