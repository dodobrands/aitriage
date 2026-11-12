package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strconv"
	"strings"
)

// ── Layer 1: Canonicalize + Fingerprint + Dedup ──────────────────────────────
//
// Fingerprinting follows the SARIF partialFingerprints idea (GitHub Code
// Scanning): a stable content hash that identifies "the same problem" across
// runs and branches so it is not counted or re-triaged twice.
//
// Crucially, the fingerprint includes the normalized LOCATION. Two instances of
// the same rule at DIFFERENT locations get DIFFERENT fingerprints and are NOT
// merged — exploitability is location-sensitive (per ZeroFalse, findings are
// adjudicated 1:1). Only byte-for-byte identical findings collapse.
//
// Because it includes the line number, the fingerprint identifies a finding
// within one run (deduplication, the identity the model echoes, the artifact
// cache). Across runs a finding is identified by its StableID (stableid.go),
// and the verdict cache is keyed by verdictCacheKey, neither of which moves
// when lines are inserted above the finding.

// Fingerprint returns a stable 32-hex-char content hash for a finding.
func Fingerprint(f EnrichedFinding) string {
	h := sha256.New()
	payload := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(f.ID)),
		strings.ToLower(strings.TrimSpace(f.Type)),
		normalizePath(f.File),
		strconv.Itoa(f.Line),
		strings.TrimSpace(f.Message),
	}, "\x00")
	_, _ = h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// normalizePath makes a finding path comparable across environments by removing
// container/scan prefixes and normalising separators. SARIF guidance warns that
// absolute or environment-specific paths break cross-run fingerprint matching.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/src/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return strings.ToLower(path.Clean(p))
}

// dedupFindings groups identical findings by fingerprint. It returns the unique
// representatives (first-occurrence order preserved) and, for each unique
// finding, the list of ORIGINAL indices that map to it. No finding is dropped:
// every original index appears in exactly one group.
func dedupFindings(findings []EnrichedFinding) (unique []EnrichedFinding, groups [][]int) {
	pos := make(map[string]int, len(findings)) // fingerprint -> index in unique
	for i, f := range findings {
		fp := Fingerprint(f)
		if p, ok := pos[fp]; ok {
			groups[p] = append(groups[p], i)
			continue
		}
		pos[fp] = len(unique)
		unique = append(unique, f)
		groups = append(groups, []int{i})
	}
	return unique, groups
}

// projectDispositions expands per-unique dispositions back onto EVERY original
// finding. Each original keeps its own finding index, VulnID and fingerprint,
// inheriting the disposition/rationale/confidence/source of its representative.
// uniqueDisps must be indexed by unique position (0..len(groups)-1).
func projectDispositions(uniqueDisps []FindingDisposition, groups [][]int, findings []EnrichedFinding) []FindingDisposition {
	out := make([]FindingDisposition, len(findings))
	for u, d := range uniqueDisps {
		for _, gi := range groups[u] {
			out[gi] = FindingDisposition{
				FindingIndex:      gi,
				FindingID:         findings[gi].VulnID,
				Disposition:       d.Disposition,
				Rationale:         d.Rationale,
				Confidence:        d.Confidence,
				DispositionSource: d.DispositionSource,
				Fingerprint:       Fingerprint(findings[gi]),
				Evidence:          d.Evidence,
			}
		}
	}
	return out
}
