package external

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner/pathpolicy"
)

// Reasons a scanner analysed a file only partly.
const (
	// PartialTimeout: a rule reached its time limit on the file. Semgrep stops
	// analysing a file after repeated rule timeouts, so the findings that go
	// missing depend on machine load and can differ between runs.
	PartialTimeout = "timeout"
	// PartialParseError: the file, or part of it, could not be parsed.
	PartialParseError = "parse_error"
	// PartialError: the scanner failed on the file for another reason, such as
	// an internal matching error or a memory limit.
	PartialError = "error"
)

// PartialFile is a project file a scanner analysed only partly, so findings in
// it may be missing. A scanner that completed still records these files: a
// completed run is not the same as a complete one.
type PartialFile struct {
	// File is relative to the project root, with forward slashes.
	File string `json:"file"`
	// Reason is PartialTimeout, PartialParseError or PartialError.
	Reason string `json:"reason"`
	// Count is how many errors of this kind the scanner reported for the file;
	// for timeouts, one per rule that timed out.
	Count int `json:"count"`
}

// partialReasonOrder lists timeouts first: they are the gaps that change
// between runs.
var partialReasonOrder = map[string]int{PartialTimeout: 0, PartialParseError: 1, PartialError: 2}

// ScopePartialFiles prepares the partial files a scanner reported for output.
// Paths become relative to the project root. Files outside the project are
// dropped, and so are files outside the audited application (generated
// reports, test code, vendored or ignored paths), as their findings are.
// Reports of the same file and reason are combined. Timeouts come first, then
// files in path order.
func ScopePartialFiles(root string, files []PartialFile) []PartialFile {
	if len(files) == 0 {
		return nil
	}
	filter := NewScopeFilter(root)
	type key struct{ file, reason string }
	counts := make(map[key]int, len(files))
	for _, pf := range files {
		clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(pf.File)))
		if clean == "" || clean == "." || isGeneratedArtifactPath(clean) || !filter.InScope(clean) {
			continue
		}
		// An error about a file outside the project, such as a rule in the
		// scanner's temporary configuration, says nothing about coverage.
		rel, inProject := filter.placeUnderRoot(clean)
		if !inProject || rel == "" || pathpolicy.IsTestLike(rel) {
			continue
		}
		counts[key{rel, pf.Reason}] += max(pf.Count, 1)
	}
	if len(counts) == 0 {
		return nil
	}
	out := make([]PartialFile, 0, len(counts))
	for k, n := range counts {
		out = append(out, PartialFile{File: k.file, Reason: k.reason, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if oi, oj := partialReasonOrder[out[i].Reason], partialReasonOrder[out[j].Reason]; oi != oj {
			return oi < oj
		}
		return out[i].File < out[j].File
	})
	return out
}

// PartialFilesSummary counts partial files per reason in a short phrase, such
// as "2 with rule timeouts, 6 with parse errors", or "" when there are none.
// A file listed under two reasons counts under each.
func PartialFilesSummary(files []PartialFile) string {
	per := map[string]int{}
	for _, pf := range files {
		per[pf.Reason]++
	}
	var parts []string
	for _, r := range []struct{ reason, label string }{
		{PartialTimeout, "rule timeouts"},
		{PartialParseError, "parse errors"},
		{PartialError, "other scanner errors"},
	} {
		if n := per[r.reason]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d with %s", n, r.label))
		}
	}
	return strings.Join(parts, ", ")
}

// PartialFileCount is the number of distinct files in files.
func PartialFileCount(files []PartialFile) int {
	seen := make(map[string]struct{}, len(files))
	for _, pf := range files {
		seen[pf.File] = struct{}{}
	}
	return len(seen)
}
