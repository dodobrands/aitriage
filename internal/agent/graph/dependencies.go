package graph

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ── Dependency advisories per package ────────────────────────────────────────
//
// One outdated library is often dozens of advisories: fifty CVEs for one
// pillow release read as fifty unrelated problems, and the single upgrade that
// clears them is nowhere to be seen. The summary header and Top Critical
// Issues show one line per package instead. The score and the gate still
// count every advisory, which is the honest measure of risk.

// dependencyGroup collects the open advisories of one installed package.
type dependencyGroup struct {
	pkg       string
	installed string
	files     []string
	// bySeverity counts advisories per upper-case severity.
	bySeverity map[string]int
	total      int
	// noFix counts advisories without a fixed version.
	noFix int
	// target is the lowest version that clears every advisory with a fix.
	target string
	// severity is the highest severity among the advisories.
	severity string
	// first is the position of the group's first advisory in the actionable
	// order, so a group sorts where its findings used to.
	first int
}

// groupDependencyFindings groups the actionable advisories by package and
// installed version, in the order their first advisory appears.
func groupDependencyFindings(actionable []actionableFinding) []dependencyGroup {
	var groups []dependencyGroup
	index := map[string]int{}
	for i, f := range actionable {
		if strings.TrimSpace(f.pkg) == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(f.pkg)) + "\x00" + strings.TrimSpace(f.installedVersion)
		pos, ok := index[key]
		if !ok {
			pos = len(groups)
			index[key] = pos
			groups = append(groups, dependencyGroup{
				pkg:        strings.TrimSpace(f.pkg),
				installed:  strings.TrimSpace(f.installedVersion),
				bySeverity: map[string]int{},
				first:      i,
			})
		}
		g := &groups[pos]
		g.total++
		severity := strings.ToUpper(strings.TrimSpace(f.severity))
		if severity == "" {
			severity = "UNKNOWN"
		}
		g.bySeverity[severity]++
		if g.severity == "" || severitySortRank(severity) < severitySortRank(g.severity) {
			g.severity = severity
		}
		if f.file != "" && !slices.Contains(g.files, f.file) {
			g.files = append(g.files, f.file)
		}
		fix := minimalFix(f.fixedVersion, g.installed)
		if fix == "" {
			g.noFix++
			continue
		}
		if g.target == "" || compareVersions(fix, g.target) > 0 {
			g.target = fix
		}
	}
	for i := range groups {
		sort.Strings(groups[i].files)
	}
	return groups
}

// summaryLine renders "pillow 9.0.0 → 10.2.0: 2 CRITICAL, 1 HIGH", with
// "(no fix for N)" when some advisories have no fixed version.
func (g dependencyGroup) summaryLine() string {
	var b strings.Builder
	b.WriteString(g.pkg)
	if g.installed != "" {
		b.WriteString(" " + g.installed)
	}
	if g.target != "" {
		b.WriteString(" → " + g.target)
	}
	if g.noFix > 0 {
		_, _ = fmt.Fprintf(&b, " (no fix for %d)", g.noFix)
	}
	b.WriteString(": " + g.severityCounts())
	return b.String()
}

func (g dependencyGroup) severityCounts() string {
	severities := make([]string, 0, len(g.bySeverity))
	for severity := range g.bySeverity {
		severities = append(severities, severity)
	}
	sort.Slice(severities, func(i, j int) bool {
		if a, b := severitySortRank(severities[i]), severitySortRank(severities[j]); a != b {
			return a < b
		}
		return severities[i] < severities[j]
	})
	parts := make([]string, 0, len(severities))
	for _, severity := range severities {
		parts = append(parts, fmt.Sprintf("%d %s", g.bySeverity[severity], severity))
	}
	return strings.Join(parts, ", ")
}

// rankDependencyGroups orders groups for the header: highest severity first,
// then the most advisories, then by name.
func rankDependencyGroups(groups []dependencyGroup) []dependencyGroup {
	out := append([]dependencyGroup(nil), groups...)
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := severitySortRank(out[i].severity), severitySortRank(out[j].severity); a != b {
			return a < b
		}
		if out[i].total != out[j].total {
			return out[i].total > out[j].total
		}
		return strings.ToLower(out[i].pkg) < strings.ToLower(out[j].pkg)
	})
	return out
}

// minimalFix returns the lowest fixed version above the installed one. Trivy
// may list one fixed version per release line ("2.11.3, 3.0.0a1").
func minimalFix(fixed, installed string) string {
	var candidates []string
	for _, field := range strings.FieldsFunc(fixed, func(r rune) bool { return r == ',' || r == '|' || unicode.IsSpace(r) }) {
		version := strings.TrimLeft(field, "<>=~^!")
		if version != "" {
			candidates = append(candidates, version)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.SliceStable(candidates, func(i, j int) bool { return compareVersions(candidates[i], candidates[j]) < 0 })
	if installed != "" {
		for _, candidate := range candidates {
			if compareVersions(candidate, installed) > 0 {
				return candidate
			}
		}
	}
	if installed == "" {
		return candidates[0]
	}
	return candidates[len(candidates)-1]
}

// compareVersions orders version strings: numeric parts numerically, other
// parts lexically, and a pre-release ("1.0.0rc1", "1.0.0-beta.2") before its
// release. It is a best-effort order across ecosystems, used only to choose a
// version to show.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		switch {
		case i >= len(pa):
			// a ran out: a longer release (1.0.0.1) is newer, a pre-release
			// suffix (1.0.0rc1) is older.
			if isNumeric(pb[i]) {
				return -1
			}
			return 1
		case i >= len(pb):
			if isNumeric(pa[i]) {
				return 1
			}
			return -1
		}
		if c := compareVersionPart(pa[i], pb[i]); c != 0 {
			return c
		}
	}
	return 0
}

func compareVersionPart(a, b string) int {
	an, aNum := numericValue(a)
	bn, bNum := numericValue(b)
	switch {
	case aNum && bNum:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aNum:
		// A number outranks a pre-release label at the same position.
		return 1
	case bNum:
		return -1
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

// versionParts splits "v1.2.3rc1" into ["1", "2", "3", "rc", "1"].
func versionParts(version string) []string {
	version = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
	var parts []string
	var current strings.Builder
	digits := false
	flush := func() {
		if current.Len() > 0 {
			parts = append(parts, current.String())
			current.Reset()
		}
	}
	for _, r := range version {
		switch {
		case unicode.IsDigit(r):
			if !digits {
				flush()
			}
			digits = true
			current.WriteRune(r)
		case unicode.IsLetter(r):
			if digits {
				flush()
			}
			digits = false
			current.WriteRune(r)
		default:
			flush()
			digits = false
		}
	}
	flush()
	return parts
}

func isNumeric(part string) bool {
	_, ok := numericValue(part)
	return ok
}

func numericValue(part string) (int, bool) {
	if part == "" {
		return 0, false
	}
	for _, r := range part {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(part)
	return n, err == nil
}
