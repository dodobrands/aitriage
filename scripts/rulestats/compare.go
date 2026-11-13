package main

import (
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// verdict abbreviates a disposition the way the reports count it: anything
// that is neither a True nor a False Positive is Needs Manual Review.
func verdict(disposition string) string {
	switch disposition {
	case "True Positive":
		return "TP"
	case "False Positive":
		return "FP"
	default:
		return "NR"
	}
}

type transition struct{ from, to string }

func (t transition) String() string { return t.from + "→" + t.to }

var (
	// flips are the verdict changes, in report order.
	flips = []transition{{"TP", "FP"}, {"TP", "NR"}, {"FP", "TP"}, {"FP", "NR"}, {"NR", "TP"}, {"NR", "FP"}}
	kept  = []transition{{"TP", "TP"}, {"FP", "FP"}, {"NR", "NR"}}
)

// change counts what happened to the findings of one rule, or of all rules.
type change struct {
	rule             string
	matched          int
	moves            map[transition]int
	onlyOld, onlyNew int
}

func (c *change) flipped() int {
	n := 0
	for _, t := range flips {
		n += c.moves[t]
	}
	return n
}

type comparison struct {
	artifacts, artifactsOnlyOld, artifactsOnlyNew int
	findingsOld, findingsNew, unidentified        int
	verdictsOld, verdictsNew                      map[string]int
	total                                         *change
	// sources counts, per transition, the disposition_source pairs behind it.
	sources map[transition]map[string]int
	rules   map[string]*change
}

func (c *comparison) rule(id string) *change {
	if c.rules[id] == nil {
		c.rules[id] = &change{rule: id, moves: map[transition]int{}}
	}
	return c.rules[id]
}

// compareSets compares every pair of artifacts the two sets share.
func compareSets(oldRoot, newRoot string) (*comparison, error) {
	oldSet, err := artifactSet(oldRoot, "old")
	if err != nil {
		return nil, err
	}
	newSet, err := artifactSet(newRoot, "new")
	if err != nil {
		return nil, err
	}
	c := &comparison{
		verdictsOld: map[string]int{},
		verdictsNew: map[string]int{},
		total:       &change{rule: allRules, moves: map[transition]int{}},
		sources:     map[transition]map[string]int{},
		rules:       map[string]*change{},
	}
	var pairs [][2]string
	pairs, c.artifactsOnlyOld, c.artifactsOnlyNew = pairArtifacts(oldSet, newSet)
	for _, p := range pairs {
		var before, after artifact
		for i, a := range []*artifact{&before, &after} {
			if err := readJSON(p[i], a); err != nil {
				return nil, err
			}
			if err := checkSchema(p[i], a.SchemaVersion); err != nil {
				return nil, err
			}
		}
		c.artifacts++
		c.add(before.Findings, after.Findings)
	}
	return c, nil
}

// pairArtifacts pairs the artifacts of the old and the new set (old path
// first) and counts those left without a partner. One artifact on each side
// is two runs of one project, wherever each lies.
func pairArtifacts(oldSet, newSet map[string]string) (pairs [][2]string, onlyOld, onlyNew int) {
	if len(oldSet) == 1 && len(newSet) == 1 {
		for _, before := range oldSet {
			for _, after := range newSet {
				return [][2]string{{before, after}}, 0, 0
			}
		}
	}
	for _, key := range slices.Sorted(maps.Keys(oldSet)) {
		if after, ok := newSet[key]; ok {
			pairs = append(pairs, [2]string{oldSet[key], after})
		} else {
			onlyOld++
		}
	}
	for key := range newSet {
		if _, ok := oldSet[key]; !ok {
			onlyNew++
		}
	}
	return pairs, onlyOld, onlyNew
}

// artifactSet maps every artifact under root to its directory relative to
// root, the key that pairs it with the same project's artifact in the other
// set.
func artifactSet(root, name string) (map[string]string, error) {
	files, err := collect([]string{root})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s set: no triage-findings.json found", name)
	}
	set := make(map[string]string, len(files))
	for _, path := range files {
		key, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		set[filepath.ToSlash(key)] = path
	}
	return set, nil
}

// add compares the findings of two runs of one project.
func (c *comparison) add(before, after []triagedFinding) {
	c.findingsOld += len(before)
	c.findingsNew += len(after)
	for _, f := range before {
		c.verdictsOld[verdict(f.Disposition.Disposition)]++
	}
	for _, f := range after {
		c.verdictsNew[verdict(f.Disposition.Disposition)]++
	}
	pairs, onlyOld, onlyNew, unidentified := matchFindings(before, after)
	c.unidentified += unidentified
	for _, p := range pairs {
		o, n := before[p[0]], after[p[1]]
		t := transition{verdict(o.Disposition.Disposition), verdict(n.Disposition.Disposition)}
		c.total.matched++
		c.total.moves[t]++
		if c.sources[t] == nil {
			c.sources[t] = map[string]int{}
		}
		c.sources[t][orDash(o.Disposition.Source)+" → "+orDash(n.Disposition.Source)]++
		// A merged finding may gain or lose a detector between runs; the
		// change counts for every rule that reported it in either run.
		for _, id := range ruleIDs(o, n) {
			r := c.rule(id)
			r.matched++
			r.moves[t]++
		}
	}
	for _, i := range onlyOld {
		c.total.onlyOld++
		for _, id := range ruleIDs(before[i]) {
			c.rule(id).onlyOld++
		}
	}
	for _, i := range onlyNew {
		c.total.onlyNew++
		for _, id := range ruleIDs(after[i]) {
			c.rule(id).onlyNew++
		}
	}
}

// matchFindings pairs the findings of two runs of one project by stable_id.
// vuln_id stands in when either finding has no stable_id, as in artifacts
// written before stable_id existed; two findings that both have one are
// never paired by vuln_id. A finding with neither id cannot be paired and is
// counted as unidentified.
func matchFindings(before, after []triagedFinding) (pairs [][2]int, onlyOld, onlyNew []int, unidentified int) {
	pairedOld := make([]bool, len(before))
	pairedNew := make([]bool, len(after))
	pair := func(i, j int) {
		pairs = append(pairs, [2]int{i, j})
		pairedOld[i], pairedNew[j] = true, true
	}
	byStableID := map[string][]int{}
	for j, f := range after {
		if id := f.Finding.StableID; id != "" {
			byStableID[id] = append(byStableID[id], j)
		}
	}
	for i, f := range before {
		if js := byStableID[f.Finding.StableID]; f.Finding.StableID != "" && len(js) > 0 {
			pair(i, js[0])
			byStableID[f.Finding.StableID] = js[1:]
		}
	}
	byVulnID := map[string][]int{}
	for j, f := range after {
		if id := f.Finding.VulnID; id != "" && !pairedNew[j] {
			byVulnID[id] = append(byVulnID[id], j)
		}
	}
	for i, f := range before {
		if pairedOld[i] || f.Finding.VulnID == "" {
			continue
		}
		for _, j := range byVulnID[f.Finding.VulnID] {
			if !pairedNew[j] && (f.Finding.StableID == "" || after[j].Finding.StableID == "") {
				pair(i, j)
				break
			}
		}
	}
	identified := func(f triagedFinding) bool { return f.Finding.StableID != "" || f.Finding.VulnID != "" }
	for i, f := range before {
		switch {
		case pairedOld[i]:
		case identified(f):
			onlyOld = append(onlyOld, i)
		default:
			unidentified++
		}
	}
	for j, f := range after {
		switch {
		case pairedNew[j]:
		case identified(f):
			onlyNew = append(onlyNew, j)
		default:
			unidentified++
		}
	}
	return pairs, onlyOld, onlyNew, unidentified
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// changedRules lists the rules with a flipped, removed or added finding:
// most flips first, then most removed and added findings.
func (c *comparison) changedRules() (changed []*change, unchanged int) {
	for _, r := range c.rules {
		if r.flipped() == 0 && r.onlyOld == 0 && r.onlyNew == 0 {
			unchanged++
			continue
		}
		changed = append(changed, r)
	}
	slices.SortFunc(changed, func(a, b *change) int {
		switch {
		case a.flipped() != b.flipped():
			return b.flipped() - a.flipped()
		case a.onlyOld+a.onlyNew != b.onlyOld+b.onlyNew:
			return (b.onlyOld + b.onlyNew) - (a.onlyOld + a.onlyNew)
		default:
			return strings.Compare(a.rule, b.rule)
		}
	})
	return changed, unchanged
}

func writeComparison(w io.Writer, c *comparison, format string) error {
	header := []string{"rule", "matched", "flipped"}
	for _, t := range flips {
		header = append(header, t.String())
	}
	header = append(header, "only-old", "only-new")
	changed, unchanged := c.changedRules()
	var rows [][]string
	for _, r := range append([]*change{c.total}, changed...) {
		row := []string{r.rule, itoa(r.matched), itoa(r.flipped())}
		for _, t := range flips {
			row = append(row, itoa(r.moves[t]))
		}
		rows = append(rows, append(row, itoa(r.onlyOld), itoa(r.onlyNew)))
	}
	var b strings.Builder
	switch format {
	case "tsv":
		tsvTable(&b, header, rows)
	case "md":
		fmt.Fprintf(&b, "Artifacts: %d compared, %d only in old, %d only in new (not compared)\n", c.artifacts, c.artifactsOnlyOld, c.artifactsOnlyNew)
		fmt.Fprintf(&b, "Findings in compared artifacts: %d old, %d new; %d matched, %d only in old, %d only in new\n",
			c.findingsOld, c.findingsNew, c.total.matched, c.total.onlyOld, c.total.onlyNew)
		if c.unidentified > 0 {
			fmt.Fprintf(&b, "Findings with neither stable_id nor vuln_id (not matched): %d\n", c.unidentified)
		}
		fmt.Fprintf(&b, "Verdicts: TP %d → %d, FP %d → %d, NR %d → %d\n",
			c.verdictsOld["TP"], c.verdictsNew["TP"], c.verdictsOld["FP"], c.verdictsNew["FP"], c.verdictsOld["NR"], c.verdictsNew["NR"])
		b.WriteString("\n## Verdicts of matched findings\n\n")
		var moves [][]string
		for _, t := range append(slices.Clone(flips), kept...) {
			if n := c.total.moves[t]; n > 0 {
				moves = append(moves, []string{t.from, t.to, itoa(n), sourcePairs(c.sources[t])})
			}
		}
		if len(moves) == 0 {
			b.WriteString("None.\n")
		} else {
			mdTable(&b, []string{"old", "new", "findings", "disposition_source old → new"}, moves)
		}
		b.WriteString("\n## Per rule\n\n")
		mdTable(&b, header, rows)
		if unchanged > 0 {
			fmt.Fprintf(&b, "\nRules without a flipped, removed or added finding (not listed): %d\n", unchanged)
		}
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// sourcePairs renders disposition_source pairs, the most frequent first.
func sourcePairs(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		if counts[a] != counts[b] {
			return counts[b] - counts[a]
		}
		return strings.Compare(a, b)
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, counts[k])
	}
	return strings.Join(parts, ", ")
}
