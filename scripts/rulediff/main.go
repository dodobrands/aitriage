// Command rulediff compares two sets of `aitriage scan --format json` reports,
// for example the same corpus scanned with the base branch and with a branch
// that changes rules. It prints, per rule id, the findings before and after,
// severity changes, and every finding that disappeared or appeared, so each
// lost finding can be checked for a false negative.
//
// Each directory holds one report per corpus, matched by file name.
//
// Usage:
//
//	go run ./scripts/rulediff <base-dir> <new-dir>
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type report struct {
	ProjectPath string `json:"project_path"`
	Results     []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		File     string `json:"file"`
		Line     int    `json:"line"`
	} `json:"results"`
}

// finding identifies one result independently of where the corpus lives.
type finding struct {
	Corpus, Rule, File string
	Line               int
}

type side struct {
	findings map[finding]string // → severity
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: rulediff <base-dir> <new-dir>")
		os.Exit(2)
	}
	base, err := load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	next, err := load(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := diff(os.Stdout, base, next); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func load(dir string) (side, error) {
	s := side{findings: map[finding]string{}}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return s, err
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return s, err
		}
		var r report
		if err := json.Unmarshal(data, &r); err != nil {
			return s, fmt.Errorf("%s: %w", p, err)
		}
		corpus := strings.TrimSuffix(filepath.Base(p), ".json")
		for _, res := range r.Results {
			file := res.File
			if rel, err := filepath.Rel(r.ProjectPath, file); err == nil && file != "" && !strings.HasPrefix(rel, "..") {
				file = filepath.ToSlash(rel)
			}
			s.findings[finding{corpus, res.ID, file, res.Line}] = res.Severity
		}
	}
	return s, nil
}

type ruleRow struct {
	rule                   string
	before, after          int
	lost, gained, resevere int
	sevBefore, sevAfter    map[string]bool
}

func diff(w io.Writer, base, next side) error {
	rows := map[string]*ruleRow{}
	row := func(id string) *ruleRow {
		if rows[id] == nil {
			rows[id] = &ruleRow{rule: id, sevBefore: map[string]bool{}, sevAfter: map[string]bool{}}
		}
		return rows[id]
	}
	var lost, gained []finding
	for f, sev := range base.findings {
		r := row(f.Rule)
		r.before++
		r.sevBefore[sev] = true
		if after, ok := next.findings[f]; !ok {
			r.lost++
			lost = append(lost, f)
		} else if after != sev {
			r.resevere++
		}
	}
	for f, sev := range next.findings {
		r := row(f.Rule)
		r.after++
		r.sevAfter[sev] = true
		if _, ok := base.findings[f]; !ok {
			r.gained++
			gained = append(gained, f)
		}
	}
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	if _, err := fmt.Fprintf(w, "Findings: %d → %d\n\n| rule | before | after | lost | new | severity |\n|---|---|---|---|---|---|\n", len(base.findings), len(next.findings)); err != nil {
		return err
	}
	for _, id := range ids {
		r := rows[id]
		if r.lost == 0 && r.gained == 0 && r.resevere == 0 && sameKeys(r.sevBefore, r.sevAfter) {
			continue
		}
		if _, err := fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %s → %s |\n", id, r.before, r.after, r.lost, r.gained, keys(r.sevBefore), keys(r.sevAfter)); err != nil {
			return err
		}
	}
	for _, list := range []struct {
		title string
		items []finding
	}{{"Lost findings (check each for a false negative)", lost}, {"New findings", gained}} {
		sortFindings(list.items)
		if _, err := fmt.Fprintf(w, "\n## %s: %d\n\n", list.title, len(list.items)); err != nil {
			return err
		}
		for _, f := range list.items {
			if _, err := fmt.Fprintf(w, "- %s %s %s:%d\n", f.Corpus, f.Rule, f.File, f.Line); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortFindings(fs []finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Corpus != b.Corpus {
			return a.Corpus < b.Corpus
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

func keys(m map[string]bool) string {
	if len(m) == 0 {
		return "-"
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
