// Command rulestats summarises how AITriage rules fared in triaged runs.
//
// It reads triage-findings.json artifacts (from `aitriage agent` runs, for
// example downloaded CI artifacts) and prints, per rule id, how many findings
// the rule produced, in how many runs, and how triage classified them. Only
// rule ids and counts are printed: no paths, code or repository names.
//
// Two more reports read the same artifacts and print no more than that:
//
//   - -reasons counts why validation rejected a model verdict or accepted it
//     in a weaker form (classification_audit: rejected[] and downgraded[]),
//     overall and per rule. Each reason is reduced to a stable category: line
//     numbers become N, and identifiers, file names, quoted values and the
//     advice after ';' are dropped. A decision counts once per model reply,
//     so a finding whose verdict was rejected on three attempts counts three
//     times.
//   - -compare pairs two sets of artifacts, for example the same projects
//     triaged by two AITriage versions, and counts the findings whose verdict
//     changed (TP→NR, FP→TP, ...), overall and per rule, and the findings
//     present in one set only. Findings are matched by stable_id, or by
//     vuln_id when either side has no stable_id; a finding counts for every
//     rule that reported it in either set. Artifacts are paired by their
//     directory relative to each set's root; two sets of one artifact each
//     are paired whatever their directories.
//
// Usage:
//
//	go run ./scripts/rulestats [-format md|tsv] [-min N] <dir-or-file>...
//	go run ./scripts/rulestats -reasons [-format md|tsv] <dir-or-file>...
//	go run ./scripts/rulestats -compare [-format md|tsv] <old-dir-or-file> <new-dir-or-file>
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const usageText = `usage: rulestats [-format md|tsv] [-min N] <dir-or-file>...
       rulestats -reasons [-format md|tsv] <dir-or-file>...
       rulestats -compare [-format md|tsv] <old-dir-or-file> <new-dir-or-file>
`

// artifact is the subset of triage-findings.json this tool reads. It covers
// both the original format (one detector per finding) and the merged format,
// where origins lists every detector that reported the same defect.
type artifact struct {
	SchemaVersion int              `json:"schema_version"`
	Findings      []triagedFinding `json:"findings"`
}

type triagedFinding struct {
	Finding struct {
		ID       string   `json:"id"`
		Source   string   `json:"source"`
		Type     string   `json:"type"`
		VulnID   string   `json:"vuln_id"`
		StableID string   `json:"stable_id"`
		Origins  []origin `json:"origins"`
	} `json:"finding"`
	Disposition struct {
		Disposition string `json:"disposition"`
		Source      string `json:"disposition_source"`
		Fingerprint string `json:"fingerprint"`
	} `json:"disposition"`
}

type origin struct {
	RuleID string `json:"rule_id"`
	Source string `json:"source"`
	Type   string `json:"type"`
}

// ruleRef is one report of a finding: the rule and the scanner behind it.
type ruleRef struct{ rule, source string }

// reports lists the rules that reported a finding: every origin with a rule
// id, or the finding's own id when it has no origins (the original format).
func reports(f triagedFinding) []ruleRef {
	var refs []ruleRef
	for _, o := range f.Finding.Origins {
		if o.RuleID != "" {
			refs = append(refs, ruleRef{o.RuleID, o.Source})
		}
	}
	if len(refs) == 0 && f.Finding.ID != "" {
		refs = []ruleRef{{f.Finding.ID, f.Finding.Source}}
	}
	return refs
}

// ruleIDs returns the distinct rule ids behind the given findings, sorted.
func ruleIDs(findings ...triagedFinding) []string {
	var ids []string
	for _, f := range findings {
		for _, r := range reports(f) {
			ids = append(ids, r.rule)
		}
	}
	sort.Strings(ids)
	return slices.Compact(ids)
}

// stat accumulates the outcome of one rule.
type stat struct {
	Rule, Source                  string
	Findings, Runs                int
	TP, FP, NR                    int
	NRFallback, TriageFailed, Mrg int
	runs                          map[int]bool
}

func (s *stat) precision() float64 {
	if s.TP+s.FP == 0 {
		return -1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

type options struct {
	format           string
	min              int
	reasons, compare bool
}

// errUsage reports command-line arguments that fit no report.
var errUsage = errors.New("usage")

func main() {
	var o options
	flag.StringVar(&o.format, "format", "md", "output format: md or tsv")
	flag.IntVar(&o.min, "min", 5, "minimum findings for a rule to be ranked by false-positive rate")
	flag.BoolVar(&o.reasons, "reasons", false, "count why validation rejected or downgraded model verdicts, overall and per rule")
	flag.BoolVar(&o.compare, "compare", false, "compare the verdicts of two artifact sets, old first")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
		flag.PrintDefaults()
	}
	flag.Parse()
	err := run(os.Stdout, o, flag.Args())
	if errors.Is(err, errUsage) {
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run writes the report the options select.
func run(w io.Writer, o options, args []string) error {
	switch {
	case o.reasons && o.compare, o.compare && len(args) != 2, len(args) == 0:
		return errUsage
	case o.compare:
		c, err := compareSets(args[0], args[1])
		if err != nil {
			return err
		}
		return writeComparison(w, c, o.format)
	case o.reasons:
		files, err := collect(args)
		if err != nil {
			return err
		}
		rep, err := countReasons(files)
		if err != nil {
			return err
		}
		return writeReasons(w, rep, o.format)
	}
	files, err := collect(args)
	if err != nil {
		return err
	}
	stats, runs, err := summarise(files)
	if err != nil {
		return err
	}
	return write(w, rank(stats, o.min), runs, o.format)
}

// collect returns every triage-findings.json under the given paths.
func collect(paths []string) ([]string, error) {
	var files []string
	for _, root := range paths {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && d.Name() == "triage-findings.json" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// readJSON decodes one artifact. Errors name the file, never its path.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

// maxSchemaVersion is the newest triage-findings.json schema the -reasons and
// -compare reports understand. They refuse a newer artifact instead of
// misreading fields whose meaning may have changed.
const maxSchemaVersion = 1

func checkSchema(path string, version int) error {
	if version > maxSchemaVersion {
		return fmt.Errorf("%s: schema_version %d is newer than this tool reads (%d)", filepath.Base(path), version, maxSchemaVersion)
	}
	return nil
}

// summarise attributes every finding's verdict to each rule that reported it.
func summarise(files []string) (map[string]*stat, int, error) {
	stats := map[string]*stat{}
	for run, path := range files {
		var a artifact
		if err := readJSON(path, &a); err != nil {
			return nil, 0, err
		}
		for _, f := range a.Findings {
			refs := reports(f)
			for _, o := range refs {
				s := stats[o.rule]
				if s == nil {
					s = &stat{Rule: o.rule, Source: o.source, runs: map[int]bool{}}
					stats[o.rule] = s
				}
				s.Findings++
				s.runs[run] = true
				if len(refs) > 1 {
					s.Mrg++
				}
				switch f.Disposition.Disposition {
				case "True Positive":
					s.TP++
				case "False Positive":
					s.FP++
				default:
					s.NR++
					switch f.Disposition.Source {
					case "nr-fallback":
						s.NRFallback++
					case "triage-failed":
						s.TriageFailed++
					}
				}
			}
		}
	}
	for _, s := range stats {
		s.Runs = len(s.runs)
	}
	return stats, len(files), nil
}

// rank orders rules by false positives, then by false-positive share among
// rules with at least minFindings findings, then by id.
func rank(stats map[string]*stat, minFindings int) []*stat {
	out := make([]*stat, 0, len(stats))
	for _, s := range stats {
		out = append(out, s)
	}
	fpShare := func(s *stat) float64 {
		if s.Findings < minFindings || s.Findings == 0 {
			return 0
		}
		return float64(s.FP) / float64(s.Findings)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.FP != b.FP {
			return a.FP > b.FP
		}
		if fa, fb := fpShare(a), fpShare(b); fa != fb {
			return fa > fb
		}
		return a.Rule < b.Rule
	})
	return out
}

func write(w io.Writer, stats []*stat, runs int, format string) error {
	header := []string{"rule", "source", "findings", "runs", "TP", "FP", "NR", "nr-fallback", "triage-failed", "merged", "precision"}
	row := func(s *stat) []string {
		prec := "-"
		if p := s.precision(); p >= 0 {
			prec = fmt.Sprintf("%.0f%%", p*100)
		}
		return []string{s.Rule, s.Source, itoa(s.Findings), itoa(s.Runs), itoa(s.TP), itoa(s.FP), itoa(s.NR), itoa(s.NRFallback), itoa(s.TriageFailed), itoa(s.Mrg), prec}
	}
	switch format {
	case "tsv":
		if _, err := fmt.Fprintln(w, strings.Join(header, "\t")); err != nil {
			return err
		}
		for _, s := range stats {
			if _, err := fmt.Fprintln(w, strings.Join(row(s), "\t")); err != nil {
				return err
			}
		}
	case "md":
		if _, err := fmt.Fprintf(w, "Runs: %d\n\n| %s |\n|%s\n", runs, strings.Join(header, " | "), strings.Repeat("---|", len(header))); err != nil {
			return err
		}
		for _, s := range stats {
			if _, err := fmt.Fprintf(w, "| %s |\n", strings.Join(row(s), " | ")); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	return nil
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// mdTable renders a Markdown table.
func mdTable(b *strings.Builder, header []string, rows [][]string) {
	fmt.Fprintf(b, "| %s |\n|%s\n", strings.Join(header, " | "), strings.Repeat("---|", len(header)))
	for _, r := range rows {
		fmt.Fprintf(b, "| %s |\n", strings.Join(r, " | "))
	}
}

// tsvTable renders a table as tab-separated values.
func tsvTable(b *strings.Builder, header []string, rows [][]string) {
	for _, r := range append([][]string{header}, rows...) {
		b.WriteString(strings.Join(r, "\t") + "\n")
	}
}
