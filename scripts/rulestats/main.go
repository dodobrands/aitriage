// Command rulestats summarises how AITriage rules fared in triaged runs.
//
// It reads triage-findings.json artifacts (from `aitriage agent` runs, for
// example downloaded CI artifacts) and prints, per rule id, how many findings
// the rule produced, in how many runs, and how triage classified them. Only
// rule ids and counts are printed: no paths, code or repository names.
//
// Usage:
//
//	go run ./scripts/rulestats [-format md|tsv] [-min N] <dir-or-file>...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// artifact is the subset of triage-findings.json this tool reads. It covers
// both the original format (one detector per finding) and the merged format,
// where origins lists every detector that reported the same defect.
type artifact struct {
	Findings []struct {
		Finding struct {
			ID      string `json:"id"`
			Source  string `json:"source"`
			Type    string `json:"type"`
			Origins []struct {
				RuleID string `json:"rule_id"`
				Source string `json:"source"`
				Type   string `json:"type"`
			} `json:"origins"`
		} `json:"finding"`
		Disposition struct {
			Disposition string `json:"disposition"`
			Source      string `json:"disposition_source"`
		} `json:"disposition"`
	} `json:"findings"`
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

func main() {
	format := flag.String("format", "md", "output format: md or tsv")
	minFindings := flag.Int("min", 5, "minimum findings for a rule to be ranked by false-positive rate")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: rulestats [-format md|tsv] [-min N] <dir-or-file>...")
		os.Exit(2)
	}
	files, err := collect(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	stats, runs, err := summarise(files)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := write(os.Stdout, rank(stats, *minFindings), runs, *format); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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

// summarise attributes every finding's verdict to each rule that reported it.
func summarise(files []string) (map[string]*stat, int, error) {
	stats := map[string]*stat{}
	for run, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, err
		}
		var a artifact
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		for _, f := range a.Findings {
			type origin struct{ rule, source string }
			var origins []origin
			for _, o := range f.Finding.Origins {
				if o.RuleID != "" {
					origins = append(origins, origin{o.RuleID, o.Source})
				}
			}
			if len(origins) == 0 && f.Finding.ID != "" {
				origins = []origin{{f.Finding.ID, f.Finding.Source}}
			}
			for _, o := range origins {
				s := stats[o.rule]
				if s == nil {
					s = &stat{Rule: o.rule, Source: o.source, runs: map[int]bool{}}
					stats[o.rule] = s
				}
				s.Findings++
				s.runs[run] = true
				if len(origins) > 1 {
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
