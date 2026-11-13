package main

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// auditedArtifact adds the classification audit: one entry per model reply,
// with the verdicts validation rejected (the finding was asked again, and
// ended Needs Manual Review if no verdict passed) and those it downgraded
// (accepted in a weaker form, such as a False Positive kept for review).
type auditedArtifact struct {
	artifact
	ClassificationAudit []auditEntry `json:"classification_audit"`
}

type auditEntry struct {
	// UniqueFindingIndices count the findings of one classification run
	// after deduplication, not positions in findings; FindingIDs and
	// Fingerprints, parallel to them, link each one to its findings.
	UniqueFindingIndices []int       `json:"unique_finding_indices"`
	FindingIDs           []string    `json:"finding_ids"`
	Fingerprints         []string    `json:"fingerprints"`
	ParseError           string      `json:"parse_error"`
	Rejected             []auditItem `json:"rejected"`
	Downgraded           []auditItem `json:"downgraded"`
}

type auditItem struct {
	FindingIndex int    `json:"finding_index"`
	Reason       string `json:"reason"`
}

const (
	allRules     = "(all)"
	unattributed = "(unattributed)"
	outOfRange   = "out-of-range finding_index"
)

// reasonKey is one bar of a histogram: a decision ("rejected" or
// "downgraded"), a rule (allRules for the overall histogram) and a category.
type reasonKey struct{ decision, rule, reason string }

type reasonReport struct {
	runs, requests, unparsed int
	counts                   map[reasonKey]int
}

// countReasons builds the histograms of every artifact's validator decisions.
func countReasons(files []string) (reasonReport, error) {
	rep := reasonReport{runs: len(files), counts: map[reasonKey]int{}}
	for _, path := range files {
		var a auditedArtifact
		if err := readJSON(path, &a); err != nil {
			return rep, err
		}
		if err := checkSchema(path, a.SchemaVersion); err != nil {
			return rep, err
		}
		rules := indexRules(a.Findings)
		for _, e := range a.ClassificationAudit {
			rep.requests++
			if e.ParseError != "" {
				rep.unparsed++
			}
			for _, d := range []struct {
				name  string
				items []auditItem
			}{{"rejected", e.Rejected}, {"downgraded", e.Downgraded}} {
				for _, item := range d.items {
					reason := normaliseReason(item.Reason)
					rep.counts[reasonKey{d.name, allRules, reason}]++
					for _, rule := range rules.of(e, item, reason) {
						rep.counts[reasonKey{d.name, rule, reason}]++
					}
				}
			}
		}
	}
	return rep, nil
}

// ruleIndex finds the rules behind the finding an audit decision names.
type ruleIndex struct{ byFingerprint, byID map[string][]string }

func indexRules(findings []triagedFinding) ruleIndex {
	x := ruleIndex{byFingerprint: map[string][]string{}, byID: map[string][]string{}}
	add := func(m map[string][]string, key string, rules []string) {
		if key == "" || len(rules) == 0 {
			return
		}
		merged := append(slices.Clone(m[key]), rules...)
		sort.Strings(merged)
		m[key] = slices.Compact(merged)
	}
	for _, f := range findings {
		rules := ruleIDs(f)
		add(x.byFingerprint, f.Disposition.Fingerprint, rules)
		// finding_ids hold the vuln_id, or the rule id when there is none.
		id := f.Finding.VulnID
		if id == "" {
			id = f.Finding.ID
		}
		add(x.byID, id, rules)
	}
	return x
}

// of returns the rules a decision is attributed to: those of the findings
// with the fingerprint (or failing that the id) the audit entry records for
// the decision's finding.
func (x ruleIndex) of(e auditEntry, item auditItem, reason string) []string {
	// The index of an out-of-range verdict is the model's own: it names no
	// finding, and may coincide with another finding's index.
	if reason == outOfRange {
		return []string{unattributed}
	}
	pos := slices.Index(e.UniqueFindingIndices, item.FindingIndex)
	if pos >= 0 && pos < len(e.Fingerprints) {
		if rules := x.byFingerprint[e.Fingerprints[pos]]; len(rules) > 0 {
			return rules
		}
	}
	if pos >= 0 && pos < len(e.FindingIDs) {
		if rules := x.byID[e.FindingIDs[pos]]; len(rules) > 0 {
			return rules
		}
	}
	return []string{unattributed}
}

// reasonCategory maps the validator reasons that start with pattern to label.
// N stands for a number and {braces} for a value the label leaves out; ${n}
// repeats a group, which must list fixed words only.
type reasonCategory struct {
	pattern *regexp.Regexp
	label   string
}

const (
	// keptPrefix opens the note of a False Positive kept as Needs Manual
	// Review; the validator's own reason follows it.
	keptPrefix = "false positive kept as Needs Manual Review: "
	// rejectedPrefix opens most code_mitigation rejections.
	rejectedPrefix = "code_mitigation evidence rejected: "
)

// reasonCategories follow the reasons of internal/agent/graph (evidence.go,
// mitigation_shape.go, source_regions.go and classify.go), most specific
// first. A reason none of them matches still gets a category from
// sanitiseReason.
var reasonCategories = func() []reasonCategory {
	rejected := regexp.QuoteMeta(rejectedPrefix)
	list := []struct{ pattern, label string }{
		{`out-of-range finding_index`, outOfRange},
		{`unsupported disposition`, "unsupported disposition"},
		{`duplicate disposition`, "duplicate disposition"},
		{`finding_id does not match requested finding`, "finding_id does not match requested finding"},
		{`fingerprint does not match requested finding`, "fingerprint does not match requested finding"},
		{`false positive has no evidence`, "false positive has no evidence"},
		{`false positive evidence basis `, "false positive evidence basis {basis} is not deterministically verifiable"},
		{`false positive for a CRITICAL finding kept as Needs Manual Review: policy fp_critical_requires_high_confidence`,
			"false positive for a CRITICAL finding kept as Needs Manual Review: policy fp_critical_requires_high_confidence requires high confidence"},
		{`a hardcoded secret is never dismissed automatically`, "a hardcoded secret is never dismissed automatically, whatever the evidence"},
		{`test_only evidence does not reference a test finding`, "test_only evidence does not reference a test finding"},
		{`test_only evidence file is missing`, "test_only evidence file is missing"},
		{`(test_only|code_mitigation) evidence file is invalid: evidence file does not match finding file`, "${1} evidence file is invalid: evidence file does not match finding file"},
		{`(test_only|code_mitigation) evidence file is invalid: finding and evidence paths are required`, "${1} evidence file is invalid: finding and evidence paths are required"},
		{`(test_only|code_mitigation) evidence file is invalid: (finding|evidence) path: path escapes project root`, "${1} evidence file is invalid: ${2} path escapes project root"},
		{`(test_only|code_mitigation) evidence file is invalid: (finding|evidence) path: path is not a regular file`, "${1} evidence file is invalid: ${2} path is not a regular file"},
		{`(test_only|code_mitigation) evidence file is invalid: (finding|evidence) path: .*(?:no such file or directory|cannot find the (?:file|path) specified)`, "${1} evidence file is invalid: ${2} path does not exist"},
		{`(test_only|code_mitigation) evidence file is invalid: (finding|evidence) path`, "${1} evidence file is invalid: ${2} path cannot be resolved"},
		{`(test_only|code_mitigation) evidence file is invalid`, "${1} evidence file is invalid"},
		{`test_only evidence line does not match finding line`, "test_only evidence line does not match finding line"},
		{`code_mitigation evidence is incomplete`, "code_mitigation evidence is incomplete"},
		{`code_mitigation evidence is not accepted for a CRITICAL finding`, "code_mitigation evidence is not accepted for a CRITICAL finding"},
		{`code_mitigation evidence is not accepted for a hardcoded secret`, "code_mitigation evidence is not accepted for a hardcoded secret"},
		{`code_mitigation evidence for a (CRITICAL|HIGH|MEDIUM|LOW|INFO|UNRATED) finding must be tied to the flagged statement's function`,
			"code_mitigation evidence for a ${1} finding must be tied to the flagged statement's function, and AITriage has no parser for {file}"},
		{`code_mitigation evidence for an? .* finding must be tied to the flagged statement's function`,
			"code_mitigation evidence for a {severity} finding must be tied to the flagged statement's function, and AITriage has no parser for {file}"},
		{`code_mitigation evidence is unreadable: flagged line \d+ is outside source file`, "code_mitigation evidence is unreadable: flagged line N is outside source file"},
		{`code_mitigation evidence is unreadable`, "code_mitigation evidence is unreadable"},
		{`code_mitigation observed text is absent from source`, "code_mitigation observed text is absent from source"},
		{rejected + `.* is a configuration or data file`, rejectedPrefix + "{file} is a configuration or data file, which contains no code that mitigates"},
		{rejected + `.* is not a recognised source language`, rejectedPrefix + "{file} is not a recognised source language"},
		{rejected + `the finding has no line`, rejectedPrefix + "the finding has no line, so no mitigation can be tied to it"},
		{rejected + `evidence\.line must cite code other than the flagged line itself`, rejectedPrefix + "evidence.line must cite code other than the flagged line itself"},
		{rejected + `line \d+ is after the flagged line`, rejectedPrefix + "line N is after the flagged line N"},
		{rejected + `line \d+ is more than \d+ lines above the flagged line`, rejectedPrefix + "line N is more than N lines above the flagged line N"},
		{rejected + `line \d+ is in a different function than the flagged line`, rejectedPrefix + "line N is in a different function than the flagged line N"},
		{rejected + `observed text could not be located in the source line`, rejectedPrefix + "observed text could not be located in the source line"},
		{rejected + `observed text is not code only: part of it lies inside a (comment or string literal|comment|string literal)`, rejectedPrefix + "observed text is not code only: part of it lies inside a ${1}"},
		{rejected + `observed text lies inside a (comment or string literal|comment|string literal), not in code`, rejectedPrefix + "observed text lies inside a ${1}, not in code"},
		{rejected + `observed text has no code tokens`, rejectedPrefix + "observed text has no code tokens (prose is not a mitigation)"},
		{rejected + `observed text shares no identifier with the flagged statement`, rejectedPrefix + "observed text shares no identifier with the flagged statement on line N"},
		{rejected + `line \d+ is neither a guard nor a re-assignment through a call`, rejectedPrefix + "line N is neither a guard nor a re-assignment through a call"},
		{rejected + `line \d+ is an assert that does not check `, rejectedPrefix + "line N is an assert that does not check {names}"},
		{rejected + `line \d+ is an assertion that does not check `, rejectedPrefix + "line N is an assertion that does not check {names}"},
		{rejected + `line \d+ is a condition that does not check `, rejectedPrefix + "line N is a condition that does not check {names}"},
		{rejected + `line \d+ is a check of `, rejectedPrefix + "line N is a check of {names} that neither exits early nor encloses the flagged line N"},
		{rejected + `line \d+ is an early exit under a condition that does not check `, rejectedPrefix + "line N is an early exit under a condition that does not check {names}"},
		{rejected + `line \d+ is an early exit that is not under a check of `, rejectedPrefix + "line N is an early exit that is not under a check of {names}"},
		{rejected + `line \d+ is an assignment to something other than `, rejectedPrefix + "line N is an assignment to something other than {names}"},
		{rejected + `line \d+ is an assignment of `, rejectedPrefix + "line N is an assignment of {name} that does not pass it through a call"},
	}
	out := make([]reasonCategory, len(list))
	for i, c := range list {
		out[i] = reasonCategory{regexp.MustCompile("^(?:" + c.pattern + ")"), c.label}
	}
	return out
}()

// normaliseReason reduces a validator reason to its category.
func normaliseReason(reason string) string {
	text := strings.Join(strings.Fields(reason), " ")
	if i := strings.IndexByte(text, ';'); i >= 0 {
		text = text[:i]
	}
	// Long reasons are cut at a fixed length and end in an ellipsis.
	text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "…"))
	if inner, ok := strings.CutPrefix(text, keptPrefix); ok {
		return keptPrefix + normaliseReason(inner)
	}
	if text == "" {
		return "(no reason)"
	}
	for _, c := range reasonCategories {
		if m := c.pattern.FindStringSubmatchIndex(text); m != nil {
			return string(c.pattern.ExpandString(nil, c.label, text, m))
		}
	}
	return sanitiseReason(text)
}

var (
	quotedText  = regexp.MustCompile("\"[^\"]*\"|`[^`]*`")
	reasonWord  = regexp.MustCompile(`[^\s,:()]+`)
	numberWord  = regexp.MustCompile(`^\d+$`)
	valueRun    = regexp.MustCompile(`\{value\}(?:[\s,]+\{value\})+`)
	commonWords = strings.Fields("a an the and or not no is are be been has have does do did must may can cannot " +
		"of to in on at by for from with as than that this it its which only any every each other another " +
		"line lines file files path paths code text evidence finding findings verdict model reply")
)

// reasonVocabulary holds the words of the category labels and a few common
// words. A reason no category matches keeps only these words, so neither an
// identifier nor a path nor a code fragment in it is printed.
var reasonVocabulary = func() map[string]bool {
	words := map[string]bool{}
	for _, w := range commonWords {
		words[w] = true
	}
	for _, c := range reasonCategories {
		for _, w := range reasonWord.FindAllString(c.label, -1) {
			words[strings.ToLower(w)] = true
		}
	}
	for _, w := range reasonWord.FindAllString(keptPrefix, -1) {
		words[strings.ToLower(w)] = true
	}
	return words
}()

// sanitiseReason turns a reason this tool does not know yet into a category:
// numbers become N, and quoted text and every word outside reasonVocabulary
// become {value}.
func sanitiseReason(text string) string {
	text = quotedText.ReplaceAllString(text, "{value}")
	text = reasonWord.ReplaceAllStringFunc(text, func(word string) string {
		switch {
		case word == "{value}" || reasonVocabulary[strings.ToLower(strings.TrimRight(word, "."))]:
			return word
		case numberWord.MatchString(word):
			return "N"
		default:
			return "{value}"
		}
	})
	return valueRun.ReplaceAllString(text, "{value}")
}

type reasonRow struct {
	reasonKey
	count int
}

// reasonRows lists the overall histogram, rejected before downgraded and the
// most frequent reason first, then the per-rule bars, the largest first.
func reasonRows(counts map[reasonKey]int) (overall, perRule []reasonRow) {
	for k, n := range counts {
		if k.rule == allRules {
			overall = append(overall, reasonRow{k, n})
		} else {
			perRule = append(perRule, reasonRow{k, n})
		}
	}
	order := func(a, b reasonRow) int {
		switch {
		case a.decision != b.decision:
			return strings.Compare(b.decision, a.decision) // rejected, then downgraded
		case a.count != b.count:
			return b.count - a.count
		default:
			return strings.Compare(a.reason, b.reason)
		}
	}
	slices.SortFunc(overall, order)
	slices.SortFunc(perRule, func(a, b reasonRow) int {
		switch {
		case a.count != b.count:
			return b.count - a.count
		case a.rule != b.rule:
			return strings.Compare(a.rule, b.rule)
		default:
			return order(a, b)
		}
	})
	return overall, perRule
}

func writeReasons(w io.Writer, rep reasonReport, format string) error {
	overall, perRule := reasonRows(rep.counts)
	var b strings.Builder
	switch format {
	case "tsv":
		var rows [][]string
		for _, r := range append(overall, perRule...) {
			rows = append(rows, []string{r.decision, r.rule, r.reason, itoa(r.count)})
		}
		tsvTable(&b, []string{"decision", "rule", "reason", "count"}, rows)
	case "md":
		totals := map[string]int{}
		for _, r := range overall {
			totals[r.decision] += r.count
		}
		fmt.Fprintf(&b, "Runs: %d\nClassification requests: %d (%d without a parsed reply)\nValidator decisions: %d rejected, %d downgraded\n",
			rep.runs, rep.requests, rep.unparsed, totals["rejected"], totals["downgraded"])
		for _, d := range []struct{ decision, title string }{{"rejected", "Rejected verdicts"}, {"downgraded", "Downgraded verdicts"}} {
			var rows [][]string
			for _, r := range overall {
				if r.decision == d.decision {
					rows = append(rows, []string{r.reason, itoa(r.count)})
				}
			}
			fmt.Fprintf(&b, "\n## %s\n\n", d.title)
			if len(rows) == 0 {
				b.WriteString("None.\n")
				continue
			}
			mdTable(&b, []string{"reason", "count"}, rows)
		}
		b.WriteString("\n## Per rule\n\n")
		var rows [][]string
		for _, r := range perRule {
			rows = append(rows, []string{r.rule, r.decision, r.reason, itoa(r.count)})
		}
		if len(rows) == 0 {
			b.WriteString("None.\n")
		} else {
			mdTable(&b, []string{"rule", "decision", "reason", "count"}, rows)
		}
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
