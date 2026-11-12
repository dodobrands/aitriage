package suppression

import (
	"bytes"
	"strings"

	"github.com/dodobrands/aitriage/internal/config"
)

// Inline suppression lets a developer silence one rule at one place, in the
// source, next to the code it is about. The directive grammar is:
//
//	aitriage-ignore: ID[, ID…] (reason)    its own line and the line below
//	aitriage:ignore ID                      same, colon form
//	aitriage-ignore-next-line: ID           the line below only
//	aitriage-ignore-file[: ID, …]           the whole file; in its first 10 lines
//
// IDs compare whole and case-insensitively, and may carry a source qualifier
// ("gitleaks:generic-api-key"). "all" silences every rule, but only as a token
// of its own. Text after the ID list, such as a reason in parentheses, is never
// read as an ID.
//
// The earlier implementation looked for the substrings "all" and the rule id
// anywhere on the line, so "# aitriage-ignore: B105 (allowed in tests)"
// silenced every rule on the line ("allowed" contains "all"), and an id
// silenced every rule whose id contained it.

// Scope says which lines a directive covers.
type Scope int

const (
	// ScopeLine covers the directive's own line and the line below it.
	ScopeLine Scope = iota
	// ScopeNextLine covers only the line below the directive.
	ScopeNextLine
	// ScopeFile covers the whole file.
	ScopeFile
)

// FileHeaderLines is how far into a file a file-level directive is honoured.
// A directive deep inside a file is far more likely to be an accident, such as
// a string literal, than a decision about the whole file.
const FileHeaderLines = 10

// allRules is the token that silences every rule.
const allRules = "all"

// Directive is one parsed inline suppression.
type Directive struct {
	Scope Scope
	// IDs are rule references as written. A file-level directive without IDs
	// covers every rule; a line-level one without IDs covers none, because a
	// bare marker does not say what was reviewed.
	IDs []string
}

// Covers reports whether the directive names the rule. sources are the names
// the finding answers to, for qualified references.
func (d Directive) Covers(ruleID string, sources ...string) bool {
	if d.Scope == ScopeFile && len(d.IDs) == 0 {
		return true
	}
	for _, id := range d.IDs {
		if strings.EqualFold(id, allRules) {
			return true
		}
		if config.ParseRuleRef(id).Matches(ruleID, sources...) {
			return true
		}
	}
	return false
}

// directiveKeywords are the two spellings of the directive prefix.
var directiveKeywords = []string{"aitriage-ignore", "aitriage:ignore"}

// keywordStem is what every directive contains; lines without it are skipped
// before any parsing.
var keywordStem = []byte("aitriage")

// ParseLine returns every directive written on one line of source.
func ParseLine(line string) []Directive {
	var directives []Directive
	rest := line
	for {
		at, keyword := nextKeyword(rest)
		if at < 0 {
			return directives
		}
		after := rest[at+len(keyword):]
		scope := ScopeLine
		switch {
		case strings.HasPrefix(after, "-next-line"):
			scope = ScopeNextLine
			after = after[len("-next-line"):]
		case strings.HasPrefix(after, "-file"):
			scope = ScopeFile
			after = after[len("-file"):]
		}
		// "aitriage-ignored" or "aitriage-ignore-files" is prose, not a directive.
		if after != "" && isWordByte(after[0]) {
			rest = after
			continue
		}
		ids, consumed := parseIDs(after)
		directives = append(directives, Directive{Scope: scope, IDs: ids})
		rest = after[consumed:]
	}
}

// nextKeyword finds the earliest directive keyword in s.
func nextKeyword(s string) (int, string) {
	best, keyword := -1, ""
	for _, candidate := range directiveKeywords {
		if i := strings.Index(s, candidate); i >= 0 && (best < 0 || i < best) {
			best, keyword = i, candidate
		}
	}
	return best, keyword
}

// parseIDs reads the comma-separated ID list that follows a keyword and
// reports how many bytes it consumed. The list ends at the first token not
// followed by a comma, so "B105 allowed in tests" yields only B105: free text
// must never widen a suppression.
func parseIDs(s string) ([]string, int) {
	i := skipSpace(s, 0)
	if i < len(s) && (s[i] == ':' || s[i] == '=') {
		i++
	}
	var ids []string
	for {
		i = skipSpace(s, i)
		if i >= len(s) || !isAlnum(s[i]) {
			return ids, i
		}
		start := i
		for i < len(s) && isIDByte(s[i]) {
			i++
		}
		// Trailing punctuation belongs to the sentence, not to the id:
		// "B105." or the "--" of a closing "-->".
		if id := strings.TrimRight(s[start:i], ".:/-"); id != "" {
			ids = append(ids, id)
		}
		i = skipSpace(s, i)
		if i < len(s) && s[i] == ',' {
			i++
			continue
		}
		return ids, i
	}
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isWordByte(b byte) bool {
	return isAlnum(b) || b == '_'
}

// isIDByte accepts the characters rule ids use across scanners: B105,
// ENTR-SLOP-01, nginx_missing_server_tokens_off, CVE-2024-1234, dotted Semgrep
// check ids, and an optional "source:" qualifier.
func isIDByte(b byte) bool {
	return isWordByte(b) || b == '-' || b == '.' || b == '/' || b == ':'
}

// Suppressed reports whether an inline directive in content silences ruleID at
// line (1-based). A finding without a line (line < 1) can only be silenced by a
// file-level directive.
func Suppressed(content []byte, line int, ruleID string, sources ...string) bool {
	last := FileHeaderLines
	if line > last {
		last = line
	}
	current := 0
	for len(content) > 0 && current < last {
		current++
		var text []byte
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			text, content = content[:i], content[i+1:]
		} else {
			text, content = content, nil
		}
		relevant := current <= FileHeaderLines || current == line || current == line-1
		if !relevant || !bytes.Contains(text, keywordStem) {
			continue
		}
		for _, d := range ParseLine(string(text)) {
			var applies bool
			switch d.Scope {
			case ScopeFile:
				applies = current <= FileHeaderLines
			case ScopeLine:
				applies = line >= 1 && (current == line || current == line-1)
			case ScopeNextLine:
				applies = line >= 1 && current == line-1
			}
			if applies && d.Covers(ruleID, sources...) {
				return true
			}
		}
	}
	return false
}
