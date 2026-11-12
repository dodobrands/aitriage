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
//	aitriage-ignore: ID ID… reason          same, IDs separated by spaces
//	aitriage:ignore ID                      same, colon form
//	aitriage-ignore-next-line: ID           the line below only
//	aitriage-ignore-file[: ID, …]           the whole file; in its first 10 lines
//
// IDs compare whole and case-insensitively, and may carry a source qualifier
// ("gitleaks:generic-api-key"). They are separated by commas or spaces. The
// first ID and every ID after a comma are read as written; a word after a
// space is read as another ID only when it looks like one (see
// looksLikeRuleID), so the reason that follows the list is never taken for
// IDs: "B105 allowed in tests" names B105 only, "ENTR-18 PY-BINDING-ALL" both.
// The list also ends at "(". "all" silences every rule, but only as the first
// ID or after a comma, never as a word of a reason.
//
// A directive counts only when it opens a comment: it follows a comment marker
// ("#", "//", "/*", "<!--", "--" or ";", including forms such as "///", "{#"
// and "{{/*") that starts the line or follows a space, or it starts a line
// inside a block comment, optionally after the "*" of a "/** … */" block.
// Anything else is a mention of the directive, not a decision: a README
// sentence such as "add aitriage-ignore-file to skip a file", a string literal
// such as "put aitriage-ignore-file here", including one that spans lines (a
// Python docstring, a JS template literal, a Go raw string), a documentation
// link to "#aitriage-ignore-file", or a comment that merely refers to the
// directive. Any of them used to silence every finding in its file.
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

// ParseLine returns every directive written on one line of source that does
// not start inside a block comment or a string.
func ParseLine(line string) []Directive {
	return parseLine(line, inCode)
}

// parseLine returns the directives on one line. state is what the line starts
// in: code, a block comment or a string that spans lines.
func parseLine(line string, state lexState) []Directive {
	var directives []Directive
	var kinds []byte
	pos := 0
	for {
		at, keyword := nextKeyword(line[pos:])
		if at < 0 {
			return directives
		}
		start := pos + at
		next := start + len(keyword)
		scope := ScopeLine
		switch rest := line[next:]; {
		case strings.HasPrefix(rest, "-next-line"):
			scope = ScopeNextLine
			next += len("-next-line")
		case strings.HasPrefix(rest, "-file"):
			scope = ScopeFile
			next += len("-file")
		}
		after := line[next:]
		// "aitriage-ignored" or "aitriage-ignore-files" is prose, not a directive.
		if after != "" && isWordByte(after[0]) {
			pos = next
			continue
		}
		if kinds == nil {
			kinds, _ = classifyLine(line, state)
		}
		if !opensComment(line, start, kinds, state) {
			pos = next
			continue
		}
		ids, consumed := parseIDs(after)
		directives = append(directives, Directive{Scope: scope, IDs: ids})
		pos = next + consumed
	}
}

// markerBytes are the characters comment markers are made of, including
// template forms such as "{#", "{{/*" and "<%#".
const markerBytes = "#/*!-<;{%"

// opensComment reports whether the directive keyword at line[at] opens a
// comment: it follows a comment marker that starts the line or follows a
// space, or it starts a line inside a block comment. kinds classifies the
// line's bytes (see classifyLine) and state is what the line starts in.
func opensComment(line string, at int, kinds []byte, state lexState) bool {
	end := at
	for end > 0 && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && strings.IndexByte(markerBytes, line[start-1]) >= 0 {
		start--
	}
	marker := line[start:end]
	atLineStart := strings.TrimLeft(line[:start], " \t") == ""
	switch {
	case marker == "":
		// A line of its own inside a block comment opened above. Inside a
		// string that spans lines it is text.
		return atLineStart && state.comment()
	case strings.Trim(marker, "*") == "":
		// The " * " that starts each line of a "/** … */" block.
		return atLineStart && state == inSlashStar
	case !strings.Contains(marker, "#") && !strings.Contains(marker, "//") && !strings.Contains(marker, "/*") &&
		!strings.Contains(marker, "--") && !strings.Contains(marker, ";"):
		return false
	}
	// "http://host/#aitriage-ignore-file" and "[docs](#aitriage-ignore-file)"
	// are a link, not a comment; a marker inside a string literal is text.
	if !atLineStart && line[start-1] != ' ' && line[start-1] != '\t' {
		return false
	}
	return kinds[start] != stringByte
}

// lexState is what a line starts in: code, a block comment, or a string that
// spans lines.
type lexState uint8

const (
	inCode         lexState = iota
	inSlashStar             // /* … */
	inMarkup                // <!-- … -->
	inTripleDouble          // """ … """: Python, and Kotlin, Swift or Java text blocks
	inTripleSingle          // ''' … ''': Python
	inBacktick              // ` … `: a JS/TS template literal or a Go raw string
)

// comment reports whether the state is a block comment.
func (s lexState) comment() bool {
	return s == inSlashStar || s == inMarkup
}

// closer is the delimiter that ends the state.
func (s lexState) closer() string {
	switch s {
	case inSlashStar:
		return "*/"
	case inMarkup:
		return "-->"
	case inTripleDouble:
		return `"""`
	case inTripleSingle:
		return "'''"
	case inBacktick:
		return "`"
	}
	return ""
}

// end returns the index just past the delimiter in line[from:] that ends the
// state, or -1 when the line does not end it. A backslash escapes the next
// byte of a triple-quoted string. A backtick string has no escapes, as in a Go
// raw string: `\` is a whole string there, and the escaped backticks of a
// template literal ("\`code\`") come in pairs, which keeps the count even.
func (s lexState) end(line string, from int) int {
	closer := s.closer()
	if s.comment() {
		if i := strings.Index(line[from:], closer); i >= 0 {
			return from + i + len(closer)
		}
		return -1
	}
	for i := from; i < len(line); i++ {
		if line[i] == '\\' && s != inBacktick {
			i++
			continue
		}
		if strings.HasPrefix(line[i:], closer) {
			return i + len(closer)
		}
	}
	return -1
}

// Byte classes classifyLine assigns; any other byte is code.
const (
	stringByte byte = iota + 1
	commentByte
)

// classifyLine marks every byte of line as code, string literal or comment,
// and returns the state at its end: what the next line starts in. It knows no
// language, so it errs towards reading text as code:
//   - a single or double quote opens a string only when the same line closes
//     it, so an apostrophe in "don't" or a Rust lifetime is not a string;
//   - "#", "--" and ";" start a line comment at the start of the line, after
//     whitespace, or after the "{" or "%" of a template comment ("{#", "<%#");
//     "//" and "/*" after whitespace, a bracket or a semicolon. "https://",
//     "x--", "a#b" and "src/*" are not comments;
//   - line comments and single-quoted or double-quoted strings end with the
//     line. Block comments (/* … */, <!-- … -->), strings between three
//     double or three single quotes (Python docstrings) and backtick strings
//     (template literals, Go raw strings) continue on the next line until
//     they are closed.
func classifyLine(line string, state lexState) ([]byte, lexState) {
	kinds := make([]byte, len(line))
	mark := func(from, to int, kind byte) {
		for i := from; i < to; i++ {
			kinds[i] = kind
		}
	}
	i := 0
	// opens enters next at line[i], which starts with its opening delimiter.
	opens := func(next lexState, delimiter string, kind byte) {
		state = next
		mark(i, i+len(delimiter), kind)
		i += len(delimiter)
	}
	for i < len(line) {
		if state != inCode {
			kind := stringByte
			if state.comment() {
				kind = commentByte
			}
			end := state.end(line, i)
			if end < 0 {
				mark(i, len(line), kind)
				return kinds, state
			}
			mark(i, end, kind)
			i = end
			state = inCode
			continue
		}
		var prev byte = ' '
		if i > 0 {
			prev = line[i-1]
		}
		rest := line[i:]
		switch c := line[i]; {
		case strings.HasPrefix(rest, "<!--"):
			opens(inMarkup, "<!--", commentByte)
		case strings.HasPrefix(rest, "/*") && strings.IndexByte(" \t;{}()", prev) >= 0:
			opens(inSlashStar, "/*", commentByte)
		case strings.HasPrefix(rest, "//") && strings.IndexByte(" \t;{}()", prev) >= 0,
			(c == '#' || c == ';' || strings.HasPrefix(rest, "--")) && strings.IndexByte(" \t{%", prev) >= 0:
			mark(i, len(line), commentByte)
			return kinds, inCode
		case strings.HasPrefix(rest, `"""`):
			opens(inTripleDouble, `"""`, stringByte)
		case strings.HasPrefix(rest, "'''"):
			opens(inTripleSingle, "'''", stringByte)
		case c == '`':
			opens(inBacktick, "`", stringByte)
		case c == '"' || c == '\'':
			end := closingQuote(line, i)
			if end < 0 {
				i++
				continue
			}
			mark(i, end+1, stringByte)
			i = end + 1
		default:
			i++
		}
	}
	return kinds, state
}

// closingQuote returns the index of the unescaped quote that closes the one at
// line[open], or -1 when the line does not close it.
func closingQuote(line string, open int) int {
	quote := line[open]
	for i := open + 1; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case quote:
			return i
		}
	}
	return -1
}

// openers are what can start a state that continues on the next line.
var openers = [][]byte{[]byte("/*"), []byte("<!--"), []byte(`"""`), []byte("'''"), []byte("`")}

// advanceState returns the state after line, given the one it starts in. Most
// lines hold nothing that opens or closes a block comment or a string that
// spans lines, and are not lexed.
func advanceState(line []byte, state lexState) lexState {
	if state == inCode {
		lex := false
		for _, opener := range openers {
			if bytes.Contains(line, opener) {
				lex = true
				break
			}
		}
		if !lex {
			return inCode
		}
	} else if !bytes.Contains(line, []byte(state.closer())) {
		return state
	}
	_, state = classifyLine(string(line), state)
	return state
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

// parseIDs reads the ID list that follows a keyword and reports how many bytes
// it consumed. IDs are separated by commas or spaces. The first token and
// every token after a comma are IDs; a token after a space alone is one only
// when it looks like a rule id, and otherwise starts the reason that ends the
// list. "B105 allowed in tests" yields only B105 while "ENTR-18
// PY-BINDING-ALL" yields both: free text must never widen a suppression, and
// IDs separated by a space, which the earlier substring matching accepted,
// must keep working. The list also ends at punctuation such as "(".
func parseIDs(s string) ([]string, int) {
	i := skipSpace(s, 0)
	if i < len(s) && (s[i] == ':' || s[i] == '=') {
		i++
	}
	var ids []string
	afterSpace := false // the token follows a space, not the keyword or a comma
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
		id := strings.TrimRight(s[start:i], ".:/-")
		if afterSpace && !looksLikeRuleID(id) {
			return ids, start
		}
		ids = append(ids, id)
		next := skipSpace(s, i)
		switch {
		case next < len(s) && s[next] == ',':
			i, afterSpace = next+1, false
		case next > i:
			i, afterSpace = next, true
		default:
			// The token ends at punctuation other than a comma, or the line
			// ends: so does the list.
			return ids, i
		}
	}
}

// looksLikeRuleID reports whether a word written after an ID with only a space
// between is another ID rather than the start of a reason. Rule ids carry a
// digit or punctuation (B105, ENTR-18, CVE-2024-1234, nginx_missing_csp,
// python.lang.security.audit.eval, gitleaks:jwt) or are written in capitals
// (SECRET); words of a sentence ("allowed", "we", "tests") are neither. "all"
// in any case is a word here: "B105 all good" must not silence every rule.
func looksLikeRuleID(token string) bool {
	if token == "" || strings.EqualFold(token, allRules) {
		return false
	}
	if strings.ContainsAny(token, "0123456789-:._") {
		return true
	}
	for i := 0; i < len(token); i++ {
		if c := token[i]; (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
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
	state := inCode
	for len(content) > 0 && current < last {
		current++
		var text []byte
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			text, content = content[:i], content[i+1:]
		} else {
			text, content = content, nil
		}
		// Block comments and strings that span lines are tracked on every
		// line, relevant or not: a directive on a line of its own counts only
		// inside a block comment, and never inside such a string.
		startState := state
		state = advanceState(text, state)
		relevant := current <= FileHeaderLines || current == line || current == line-1
		if !relevant || !bytes.Contains(text, keywordStem) {
			continue
		}
		for _, d := range parseLine(string(text), startState) {
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
