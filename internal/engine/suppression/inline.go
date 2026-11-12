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
// A directive counts only when it opens a comment: it follows a comment marker
// ("#", "//", "/*", "<!--", "--" or ";", including forms such as "///", "{#"
// and "{{/*") that starts the line or follows a space, or it starts a line
// inside a block comment, optionally after the "*" of a "/** … */" block.
// Anything else is a mention of the directive, not a decision: a README
// sentence such as "add aitriage-ignore-file to skip a file", a string literal
// such as "put aitriage-ignore-file here", a documentation link to
// "#aitriage-ignore-file", or a comment that merely refers to the directive.
// Any of them used to silence every finding in its file.
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
// not start inside a block comment.
func ParseLine(line string) []Directive {
	return parseLine(line, noBlock)
}

// parseLine returns the directives on one line. block is the block comment the
// line starts in, if any.
func parseLine(line string, block blockComment) []Directive {
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
			kinds, _ = classifyLine(line, block)
		}
		if !opensComment(line, start, kinds, block) {
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
// line's bytes (see classifyLine) and block is the block comment the line
// starts in.
func opensComment(line string, at int, kinds []byte, block blockComment) bool {
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
		// A line of its own inside a block comment opened above.
		return atLineStart && block != noBlock
	case strings.Trim(marker, "*") == "":
		// The " * " that starts each line of a "/** … */" block.
		return atLineStart && block == slashStarBlock
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

// blockComment is the kind of block comment a line starts in.
type blockComment uint8

const (
	noBlock        blockComment = iota
	slashStarBlock              // /* … */
	markupBlock                 // <!-- … -->
)

// Byte classes classifyLine assigns; any other byte is code.
const (
	stringByte byte = iota + 1
	commentByte
)

// classifyLine marks every byte of line as code, string literal or comment,
// and returns the block comment still open at its end. It knows no language,
// so it errs towards reading text as code:
//   - a quote opens a string only when the same line closes it, so an
//     apostrophe in "don't" or a Rust lifetime is not a string;
//   - "#", "--" and ";" start a line comment at the start of the line, after
//     whitespace, or after the "{" or "%" of a template comment ("{#", "<%#");
//     "//" and "/*" after whitespace, a bracket or a semicolon. "https://",
//     "x--", "a#b" and "src/*" are not comments;
//   - strings and comments do not span lines, except /* … */ and <!-- … -->.
func classifyLine(line string, block blockComment) ([]byte, blockComment) {
	kinds := make([]byte, len(line))
	mark := func(from, to int, kind byte) {
		for i := from; i < to; i++ {
			kinds[i] = kind
		}
	}
	for i := 0; i < len(line); {
		if block != noBlock {
			closer := "*/"
			if block == markupBlock {
				closer = "-->"
			}
			end := strings.Index(line[i:], closer)
			if end < 0 {
				mark(i, len(line), commentByte)
				return kinds, block
			}
			mark(i, i+end+len(closer), commentByte)
			i += end + len(closer)
			block = noBlock
			continue
		}
		var prev byte = ' '
		if i > 0 {
			prev = line[i-1]
		}
		rest := line[i:]
		switch c := line[i]; {
		case strings.HasPrefix(rest, "<!--"):
			block = markupBlock
			mark(i, i+4, commentByte)
			i += 4
		case strings.HasPrefix(rest, "/*") && strings.IndexByte(" \t;{}()", prev) >= 0:
			block = slashStarBlock
			mark(i, i+2, commentByte)
			i += 2
		case strings.HasPrefix(rest, "//") && strings.IndexByte(" \t;{}()", prev) >= 0,
			(c == '#' || c == ';' || strings.HasPrefix(rest, "--")) && strings.IndexByte(" \t{%", prev) >= 0:
			mark(i, len(line), commentByte)
			return kinds, noBlock
		case c == '"' || c == '\'' || c == '`':
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
	return kinds, block
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

// advanceBlock returns the block comment open after line, given the one it
// starts in. Most lines hold no block comment marker and are not lexed.
func advanceBlock(line []byte, block blockComment) blockComment {
	switch block {
	case noBlock:
		if !bytes.Contains(line, []byte("/*")) && !bytes.Contains(line, []byte("<!--")) {
			return noBlock
		}
	case slashStarBlock:
		if !bytes.Contains(line, []byte("*/")) {
			return block
		}
	case markupBlock:
		if !bytes.Contains(line, []byte("-->")) {
			return block
		}
	}
	_, block = classifyLine(string(line), block)
	return block
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
	block := noBlock
	for len(content) > 0 && current < last {
		current++
		var text []byte
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			text, content = content[:i], content[i+1:]
		} else {
			text, content = content, nil
		}
		// Block comments are tracked on every line, relevant or not: a
		// directive on a line of its own counts only inside one.
		startBlock := block
		block = advanceBlock(text, block)
		relevant := current <= FileHeaderLines || current == line || current == line-1
		if !relevant || !bytes.Contains(text, keywordStem) {
			continue
		}
		for _, d := range parseLine(string(text), startBlock) {
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
