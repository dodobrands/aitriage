package engine

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ENTR-SLOP-01 flags files that are mostly unfinished scaffolding: TODO and
// FIXME notes, "placeholder" and "temporary" stubs, tempVar/result1/var2
// names. It is a code-quality signal, not a vulnerability, so it is LOW.

// slopMarker is the residue vocabulary. Word boundaries keep it from matching
// inside other words ("autodownload", "todos", "TodoList").
var slopMarker = regexp.MustCompile(`(?i)\b(?:todo|fixme|temporary|tempvar|result\d+|var\d+|placeholder)\b`)

const (
	// slopMinMarkers is the floor: a handful of notes is ordinary in any file.
	slopMinMarkers = 5
	// slopLinesPerMarker sets the density on top of the floor. A fixed count
	// punishes size: six TODO notes in a 3,000-line module are routine debt,
	// six in a 60-line file mean the file is mostly scaffolding. Requiring at
	// least one marker per 100 lines keeps every file up to 600 lines on the
	// old "more than five" rule and stops large files from tripping it.
	slopLinesPerMarker = 100
)

// slopExtensions are the source files the heuristic reads.
var slopExtensions = map[string]bool{
	".go": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".py": true,
}

// slopLanguage selects the lexical rules used to find strings and comments.
type slopLanguage int

const (
	slopC      slopLanguage = iota // JS/TS: '…' "…" `…`, // and /* */ comments
	slopGo                         // Go: as above, but `…` is raw (no escapes)
	slopPython                     // Python: '…' "…" '''…''' """…""", # comments
)

func slopLanguageFor(path string) slopLanguage {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return slopPython
	case ".go":
		return slopGo
	default:
		return slopC
	}
}

// countScaffoldingResidue counts residue markers in src and returns the
// 1-based line of the first one counted.
//
// Text inside string literals is data (UI copy, SQL, CSS in template
// literals), not residue. "placeholder" used in code as the name of an
// attribute, prop or field is form vocabulary: a TSX form with seven
// placeholder="…" inputs is an ordinary form. Comments are read as they are,
// since that is where scaffolding notes live.
func countScaffoldingResidue(src, path string) (count, firstLine int) {
	lexed := lexSource(src, slopLanguageFor(path))
	firstOffset := -1
	for _, loc := range slopMarker.FindAllStringIndex(lexed.masked, -1) {
		if strings.EqualFold(lexed.masked[loc[0]:loc[1]], "placeholder") &&
			!lexed.inComment(loc[0]) && isPropertyName(lexed.masked, loc[0], loc[1]) {
			continue
		}
		count++
		if firstOffset < 0 {
			firstOffset = loc[0]
		}
	}
	if count == 0 {
		return 0, 0
	}
	// Masking keeps offsets and newlines, so the line is the same in src.
	return count, strings.Count(lexed.masked[:firstOffset], "\n") + 1
}

// excessiveResidue applies the floor and the density rule.
func excessiveResidue(count, lines int) bool {
	return count > slopMinMarkers && count*slopLinesPerMarker >= lines
}

// lineCount returns the number of lines in src.
func lineCount(src string) int {
	n := strings.Count(src, "\n")
	if src != "" && !strings.HasSuffix(src, "\n") {
		n++
	}
	return n
}

// isPropertyName reports whether the word at s[start:end] names an attribute,
// prop or field: placeholder="…" or placeholder={…} (JSX and HTML),
// placeholder: and placeholder?: (object keys, TypeScript members) and
// x.placeholder (member access).
func isPropertyName(s string, start, end int) bool {
	if start > 0 && s[start-1] == '.' {
		return true
	}
	i := end
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i < len(s) && s[i] == '?' {
		i++
	}
	if i >= len(s) {
		return false
	}
	var next byte
	if i+1 < len(s) {
		next = s[i+1]
	}
	switch s[i] {
	case '=':
		return next != '=' && next != '>' // not a comparison or an arrow
	case ':':
		return next != ':'
	}
	return false
}

// lexedSource is a source file with the contents of its string literals
// replaced by spaces, plus the byte ranges of its comments. Newlines and byte
// offsets are kept, so a position found in masked is valid in the original.
type lexedSource struct {
	masked   string
	comments [][2]int // [start, end) byte ranges, in order
}

func (l lexedSource) inComment(offset int) bool {
	i := sort.Search(len(l.comments), func(i int) bool { return l.comments[i][1] > offset })
	return i < len(l.comments) && l.comments[i][0] <= offset
}

// lexSource masks string literals and records comments. It is a lexer, not a
// parser: a quote it misreads (an apostrophe in JSX text, a quote inside a
// regex literal) only affects the rest of that line, because single- and
// double-quoted strings end at a newline in every language handled here.
func lexSource(src string, lang slopLanguage) lexedSource {
	out := []byte(src)
	n := len(src)
	var comments [][2]int
	blank := func(from, to int) {
		for k := from; k < to && k < n; k++ {
			if out[k] != '\n' {
				out[k] = ' '
			}
		}
	}

	for i := 0; i < n; {
		c := src[i]
		switch {
		case lang == slopPython && c == '#',
			lang != slopPython && c == '/' && i+1 < n && src[i+1] == '/':
			end := lineEnd(src, i)
			comments = append(comments, [2]int{i, end})
			i = end
		case lang != slopPython && c == '/' && i+1 < n && src[i+1] == '*':
			end := n
			if j := strings.Index(src[i+2:], "*/"); j >= 0 {
				end = i + 2 + j + 2
			}
			comments = append(comments, [2]int{i, end})
			i = end
		case lang == slopPython && (c == '"' || c == '\'') && strings.HasPrefix(src[i:], strings.Repeat(string(c), 3)):
			delim := strings.Repeat(string(c), 3)
			end := closingDelimiter(src, i+3, delim)
			blank(i+3, end)
			i = end + len(delim)
		case c == '"' || c == '\'' || (c == '`' && lang != slopPython):
			multiline := c == '`'
			escapes := c != '`' || lang != slopGo
			end := closingQuote(src, i+1, c, multiline, escapes)
			blank(i+1, end)
			i = end + 1
		default:
			i++
		}
	}
	return lexedSource{masked: string(out), comments: comments}
}

// lineEnd returns the index of the newline ending the line at i (or len(s)).
func lineEnd(s string, i int) int {
	if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(s)
}

// closingQuote returns the index of the quote closing a literal whose content
// starts at from, or where an unterminated literal stops: the next newline for
// a single-line literal, the end of input otherwise.
func closingQuote(s string, from int, quote byte, multiline, escapes bool) int {
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if escapes {
				i++
			}
		case '\n':
			if !multiline {
				return i
			}
		case quote:
			return i
		}
	}
	return len(s)
}

// closingDelimiter returns the index of delim closing a triple-quoted Python
// string whose content starts at from, or len(s) if it is unterminated.
func closingDelimiter(s string, from int, delim string) int {
	for i := from; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], delim) {
			return i
		}
	}
	return len(s)
}
