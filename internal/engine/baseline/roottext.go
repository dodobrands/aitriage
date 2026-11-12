package baseline

import (
	"path/filepath"
	"regexp"
	"strings"
)

// rootTextDelimiters end a path mentioned in free text.
const rootTextDelimiters = `[\s"'),;:\]]`

// StripRootFromText removes an absolute project root from free text such as a
// scanner message ("Rule X found issue in /github/workspace/src/main.py"),
// leaving project-relative paths with forward slashes ("src/main.py"). A bare
// mention of the root becomes ".". Both the slash form and the platform's
// native form of the root are recognised, so a Windows message ("…found issue
// in D:\a\repo\src\main.py") is rewritten like a Unix one.
func StripRootFromText(root, text string) string {
	slash := strings.TrimSuffix(filepath.ToSlash(strings.TrimSpace(root)), "/")
	if slash == "" || text == "" {
		return text
	}
	text = stripRootForm(text, slash, "/")
	if native := filepath.FromSlash(slash); native != slash {
		text = stripRootForm(text, native, string(filepath.Separator))
	}
	return text
}

// stripRootForm strips one spelling of the root, whose path separator is sep.
// Paths found below it are returned with forward slashes.
func stripRootForm(text, root, sep string) string {
	if root == "" || !strings.Contains(text, root) {
		return text
	}
	re := regexp.MustCompile(regexp.QuoteMeta(root) + `(?:` + regexp.QuoteMeta(sep) + `([^\s"'),;:\]]*))?($|` + rootTextDelimiters + `)`)
	return re.ReplaceAllStringFunc(text, func(match string) string {
		groups := re.FindStringSubmatch(match)
		rest, delimiter := groups[1], groups[2]
		if rest == "" {
			return "." + delimiter
		}
		if sep != "/" {
			rest = strings.ReplaceAll(rest, sep, "/")
		}
		return rest + delimiter
	})
}
