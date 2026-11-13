package external

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

type banditOutput struct {
	Results []struct {
		TestID    string `json:"test_id"`
		TestName  string `json:"test_name"`
		Severity  string `json:"issue_severity"`
		Text      string `json:"issue_text"`
		Code      string `json:"code"`
		Filename  string `json:"filename"`
		LineRange []int  `json:"line_range"`
	} `json:"results"`
}

// RunBandit runs bandit (Python SAST) and returns unified findings.
func RunBandit(ctx context.Context, path string) ([]UnifiedFinding, error) {
	if !IsInstalled("bandit") {
		return nil, fmt.Errorf("bandit not installed")
	}
	excluded := banditExcludePaths(path)
	result, err := RunTool(ctx, "bandit", "-r", path, "-f", "json", "-q", "-x", strings.Join(excluded, ","))
	if err != nil {
		return nil, fmt.Errorf("bandit execution failed: %w", err)
	}
	return parseBanditReport([]byte(result.Stdout))
}

// parseBanditReport converts a Bandit JSON report into unified findings.
func parseBanditReport(data []byte) ([]UnifiedFinding, error) {
	var output banditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse bandit output: %w", err)
	}
	findings := make([]UnifiedFinding, 0, len(output.Results))
	for _, r := range output.Results {
		if isGeneratedArtifactPath(r.Filename) {
			continue
		}
		if quotesNoCredential(r.TestID, r.Text, r.Code) {
			continue
		}
		line := 0
		if len(r.LineRange) > 0 {
			line = r.LineRange[0]
		}
		findings = append(findings, UnifiedFinding{
			Source:   "bandit",
			RuleID:   r.TestID,
			Severity: r.Severity,
			Message:  fmt.Sprintf("%s: %s", r.TestName, r.Text),
			File:     r.Filename,
			Line:     line,
		})
	}
	return findings, nil
}

// Bandit's hardcoded-password tests (B105 string, B106 function argument, B107
// default argument) report any string literal assigned to, compared with or
// passed as a name containing "password", "pass", "pwd", "token" or "secret",
// and quote it: "Possible hardcoded password: '<literal>'". So an error
// message, an empty default or the name of a token reaches the report as a
// hardcoded secret, and a hardcoded secret is held for a person to decide.
// The built-in secret detector does not report such values at all, and
// neither does AITriage for Bandit. A report is dropped only when the literal
// cannot be a credential:
//   - it is empty or blank;
//   - it is a message about a credential: two or more words, among them a
//     word that names a credential ("Invalid credentials", "Password is
//     required", "Incorrect username or password") or a format placeholder
//     ("Login failed: %s", "Reset link sent to {email}"). A literal with a
//     word that could be a credential on its own ("signing key
//     4f9a8b7c6d5e") or that asks for the value to be replaced ("change this
//     secret key", the placeholder a signing key is shipped with) is kept;
//   - it names a token that is only ever issued at run time (an OAuth 2.0
//     access or refresh token, an OpenID Connect ID token, a CSRF or a
//     session token), and the code Bandit quotes uses it as the name of a
//     cookie, a header or a mapping key: response.set_cookie("csrf_token",
//     ...), request.headers["X-XSRF-TOKEN"], claims.get("id_token"). The same
//     name assigned to a signing key (JWT_SECRET = "access_token") is a weak
//     secret, and without the code there is no telling which it is.
//
// Everything else is kept, short and weak values included. Spaces, and words
// such as "please" or "not", do not make a message: a passphrase is words too
// ("correct horse battery staple", "winter is coming soon", "Ocean Breeze
// 1987!"), and so is a backdoor (form["password"] == "let me in please"). A
// bare credential noun ("password", "secret", "api_key") is kept as well: it
// is the field name in a form, but it is also the placeholder value a signing
// key or a static API token is left at, which is a real weakness.

// banditPasswordTests are Bandit's hardcoded-password tests.
var banditPasswordTests = map[string]bool{"B105": true, "B106": true, "B107": true}

// banditPasswordPrefix starts the text of every hardcoded-password report.
const banditPasswordPrefix = "Possible hardcoded password: "

// quotesNoCredential reports whether a Bandit hardcoded-password report quotes
// a literal that cannot be a credential; code is the source Bandit quotes
// with the report. Reports of other tests, and texts in a form it does not
// recognise, are kept.
func quotesNoCredential(testID, text, code string) bool {
	if !banditPasswordTests[strings.ToUpper(strings.TrimSpace(testID))] {
		return false
	}
	literal, ok := banditPasswordLiteral(text)
	if !ok {
		return false
	}
	return strings.TrimSpace(literal) == "" || isCredentialMessage(literal) ||
		(namesIssuedToken(literal) && usedAsKey(literal, code))
}

// banditPasswordLiteral returns the literal a hardcoded-password report quotes.
func banditPasswordLiteral(text string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(text), banditPasswordPrefix)
	if !ok || len(rest) < 2 {
		return "", false
	}
	quote := rest[0]
	if (quote != '\'' && quote != '"') || rest[len(rest)-1] != quote {
		return "", false
	}
	return rest[1 : len(rest)-1], true
}

// credentialWords name what a credential is. Each counts only as a whole word,
// in any case: "key" is not in "monkey".
var credentialWords = wordSet("password", "passwd", "passphrase", "credential", "credentials",
	"token", "secret", "key", "username", "login")

// replaceWords ask for the value to be replaced: the literal is a placeholder,
// which is a real weakness when it ships as the secret.
var replaceWords = wordSet("change", "changeme", "replace")

// formatPlaceholder matches a placeholder a message is formatted with: a
// printf verb ("%s", "%d", "%v") or a str.format or logging field ("{}",
// "{0}", "{name}").
var formatPlaceholder = regexp.MustCompile(`%[sdv]\b|\{(?:\d+|[A-Za-z_]\w*)?\}`)

// isCredentialMessage reports whether a literal is a message about a
// credential rather than a value: two or more words, among them a word that
// names a credential or a format placeholder, no word that could be a
// credential on its own and none that asks for the value to be replaced.
func isCredentialMessage(literal string) bool {
	fields := strings.Fields(literal)
	if len(fields) < 2 {
		return false
	}
	for _, field := range fields {
		if tokenLike(field) {
			return false
		}
	}
	message := formatPlaceholder.MatchString(literal)
	for _, word := range strings.FieldsFunc(strings.ToLower(literal), notWordRune) {
		if replaceWords[word] {
			return false
		}
		message = message || credentialWords[word]
	}
	return message
}

// notWordRune reports a rune that separates words: anything but a letter, a
// digit or "_", so "csrf_token" and "key1" are one word each, neither of them
// "token" or "key".
func notWordRune(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
}

func wordSet(words ...string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, w := range words {
		set[w] = true
	}
	return set
}

// tokenLike reports a word that could be a credential on its own: eight or
// more characters with a digit, or with a capital after a lower-case letter,
// as codes and encoded or generated values have ("48151623", "dXNlcjpwYXNz",
// "9f8e7d6c5b4a"). Words of a sentence are lower-case, capitalised or all
// capitals, and their numbers are short.
func tokenLike(word string) bool {
	if len(word) < 8 {
		return false
	}
	var digit, mixedCase bool
	prevLower := false
	for _, r := range word {
		if unicode.IsDigit(r) {
			digit = true
		}
		if unicode.IsUpper(r) && prevLower {
			mixedCase = true
		}
		prevLower = unicode.IsLower(r)
	}
	return digit || mixedCase
}

// issuedTokenName matches the name of a token issued at run time: an optional
// "x" header prefix, the kind of token and the word "token", separated by "_",
// "-", "." or nothing ("csrf_token", "X-XSRF-TOKEN", "idToken").
var issuedTokenName = regexp.MustCompile(`(?i)^(?:x[-_.]?)?(?:access|refresh|id|csrf|xsrf|session)[-_.]?token$`)

// namesIssuedToken reports whether a literal is the name of a token that is
// only ever issued at run time.
func namesIssuedToken(literal string) bool {
	return issuedTokenName.MatchString(strings.TrimSpace(literal))
}

// usedAsKey reports whether code, the source Bandit quotes with a report,
// uses literal, quoted, as the name of a cookie, a header or a mapping key:
// the first argument of set_cookie, delete_cookie or a .get call, or the key
// of cookies[...] or headers[...]. Code that is missing shows no such use.
func usedAsKey(literal, code string) bool {
	if strings.TrimSpace(code) == "" {
		return false
	}
	name := regexp.QuoteMeta(literal)
	use := regexp.MustCompile(`(?:\b(?:set_cookie|delete_cookie)\(\s*(?:key\s*=\s*)?|\.get\(\s*|\b(?i:cookies|headers)\[\s*)(?:'` + name + `'|"` + name + `")`)
	return use.MatchString(code)
}
