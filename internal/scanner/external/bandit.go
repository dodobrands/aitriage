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
		if quotesNoCredential(r.TestID, r.Text) {
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
//   - it is prose: words separated by spaces, by the reading the built-in
//     detector uses, none of which looks like a token on its own
//     ("Basic dXNlcjpwYXNz", "Bearer 9f8e…" stay);
//   - it names a token that is only ever issued at run time: an OAuth 2.0
//     access or refresh token, an OpenID Connect ID token, a CSRF or a
//     session token ("csrf_token", "X-XSRF-TOKEN"). Such a token is never
//     spelled like its own name, so the literal is a cookie, header or field
//     name.
//
// Everything else is kept, short and weak values included. A bare credential
// noun ("password", "secret", "api_key") is kept as well: it is the field name
// in a form, but it is also the placeholder value a signing key or a static
// API token is left at, which is a real weakness.

// banditPasswordTests are Bandit's hardcoded-password tests.
var banditPasswordTests = map[string]bool{"B105": true, "B106": true, "B107": true}

// banditPasswordPrefix starts the text of every hardcoded-password report.
const banditPasswordPrefix = "Possible hardcoded password: "

// quotesNoCredential reports whether a Bandit hardcoded-password report quotes
// a literal that cannot be a credential. Reports of other tests, and texts in
// a form it does not recognise, are kept.
func quotesNoCredential(testID, text string) bool {
	if !banditPasswordTests[strings.ToUpper(strings.TrimSpace(testID))] {
		return false
	}
	literal, ok := banditPasswordLiteral(text)
	if !ok {
		return false
	}
	return strings.TrimSpace(literal) == "" || isProse(literal) || namesIssuedToken(literal)
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

// proseWords matches words of letters separated by spaces, later words
// allowing sentence punctuation: "Wrong user name or password." It is the
// built-in detector's reading of UI copy (engine.proseRegex).
var proseWords = regexp.MustCompile(`^\pL[\pL'’]*(?:[ \t]+[\pL'’.,!?:-]+)+$`)

// isProse reports whether a literal is a sentence or a label rather than a
// value: two or more words, by the built-in detector's reading (letters only,
// or at least three words with fewer than three symbols), and no word that
// could be a credential on its own.
func isProse(literal string) bool {
	v := strings.TrimSpace(literal)
	words := strings.Fields(v)
	if len(words) < 2 {
		return false
	}
	if !proseWords.MatchString(v) && !fewSymbols(v, words) {
		return false
	}
	for _, word := range words {
		if tokenLike(word) {
			return false
		}
	}
	return true
}

// fewSymbols reports a text of three or more words with fewer than three
// symbols, the built-in detector's other test for prose (engine.looksLikeProse):
// "Password must be at least 12 characters", "Token %s has expired".
func fewSymbols(v string, words []string) bool {
	if len(words) < 3 {
		return false
	}
	symbols := 0
	for _, r := range v {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune(".,:;'’()–—-/&?!", r) {
			symbols++
		}
	}
	return symbols < 3
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
// only ever issued at run time, which no literal can hold.
func namesIssuedToken(literal string) bool {
	return issuedTokenName.MatchString(strings.TrimSpace(literal))
}
