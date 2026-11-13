package external

import (
	"encoding/json"
	"slices"
	"testing"
)

// banditReport renders a Bandit JSON report with one result per test id, issue
// text and quoted code, all on app/settings.py, one line each.
func banditReport(t *testing.T, results [][3]string) []byte {
	t.Helper()
	type result struct {
		TestID    string `json:"test_id"`
		TestName  string `json:"test_name"`
		Severity  string `json:"issue_severity"`
		Text      string `json:"issue_text"`
		Code      string `json:"code,omitempty"`
		Filename  string `json:"filename"`
		LineRange []int  `json:"line_range"`
	}
	var out struct {
		Results []result `json:"results"`
	}
	for i, r := range results {
		out.Results = append(out.Results, result{
			TestID: r[0], TestName: "test", Severity: "LOW", Text: r[1], Code: r[2],
			Filename: "app/settings.py", LineRange: []int{i + 1},
		})
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func password(literal string) string {
	return "Possible hardcoded password: '" + literal + "'"
}

// reportedLiterals parses a report of one B105 result per literal, each with
// the code given for it, and returns which literals were reported.
func reportedLiterals(t *testing.T, literals, code []string) map[string]bool {
	t.Helper()
	var results [][3]string
	for i, literal := range literals {
		results = append(results, [3]string{"B105", password(literal), code[i]})
	}
	findings, err := parseBanditReport(banditReport(t, results))
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, f := range findings {
		reported[f.Message] = true
	}
	return reported
}

// Bandit's password tests flag any string assigned to, compared with or passed
// as a name containing "password", "token" or "secret": messages about a
// credential and empty defaults became hardcoded secrets that a person had to
// review. Those are dropped; every literal that could be a credential is
// kept, weak ones, passphrases and backdoors included.
func TestBanditPasswordReportsQuotingNoCredentialAreDropped(t *testing.T) {
	dropped := []string{
		"",
		"   ",
		// Messages that name a credential.
		"Invalid credentials",
		"Password is required",
		"Enter your password",
		"Incorrect username or password",
		"Wrong user name or password",
		"Incorrect email or password.",
		"Token has expired, please sign in again",
		"Password must contain at least 12 characters",
		"Your secret key was rotated",
		// Messages and templates with a format placeholder.
		"Login failed: %s",
		"Invalid token: {}",
		"Session %s is no longer valid",
		"Bearer %s",
		"Rotated key %d of %d",
		"Token {0} revoked",
		"Reset link sent to {email}",
	}
	kept := []string{
		"hunter22",
		"Tr0ub4dor&3",
		"8f2Kq9vLx3TzR7mW4pYc",
		"P@ss w0rd!",
		"Basic dXNlcjpwYXNz",
		"Bearer 9f8e7d6c5b4a3f2e1d0c",
		"recovery code 4815162342",
		// Passphrases: words, digits and punctuation do not make a message.
		"correct horse battery staple",
		"correct horse battery staple 2024",
		"purple monkey dishwasher",
		"winter is coming soon",
		"Ocean Breeze 1987!",
		"P@ss w0rd 2024!",
		"admin pass 1234",
		// A backdoor reads like a request but names no credential:
		// form["password"] == "let me in please".
		"let me in please",
		// A credential word counts only as a whole word.
		"monkey keyboard tokenizer",
		// A literal that holds a value which could be a credential on its
		// own, or a placeholder a signing key is shipped with, is a
		// credential even when it names one.
		"signing key 4f9a8b7c6d5e4f3a2b1c",
		"Token abc123def456",
		"Invalid token 9f8e7d6c5b4a3f2e1d0c",
		"change this secret key",
		"please change me",
		// A bare credential noun is also the placeholder a signing key or a
		// static token is left at.
		"secret",
		"password",
		"api_key",
		"super_secret_key",
		"my_api_token",
		"auth_token",
		"Bearer ",
	}
	literals := append(append([]string(nil), dropped...), kept...)
	reported := reportedLiterals(t, literals, make([]string, len(literals)))
	for _, literal := range dropped {
		if reported["test: "+password(literal)] {
			t.Errorf("%q was reported as a hardcoded password", literal)
		}
	}
	for _, literal := range kept {
		if !reported["test: "+password(literal)] {
			t.Errorf("%q was dropped; a literal that could be a credential must be reported", literal)
		}
	}
}

// The name of a token issued at run time is dropped only when the code Bandit
// quotes uses it as the name of a cookie, a header or a mapping key. The same
// name assigned to a signing key is a weak secret, and without the code there
// is no telling which it is: both are kept.
func TestBanditIssuedTokenNamesAreDroppedOnlyWhereTheCodeUsesThemAsKeys(t *testing.T) {
	for _, tc := range []struct {
		literal, code string
		dropped       bool
	}{
		{"csrf_token", "12 response.set_cookie(\"csrf_token\", token, httponly=True)\n", true},
		{"access_token", "12 response.set_cookie(key='access_token', value=token)\n", true},
		{"refresh_token", "30 response.delete_cookie( 'refresh_token' )\n", true},
		{"session-token", "8 value = request.cookies.get(\"session-token\")\n", true},
		{"idToken", "8 raw = request.COOKIES['idToken']\n", true},
		{"X-XSRF-TOKEN", "20 def check(request):\n21     header = request.headers[\"X-XSRF-TOKEN\"]\n22     return header\n", true},
		{"id_token", "40 return claims.get('id_token')\n", true},
		{"access_token", "3 JWT_SECRET = \"access_token\"\n", false},
		{"csrf_token", "", false},
		{"csrf_token", "9 if token_name == \"csrf_token\":\n", false},
		{"csrf_token", "9 response.set_cookie(\"csrftoken\", token)\n", false},
		{"csrf_token", "9 value = data.get(name, 'csrf_token')\n", false},
		{"session_token", "9 SESSION_TOKEN_COOKIE = 'session_token'\n10 response.set_cookie(SESSION_TOKEN_COOKIE, token)\n", false},
		{"access_token", "9 response.reset_cookie('access_token')\n", false},
	} {
		reported := reportedLiterals(t, []string{tc.literal}, []string{tc.code})
		if got := !reported["test: "+password(tc.literal)]; got != tc.dropped {
			t.Errorf("%q with code %q: dropped = %v, want %v", tc.literal, tc.code, got, tc.dropped)
		}
	}
}

// B106 and B107 quote the literal the same way; other tests, and texts in a
// form the filter does not recognise, are never dropped.
func TestBanditFilterAppliesOnlyToPasswordReports(t *testing.T) {
	findings, err := parseBanditReport(banditReport(t, [][3]string{
		{"B106", password("Wrong user name or password")},
		{"B107", `Possible hardcoded password: ""`},
		{"B107", password("csrf_token"), "7 def read_csrf(request, token_name=\"csrf_token\"):\n8     return request.cookies.get(\"csrf_token\")\n"},
		{"B602", "subprocess call with shell=True identified, security issue."},
		{"B105", "Possible hardcoded password: Wrong user name or password"},
		{"B105", "Hardcoded password: ''"},
		{"B106", password("hunter22")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, f := range findings {
		kept = append(kept, f.RuleID)
	}
	if want := []string{"B602", "B105", "B105", "B106"}; !slices.Equal(kept, want) {
		t.Fatalf("kept %v; want %v", kept, want)
	}
	if findings[3].Line != 7 || findings[3].File != "app/settings.py" || findings[3].Severity != "LOW" {
		t.Errorf("finding = %+v; want the report's own location and severity", findings[3])
	}
}

func TestBanditPasswordLiteral(t *testing.T) {
	cases := []struct {
		text, literal string
		ok            bool
	}{
		{"Possible hardcoded password: 'abc'", "abc", true},
		{`Possible hardcoded password: "abc"`, "abc", true},
		{"Possible hardcoded password: 'it's'", "it's", true},
		{"Possible hardcoded password: ''", "", true},
		{"Possible hardcoded password: 'abc\"", "", false},
		{"Possible hardcoded password: abc", "", false},
		{"Possible hardcoded password: '", "", false},
		{"subprocess call with shell=True", "", false},
	}
	for _, tc := range cases {
		literal, ok := banditPasswordLiteral(tc.text)
		if literal != tc.literal || ok != tc.ok {
			t.Errorf("banditPasswordLiteral(%q) = %q, %t; want %q, %t", tc.text, literal, ok, tc.literal, tc.ok)
		}
	}
}

func TestBanditReportParseError(t *testing.T) {
	if _, err := parseBanditReport([]byte("not json")); err == nil {
		t.Fatal("a report that is not JSON was accepted")
	}
}
