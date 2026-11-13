package external

import (
	"encoding/json"
	"slices"
	"testing"
)

// banditReport renders a Bandit JSON report with one result per test id and
// issue text, all on app/settings.py, one line each.
func banditReport(t *testing.T, results [][2]string) []byte {
	t.Helper()
	type result struct {
		TestID    string `json:"test_id"`
		TestName  string `json:"test_name"`
		Severity  string `json:"issue_severity"`
		Text      string `json:"issue_text"`
		Filename  string `json:"filename"`
		LineRange []int  `json:"line_range"`
	}
	var out struct {
		Results []result `json:"results"`
	}
	for i, r := range results {
		out.Results = append(out.Results, result{
			TestID: r[0], TestName: "test", Severity: "LOW", Text: r[1],
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

// Bandit's password tests flag any string assigned to, compared with or passed
// as a name containing "password", "token" or "secret": error messages, empty
// defaults and the names of tokens became hardcoded secrets that a person had
// to review. Those are dropped; every literal that could be a credential is
// kept, weak ones included.
func TestBanditPasswordReportsQuotingNoCredentialAreDropped(t *testing.T) {
	dropped := []string{
		"",
		"   ",
		"Wrong user name or password",
		"Incorrect email or password.",
		"Token has expired, please sign in again",
		"Password must contain at least 12 characters",
		"Invalid token: {}",
		"Session %s is no longer valid",
		"Authorization header must start with 'Bearer'",
		"csrf_token",
		"X-XSRF-TOKEN",
		"idToken",
		"session-token",
	}
	kept := []string{
		"hunter22",
		"Tr0ub4dor&3",
		"8f2Kq9vLx3TzR7mW4pYc",
		"P@ss w0rd!",
		"Basic dXNlcjpwYXNz",
		"Bearer 9f8e7d6c5b4a3f2e1d0c",
		"signing key 4f9a8b7c6d5e4f3a2b1c",
		"recovery code 4815162342",
		"Token abc123def456",
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
	var results [][2]string
	for _, literal := range dropped {
		results = append(results, [2]string{"B105", password(literal)})
	}
	for _, literal := range kept {
		results = append(results, [2]string{"B105", password(literal)})
	}
	findings, err := parseBanditReport(banditReport(t, results))
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, f := range findings {
		reported[f.Message] = true
	}
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

// B106 and B107 quote the literal the same way; other tests, and texts in a
// form the filter does not recognise, are never dropped.
func TestBanditFilterAppliesOnlyToPasswordReports(t *testing.T) {
	findings, err := parseBanditReport(banditReport(t, [][2]string{
		{"B106", password("Wrong user name or password")},
		{"B107", `Possible hardcoded password: ""`},
		{"B107", password("csrf_token")},
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
