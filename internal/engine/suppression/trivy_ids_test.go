package suppression

import "testing"

// Trivy has reported one check as KSV012, AVD-KSV-0012 and KSV-0012 in
// different releases. A directive names the check the way its author saw it,
// and must keep covering the finding whichever spelling the next release
// reports.
func TestInlineDirectivesMatchEverySpellingOfATrivyCheck(t *testing.T) {
	content := []byte(`apiVersion: v1
kind: Pod
# aitriage-ignore-next-line: AVD-KSV-0012
spec:
  securityContext:
    runAsUser: 0  # aitriage-ignore: trivy:KSV012
  hostNetwork: true
`)
	for _, id := range []string{"KSV012", "KSV-0012", "AVD-KSV-0012"} {
		for _, line := range []int{4, 6, 7} {
			if !Suppressed(content, line, id, "trivy") {
				t.Errorf("Trivy's %s on line %d was not silenced", id, line)
			}
		}
	}
	if Suppressed(content, 6, "KSV-0017", "trivy") {
		t.Error("a directive for one check silenced another")
	}
	if Suppressed(content, 6, "KSV-0012", "semgrep") {
		t.Error("a trivy-qualified directive silenced another scanner")
	}
}

// Advisories and the rules of other sources still compare as written.
func TestInlineDirectivesKeepOtherIDsExact(t *testing.T) {
	content := []byte("requests==2.0.0  # aitriage-ignore: CVE-2024-0042, ENTR-018, B-0105\n")
	if !Suppressed(content, 1, "CVE-2024-0042", "trivy") {
		t.Error("the advisory the directive names was not silenced")
	}
	cases := []struct {
		id     string
		source string
	}{
		{"CVE-2024-42", "trivy"},
		{"ENTR-18", "aitriage"},
		{"B105", "bandit"},
	}
	for _, tc := range cases {
		if Suppressed(content, 1, tc.id, tc.source) {
			t.Errorf("%s from %s was silenced by a directive that spells another id", tc.id, tc.source)
		}
	}
}

// Only the spellings Trivy has used are read as one check. A word written
// after the ids of a directive is read as another id when it has a digit, so
// "DS26" in a reason must not silence DS-0026, and other Trivy families
// (tfsec's legacy AWS001 against Trivy's AWS-0001) compare as written.
func TestInlineDirectivesNormaliseOnlyRealTrivySpellings(t *testing.T) {
	content := []byte(`FROM alpine:3.20
# aitriage-ignore-next-line: KSV12, AWS001
USER root
COPY . /app  # aitriage-ignore: DS002 DS26 handled by the base image
`)
	for _, tc := range []struct {
		line int
		id   string
	}{
		{3, "KSV-0012"},
		{3, "AWS-0001"},
		{4, "DS-0026"},
	} {
		if Suppressed(content, tc.line, tc.id, "trivy") {
			t.Errorf("Trivy's %s on line %d was silenced by a directive that names no spelling of it", tc.id, tc.line)
		}
	}
	if !Suppressed(content, 4, "DS-0002", "trivy") {
		t.Error("the check the directive names was not silenced")
	}
}
