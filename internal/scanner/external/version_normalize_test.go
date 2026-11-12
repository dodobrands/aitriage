package external

import "testing"

// Trivy prints "Version: 0.72.0"; manifests and summaries should show the bare
// version like the other scanners.
func TestNormalizeToolVersionDropsVersionLabel(t *testing.T) {
	cases := map[string]string{
		"Version: 0.72.0\nVulnerability DB:\n  Version: 2\n": "0.72.0",
		"1.170.1\n":                             "1.170.1",
		"v8.30.1":                               "v8.30.1",
		"bandit 1.9.4\n  python version = 3.11": "bandit 1.9.4",
	}
	for in, want := range cases {
		if got := normalizeToolVersion(in); got != want {
			t.Errorf("normalizeToolVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
