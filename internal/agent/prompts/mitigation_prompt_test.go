package prompts

import (
	"strings"
	"testing"
)

// Models dismissed findings by citing comments, configuration, and the
// vulnerable line itself as "code_mitigation". The prompt must rule each of
// those out explicitly, matching the evidence validator.
func TestClassificationPromptStatesWhatIsNotACodeMitigation(t *testing.T) {
	for _, want := range []string{
		"comments, docstrings",
		"README",
		"string literals",
		"the flagged line itself",
		"environment variable names",
		"configuration flags",
		"cite the line",
		"where it is actually applied",
		"never accepted for configuration or data files",
	} {
		if !strings.Contains(ClassificationSystemPrompt, want) {
			t.Errorf("classification prompt does not say %q", want)
		}
	}
}

// The evidence contract changed, so verdicts cached under the previous prompt
// must not be served under this one.
func TestPromptVersionWasBumpedForTheEvidenceContract(t *testing.T) {
	if SecureCoderPromptVersion == "securecoder-v3" {
		t.Error("the evidence contract changed but SecureCoderPromptVersion did not")
	}
}
