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

// The validator ties code_mitigation evidence to its finding and keeps
// CRITICAL findings and hardcoded secrets for a person; the prompt states the
// same rules so a model can meet them.
func TestClassificationPromptStatesHowAMitigationIsTiedToItsFinding(t *testing.T) {
	for _, want := range []string{
		"above the flagged line and at most 30",
		"code only (no comment or string text)",
		"names a\n  variable or function the flagged statement uses",
		"never dismisses a CRITICAL finding or a hardcoded secret",
		"return Needs Manual\n  Review or True Positive",
	} {
		if !strings.Contains(ClassificationSystemPrompt, want) {
			t.Errorf("classification prompt does not say %q", want)
		}
	}
}

// The evidence contract changed, so verdicts cached under the previous prompt
// must not be served under this one.
func TestPromptVersionWasBumpedForTheEvidenceContract(t *testing.T) {
	for _, previous := range []string{"securecoder-v3", "securecoder-v4", "securecoder-v5"} {
		if SecureCoderPromptVersion == previous {
			t.Errorf("the evidence contract changed but SecureCoderPromptVersion is still %q", previous)
		}
	}
}
