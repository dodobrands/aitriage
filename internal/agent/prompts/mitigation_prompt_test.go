package prompts

import (
	"strings"
	"testing"
)

// classificationPromptText is the classification prompt with its line breaks
// and indentation collapsed, so a check does not depend on where a sentence
// wraps.
func classificationPromptText() string {
	return strings.Join(strings.Fields(ClassificationSystemPrompt), " ")
}

// Models dismissed findings by citing comments, configuration, and the
// vulnerable line itself as "code_mitigation". The prompt must rule each of
// those out explicitly, matching the evidence validator.
func TestClassificationPromptStatesWhatIsNotACodeMitigation(t *testing.T) {
	prompt := classificationPromptText()
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
		if !strings.Contains(prompt, want) {
			t.Errorf("classification prompt does not say %q", want)
		}
	}
}

// The validator ties code_mitigation evidence to its finding and keeps
// CRITICAL findings for a person; the prompt states the same rules so a model
// can meet them.
func TestClassificationPromptStatesHowAMitigationIsTiedToItsFinding(t *testing.T) {
	prompt := classificationPromptText()
	for _, want := range []string{
		"in the same function as the flagged line, above it and at most 30 lines before it",
		"code only (no comment or string text)",
		"names a variable or function the flagged statement uses",
		"never dismisses a CRITICAL finding",
		"return Needs Manual Review or True Positive",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("classification prompt does not say %q", want)
		}
	}
}

// The cited line must be a guard or x = f(x): the prompt names both and the
// look-alikes the validator rejects.
func TestClassificationPromptStatesTheShapeOfAMitigation(t *testing.T) {
	prompt := classificationPromptText()
	for _, want := range []string{
		"a guard of that variable or a re-assignment of it through a call",
		"exits early (return, raise, throw, abort) or encloses the flagged statement",
		"x = f(x)",
		"The assignment that produces the value",
		"a call whose result nothing checks",
		"a check in another function are not mitigations",
		"other than Python, Go, JavaScript and TypeScript",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("classification prompt does not say %q", want)
		}
	}
}

// A hardcoded secret is never a False Positive, whatever the evidence basis.
func TestClassificationPromptNeverDismissesAHardcodedSecret(t *testing.T) {
	if want := "A hardcoded secret (credential, key, token) is never a False Positive, not even in a test file"; !strings.Contains(classificationPromptText(), want) {
		t.Errorf("classification prompt does not say %q", want)
	}
}

// A verdict is bound to its finding by finding_index and finding_id. The
// prompt must not ask for the fingerprint: models garble long hex strings,
// and the validator no longer checks one.
func TestClassificationPromptBindsVerdictsByFindingID(t *testing.T) {
	prompt := classificationPromptText()
	if want := "Echo the exact finding_id from the input for every entry"; !strings.Contains(prompt, want) {
		t.Errorf("classification prompt does not say %q", want)
	}
	if strings.Contains(strings.ToLower(prompt), "fingerprint") {
		t.Error("classification prompt still asks for the fingerprint")
	}
}

// The evidence contract changed, so verdicts cached under the previous prompt
// must not be served under this one.
func TestPromptVersionWasBumpedForTheEvidenceContract(t *testing.T) {
	for _, previous := range []string{"securecoder-v3", "securecoder-v4", "securecoder-v5", "securecoder-v6", "securecoder-v7"} {
		if SecureCoderPromptVersion == previous {
			t.Errorf("the evidence contract changed but SecureCoderPromptVersion is still %q", previous)
		}
	}
}
