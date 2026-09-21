package prompts

import (
	"strings"
	"testing"
)

// The AI summary came out in English however the interface language was set,
// because "MUST respond in English" was baked into the shared system prompt.

func TestNormalizeLanguage(t *testing.T) {
	for input, want := range map[string]string{
		"ru":      "ru",
		"RU":      "ru",
		"ru-RU":   "ru",
		"ru_RU":   "ru",
		"en":      "en",
		"en-GB":   "en",
		"":        "en",
		"klingon": "en",
	} {
		if got := NormalizeLanguage(input); got != want {
			t.Errorf("NormalizeLanguage(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestLocalisationContractNamesTheRequestedLanguage(t *testing.T) {
	if !strings.Contains(LocalisationContract("ru"), "Russian") {
		t.Error("a Russian request does not ask for Russian prose")
	}
	if !strings.Contains(LocalisationContract("en"), "English") {
		t.Error("an English request does not ask for English prose")
	}
	// An unknown tag must still produce a usable contract.
	if !strings.Contains(LocalisationContract("xx"), "English") {
		t.Error("an unsupported language did not fall back to English")
	}
}

func TestLocalisationContractProtectsJoinKeys(t *testing.T) {
	contract := LocalisationContract("ru")

	// These are the values a human or a machine joins on. Translating any of
	// them would make two reports of the same project incomparable.
	for _, want := range []string{
		"CS-XXX-NNN",
		"CWE/CVE",
		"CRITICAL",
		"True Positive",
		"False Positive",
		"Needs Manual Review",
		"JSON key",
	} {
		if !strings.Contains(contract, want) {
			t.Errorf("contract does not protect %q from translation", want)
		}
	}
}

// The system prompt must stay byte-identical across languages. It is the stable
// prefix that provider-side prompt caching keys on, and this tool's whole cost
// story depends on that cache surviving.
func TestSystemPromptsAreLanguageIndependent(t *testing.T) {
	for name, prompt := range map[string]string{
		"threat model":   ThreatModelSystemPrompt,
		"classification": ClassificationSystemPrompt,
		"poc":            PoCSystemPrompt,
		"report":         ReportSystemPrompt,
		"fixspec":        FixSpecSystemPrompt,
	} {
		if strings.Contains(prompt, "Respond in Russian") || strings.Contains(prompt, "MUST respond in English") {
			t.Errorf("the %s system prompt hardcodes a language; language belongs in the per-request contract", name)
		}
		if !strings.Contains(prompt, "LOCALISATION CONTRACT") {
			t.Errorf("the %s system prompt does not defer to the localisation contract", name)
		}
	}
}

// Changing prompt text without bumping the version would serve verdicts produced
// by the old prompt from the cache namespace of the new one.
func TestPromptVersionWasBumpedForTheLocalisationChange(t *testing.T) {
	if SecureCoderPromptVersion == "securecoder-v2" {
		t.Error("the framework text changed but SecureCoderPromptVersion did not")
	}
}
