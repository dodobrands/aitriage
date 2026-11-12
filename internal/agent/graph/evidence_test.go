package graph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

// A verdict for another finding is rejected. When it is the only verdict the
// model ever gives, nothing was classified: the finding is triage-failed and
// the triage incomplete, never an ordinary fallback.
func TestClassifyFindingsRejectsWrongIdentityToNeedsReview(t *testing.T) {
	pinConcurrency(t)
	findings := []EnrichedFinding{{ID: "B101", VulnID: "CS-MISC-001", Severity: "LOW", File: "tests/a_test.py", Line: 7, Message: "assert"}}
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(_ int, _ []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"finding_id":"CS-OTHER","fingerprint":"wrong","disposition":"False Positive","confidence":"high","rationale":"wrong target","evidence":{"basis":"test_only","file":"tests/a_test.py","line":7}}]}`, nil
		},
	}
	var usage llm.Usage
	_, dispositions, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", t.TempDir(), "", findings, mock, &usage, 150)
	if !errors.Is(err, ErrTriageIncomplete) {
		t.Fatalf("ClassifyFindingsWithAudit() error = %v, want ErrTriageIncomplete", err)
	}
	if got := dispositions[0]; got.Disposition != "Needs Manual Review" || got.DispositionSource != dispositionSourceTriageFailed {
		t.Fatalf("disposition = %+v, want triage-failed Needs Manual Review", got)
	}
	if !auditMentions(audit, "finding_id does not match") {
		t.Fatalf("audit = %+v, want recorded rejection", audit)
	}
}

// A False Positive without evidence is rejected. The model did give the
// finding a verdict of its own, so it ends as an ordinary fallback: Needs
// Manual Review, never False Positive.
func TestClassifyFindingsRejectsFalsePositiveWithoutEvidence(t *testing.T) {
	pinConcurrency(t)
	findings := []EnrichedFinding{{ID: "B101", VulnID: "CS-MISC-001", Severity: "LOW", File: "tests/a_test.py", Line: 7, Message: "assert"}}
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(_ int, _ []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"trust me"}]}`, nil
		},
	}
	var usage llm.Usage
	_, dispositions, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", t.TempDir(), "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("ClassifyFindingsWithAudit() error = %v, want a complete triage", err)
	}
	if got := dispositions[0]; got.Disposition != "Needs Manual Review" || got.DispositionSource != dispositionSourceNRFallback {
		t.Fatalf("disposition = %+v, want nr-fallback Needs Manual Review", got)
	}
	if !auditMentions(audit, "false positive has no evidence") {
		t.Fatalf("audit = %+v, want recorded rejection", audit)
	}
}

func TestClassifyFindingsAcceptsValidatedTestOnlyFalsePositive(t *testing.T) {
	pinConcurrency(t)
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "tests", "a_test.py"), []byte("\n\n\n\n\n\nassert True\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := []EnrichedFinding{{ID: "B101", VulnID: "CS-MISC-001", Severity: "LOW", File: "tests/a_test.py", Line: 7, Message: "assert"}}
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(_ int, _ []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"test assertion","evidence":{"basis":"test_only","file":"tests/a_test.py","line":7}}]}`, nil
		},
	}
	var usage llm.Usage
	_, dispositions, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("ClassifyFindingsWithAudit() error = %v", err)
	}
	if got := dispositions[0].Disposition; got != "False Positive" {
		t.Fatalf("disposition = %q, want False Positive", got)
	}
	if dispositions[0].Evidence == nil || dispositions[0].Evidence.Basis != "test_only" {
		t.Fatalf("evidence = %+v, want test_only", dispositions[0].Evidence)
	}
	if len(audit) != 1 || len(audit[0].AcceptedFindingIndices) != 1 {
		t.Fatalf("audit = %+v, want one accepted finding", audit)
	}
}

// The mitigation is a guard on another line above the HIGH finding, in the
// same function: a check that exits early when the token does not verify.
func TestClassifyFindingsAcceptsValidatedCodeMitigationFalsePositive(t *testing.T) {
	pinConcurrency(t)
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "auth.py"), []byte("def handler(request):\n    if not verify_token(request):\n        abort(401)\n    return load_profile(request)\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	findings := []EnrichedFinding{{ID: "R-1", VulnID: "CS-AUTH-001", Severity: "HIGH", File: "auth.py", Line: 4, Message: "missing auth"}}
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(_ int, _ []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"guard exists","evidence":{"basis":"code_mitigation","file":"auth.py","line":2,"observed":"verify_token(request)"}}]}`, nil
		},
	}
	var usage llm.Usage
	_, dispositions, _, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("ClassifyFindingsWithAudit() error = %v", err)
	}
	if got := dispositions[0].Disposition; got != "False Positive" {
		t.Fatalf("disposition = %q, want False Positive", got)
	}
}

func TestCodeMitigationAcceptsAbsoluteInProjectEvidence(t *testing.T) {
	pinConcurrency(t)
	project := t.TempDir()
	path := filepath.Join(project, "files.py")
	if err := os.WriteFile(path, []byte("def read(name):\n    name = os.path.basename(name)\n    return open(name).read()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := []EnrichedFinding{{ID: "R-1", VulnID: "CS-MISC-001", Severity: "MEDIUM", File: path, Line: 3, Message: "path from input"}}
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(_ int, _ []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"directory parts are stripped","evidence":{"basis":"code_mitigation","file":` + strconv.Quote(path) + `,"line":2,"observed":"os.path.basename(name)"}}]}`, nil
		},
	}
	var usage llm.Usage
	_, dispositions, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatal(err)
	}
	if dispositions[0].Disposition != "False Positive" || dispositions[0].DispositionSource != dispositionSourceLLM {
		t.Fatalf("disposition = %+v, want source-backed LLM False Positive", dispositions[0])
	}
	if len(audit) != 1 || len(audit[0].Rejected) != 0 {
		t.Fatalf("audit = %+v, want first-attempt acceptance", audit)
	}
}

// A possible hardcoded password is never dismissed by code_mitigation, even
// when the model is right that the value is only an environment variable
// name: the verdict is kept for a person, recorded as a downgrade.
func TestCodeMitigationKeepsHardcodedSecretForReview(t *testing.T) {
	pinConcurrency(t)
	project := t.TempDir()
	path := filepath.Join(project, "security_controls.py")
	if err := os.WriteFile(path, []byte("TOKEN_ENV = \"API_TOKENS_JSON\"\nraw = os.environ.get(TOKEN_ENV)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := []EnrichedFinding{{ID: "B105", VulnID: "CS-SECRETS-001", Type: "external", Source: "bandit", Severity: "LOW", File: path, Line: 1, Message: "possible hardcoded password"}}
	mock := &fakeLLM{
		t: t,
		classifyHandler: func(_ int, _ []EnrichedFinding) (string, error) {
			return `{"finding_dispositions":[{"finding_index":0,"disposition":"False Positive","confidence":"high","rationale":"environment variable name only","evidence":{"basis":"code_mitigation","file":` + strconv.Quote(path) + `,"line":2,"observed":"os.environ.get(TOKEN_ENV)"}}]}`, nil
		},
	}
	var usage llm.Usage
	_, dispositions, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", project, "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatal(err)
	}
	d := dispositions[0]
	if d.Disposition != "Needs Manual Review" || d.DispositionSource != dispositionSourceLLM || !strings.Contains(d.Rationale, "environment variable name only") {
		t.Fatalf("disposition = %+v, want the dismissal kept for manual review with the model's rationale", d)
	}
	if len(audit) != 1 || len(audit[0].Downgraded) != 1 || !strings.Contains(audit[0].Downgraded[0].Reason, "hardcoded secret") {
		t.Fatalf("audit = %+v, want one downgrade naming the hardcoded secret", audit)
	}
}

func TestCodeMitigationRejectsAbsoluteOutsideProjectEvidence(t *testing.T) {
	project, outside := t.TempDir(), t.TempDir()
	projectPath := filepath.Join(project, "app.py")
	outsidePath := filepath.Join(outside, "app.py")
	if err := os.WriteFile(projectPath, []byte("unsafe()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsidePath, []byte("verify_token()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	finding := EnrichedFinding{ID: "R-1", VulnID: "CS-AUTH-001", File: projectPath, Line: 1}
	evidence := &DispositionEvidence{Basis: "code_mitigation", File: outsidePath, Line: 1, Observed: "verify_token()"}
	if err := validateFalsePositiveEvidence(project, finding, evidence); err == nil || !strings.Contains(err.Error(), "escapes project root") {
		t.Fatalf("outside evidence error = %v, want project-root rejection", err)
	}
}

func TestCodeMitigationRejectsSymlinkEscape(t *testing.T) {
	project, outside := t.TempDir(), t.TempDir()
	outsidePath := filepath.Join(outside, "guard.py")
	if err := os.WriteFile(outsidePath, []byte("verify_token()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "guard.py")
	if err := os.Symlink(outsidePath, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	finding := EnrichedFinding{ID: "R-1", VulnID: "CS-AUTH-001", File: link, Line: 1}
	evidence := &DispositionEvidence{Basis: "code_mitigation", File: link, Line: 1, Observed: "verify_token()"}
	if err := validateFalsePositiveEvidence(project, finding, evidence); err == nil || !strings.Contains(err.Error(), "escapes project root") {
		t.Fatalf("symlink evidence error = %v, want project-root rejection", err)
	}
}

func TestClassifyFindingsAuditPreservesRawResponseAndGlobalMapping(t *testing.T) {
	pinConcurrency(t)
	findings := makeFindings(218)
	mock := &fakeLLM{t: t}
	var usage llm.Usage
	_, dispositions, audit, _, err := ClassifyFindingsWithAudit(context.Background(), "", t.TempDir(), "", findings, mock, &usage, 150)
	if err != nil {
		t.Fatalf("ClassifyFindingsWithAudit() error = %v", err)
	}
	if len(dispositions) != 218 || len(audit) == 0 {
		t.Fatalf("got %d dispositions and %d audit entries, want 218 and non-empty audit", len(dispositions), len(audit))
	}
	for _, entry := range audit {
		if entry.RawResponse == "" || len(entry.UniqueFindingIndices) != len(entry.FindingIDs) || len(entry.FindingIDs) != len(entry.Fingerprints) {
			t.Fatalf("invalid audit entry: %+v", entry)
		}
	}
}
