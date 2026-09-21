package suppression

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
)

// Dismissing a finding used to mean three different things: the Web UI wrote to
// its own database, the MCP tool proxied to an external IDE service, and the CLI
// could not do it at all. A decision only one surface can see is not a decision.

func item(source, ruleID, file, evidence string) baseline.Item {
	return baseline.Item{Source: source, RuleID: ruleID, File: file, Evidence: evidence}
}

func TestADismissalIsVisibleToEverySurface(t *testing.T) {
	dir := t.TempDir()
	finding := item("trivy", "CVE-2026-1", "composer.lock", "guzzle 7.8.1")

	// One surface records the decision.
	store, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, _, err := store.Add(finding, "false-positive", "not reachable from our code", "cli"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := Save(dir, store); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Another surface reads the same project and sees it.
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	entry, ok := reloaded.Suppresses(finding)
	if !ok {
		t.Fatal("a dismissal recorded by one surface was invisible to another")
	}
	if entry.Reason != ReasonFalsePositive {
		t.Errorf("reason = %q; want %q", entry.Reason, ReasonFalsePositive)
	}
	if entry.Note != "not reachable from our code" {
		t.Errorf("the justification was lost: %q", entry.Note)
	}
}

func TestAnAcceptedRiskNeedsAJustification(t *testing.T) {
	store := New()

	if _, _, err := store.Add(item("core", "X", "a.go", "e"), "accepted-risk", "", ""); err == nil {
		t.Error("an accepted risk was recorded with no justification; a reviewer cannot act on that")
	}

	if _, _, err := store.Add(item("core", "X", "a.go", "e"), "accepted-risk", "mitigated at the gateway", ""); err != nil {
		t.Errorf("a justified accepted risk was refused: %v", err)
	}
}

func TestAFalsePositiveNeedsNoJustification(t *testing.T) {
	store := New()

	// "We looked and it is wrong" is self-explanatory; requiring prose here
	// would only teach people to type filler.
	if _, _, err := store.Add(item("core", "X", "a.go", "e"), "false-positive", "", ""); err != nil {
		t.Errorf("a plain false positive was refused: %v", err)
	}
}

func TestReasonWordingsFromEverySurfaceAgree(t *testing.T) {
	for _, spelling := range []string{"False Positive", "false_positive", "FP", "falsepositive", ""} {
		if got, err := NormalizeReason(spelling); err != nil || got != ReasonFalsePositive {
			t.Errorf("NormalizeReason(%q) = %q, %v", spelling, got, err)
		}
	}
	for _, spelling := range []string{"Accepted Risk", "risk_accepted", "accepted"} {
		if got, err := NormalizeReason(spelling); err != nil || got != ReasonAcceptedRisk {
			t.Errorf("NormalizeReason(%q) = %q, %v", spelling, got, err)
		}
	}
	if _, err := NormalizeReason("because I said so"); err == nil {
		t.Error("an arbitrary reason was accepted; the stored set must stay closed")
	}
}

func TestDismissingOneScannerDoesNotHideAnother(t *testing.T) {
	store := New()
	semgrep := item("semgrep", "sqli", "a.php", "$_GET")
	bandit := item("bandit", "sqli", "a.php", "$_GET")

	if _, _, err := store.Add(semgrep, "false-positive", "", ""); err != nil {
		t.Fatalf("add: %v", err)
	}

	if _, ok := store.Suppresses(bandit); ok {
		t.Error("dismissing one scanner's finding also hid another scanner's")
	}
}

func TestRemoveByRuleIDAndByFingerprint(t *testing.T) {
	store := New()
	entry, _, err := store.Add(item("trivy", "CVE-1", "go.sum", "e"), "wont-fix", "", "")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	if removed := store.Remove(entry.Fingerprint); removed != 1 {
		t.Errorf("remove by fingerprint removed %d", removed)
	}

	if _, _, err := store.Add(item("trivy", "CVE-2", "go.sum", "a"), "wont-fix", "", ""); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, _, err := store.Add(item("trivy", "CVE-2", "other.lock", "b"), "wont-fix", "", ""); err != nil {
		t.Fatalf("add: %v", err)
	}
	if removed := store.Remove("CVE-2"); removed != 2 {
		t.Errorf("remove by rule id removed %d; want both entries", removed)
	}
	if removed := store.Remove("nothing"); removed != 0 {
		t.Errorf("removing an unknown identifier removed %d", removed)
	}
}

func TestReDismissingKeepsTheOriginalDate(t *testing.T) {
	store := New()
	finding := item("core", "X", "a.go", "e")

	first, _, err := store.Add(finding, "false-positive", "first pass", "")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	second, replaced, err := store.Add(finding, "wont-fix", "changed our minds", "")
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if !replaced {
		t.Error("re-dismissing the same finding was not reported as a replacement")
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Error("the original date was lost; a suppression's age is what makes a stale one visible")
	}
	if second.Reason != ReasonWontFix {
		t.Errorf("reason = %q; want the updated one", second.Reason)
	}
}

func TestAMissingStoreIsEmptyNotAnError(t *testing.T) {
	store, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("a project without dismissals must load cleanly: %v", err)
	}
	if len(store.List()) != 0 {
		t.Error("an empty project reported dismissals")
	}
	if _, ok := store.Suppresses(item("core", "X", "a", "e")); ok {
		t.Error("an empty store suppressed a finding")
	}
}

func TestTheStoreIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has no POSIX permission bits: os.WriteFile reports 0666
		// whatever mode is requested. Access there is governed by ACLs, which
		// this assertion cannot express.
		t.Skip("POSIX permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	store := New()
	if _, _, err := store.Add(item("core", "X", "a", "e"), "false-positive", "", ""); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := Save(dir, store); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, File))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// It records security decisions, so it is not world-readable.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o; want 0600", perm)
	}
}

func TestCorruptStoreIsReportedRatherThanIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, File), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Silently treating an unreadable store as empty would resurrect every
	// dismissed finding with no explanation.
	if _, err := Load(dir); err == nil {
		t.Error("a corrupt store loaded as if it were empty")
	}
}
