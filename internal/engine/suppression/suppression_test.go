package suppression

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
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

func TestOlderDismissalStillMatchesAfterCheckoutMoves(t *testing.T) {
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	old := item("trivy", "CVE-1", filepath.Join(oldRoot, "composer.lock"), "pkg 1.0")
	store := New()
	if _, _, err := store.Add(old, ReasonFalsePositive, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := Save(oldRoot, store); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	current := item("trivy", "CVE-1", "composer.lock", "pkg 1.0")
	if _, ok := reloaded.SuppressesInProject(oldRoot, current); !ok {
		t.Error("dismissal stopped matching in its original checkout")
	}
	if _, ok := reloaded.SuppressesInProject(newRoot, current); !ok {
		t.Error("dismissal stopped matching after checkout moved")
	}
	current.Evidence = "pkg 2.0"
	if _, ok := reloaded.SuppressesInProject(newRoot, current); ok {
		t.Error("dismissal hid changed evidence")
	}
}

// recordLikeTheCLI adds a dismissal the way `aitriage ignore add` builds it:
// the file relative to the project, the line not part of the identity, and
// the evidence only when --evidence was given.
func recordLikeTheCLI(t *testing.T, store *Store, project, source, ruleID, file, evidence, reason, note string) Entry {
	t.Helper()
	entry, _, err := store.Add(baseline.Item{
		Source:   source,
		RuleID:   ruleID,
		File:     baseline.RelativePath(project, file),
		Evidence: evidence,
	}, reason, note, "reviewer")
	if err != nil {
		t.Fatalf("add %s: %v", ruleID, err)
	}
	return entry
}

// scannedCore and scannedExternal map findings the way
// orchestrator.ApplySuppressions does before asking the store.
func scannedCore(root string, r core.CheckResult) baseline.Item {
	return baseline.Relativize(root, baseline.FromCore([]core.CheckResult{r}))[0]
}

func scannedExternal(root string, f external.UnifiedFinding) baseline.Item {
	return baseline.Relativize(root, baseline.FromExternal([]external.UnifiedFinding{f}))[0]
}

// `aitriage ignore add RULE --file F` without --evidence says it covers any
// finding of RULE in F. A scanned finding always carries its evidence, so an
// entry matched only by its exact fingerprint covered nothing at all.
func TestDismissalWithoutEvidenceCoversTheRuleInItsFile(t *testing.T) {
	project := t.TempDir()
	store := New()
	recordLikeTheCLI(t, store, project, "core", "SECRET-ASSIGN", "core/fns.py", "", "false-positive", "")

	finding := core.CheckResult{ID: "SECRET-ASSIGN", Status: core.Absent, Severity: "CRITICAL",
		File: filepath.Join(project, "core", "fns.py"), Line: 3, Evidence: "CLIENT_SECRET = '...'"}
	if _, ok := store.SuppressesInProject(project, scannedCore(project, finding)); !ok {
		t.Fatal("a dismissal recorded without evidence did not cover the finding it names")
	}

	elsewhereInFile := finding
	elsewhereInFile.Line, elsewhereInFile.Evidence = 40, "API_SECRET = '...'"
	if _, ok := store.SuppressesInProject(project, scannedCore(project, elsewhereInFile)); !ok {
		t.Error("the dismissal did not cover another finding of the rule in the same file")
	}

	otherFile := finding
	otherFile.File = filepath.Join(project, "core", "settings.py")
	if _, ok := store.SuppressesInProject(project, scannedCore(project, otherFile)); ok {
		t.Error("a dismissal scoped to one file hid the rule in another file")
	}

	otherRule := finding
	otherRule.ID = "PY-EVAL"
	if _, ok := store.SuppressesInProject(project, scannedCore(project, otherRule)); ok {
		t.Error("a dismissal for one rule hid a different rule")
	}

	otherScanner := external.UnifiedFinding{Source: "semgrep", RuleID: "SECRET-ASSIGN", File: finding.File, Message: "secret"}
	if _, ok := store.SuppressesInProject(project, scannedExternal(project, otherScanner)); ok {
		t.Error("a dismissal for the built-in engine hid another scanner's finding")
	}
}

// Without --file as well, the help example `ignore add CVE-2026-1 --source
// trivy --reason accepted-risk` means the CVE wherever it is reported.
func TestDismissalWithoutFileOrEvidenceCoversTheRuleEverywhere(t *testing.T) {
	project := t.TempDir()
	store := New()
	recordLikeTheCLI(t, store, project, "trivy", "CVE-2026-1", "", "", "accepted-risk", "mitigated at the gateway")

	for _, file := range []string{"requirements.txt", filepath.Join(project, "services", "api", "requirements.txt")} {
		cve := external.UnifiedFinding{Source: "trivy", RuleID: "CVE-2026-1", Severity: "HIGH", File: file, Message: "pillow: arbitrary code execution"}
		entry, ok := store.SuppressesInProject(project, scannedExternal(project, cve))
		if !ok {
			t.Fatalf("a project-wide dismissal did not cover the CVE in %s", file)
		}
		if entry.Reason != ReasonAcceptedRisk || entry.Note != "mitigated at the gateway" {
			t.Errorf("matched entry = %+v, want the recorded decision", entry)
		}
	}

	otherCVE := external.UnifiedFinding{Source: "trivy", RuleID: "CVE-2026-2", File: "requirements.txt", Message: "pillow"}
	if _, ok := store.SuppressesInProject(project, scannedExternal(project, otherCVE)); ok {
		t.Error("a dismissal for one CVE hid another")
	}
	sameIDOtherScanner := external.UnifiedFinding{Source: "semgrep", RuleID: "CVE-2026-1", File: "requirements.txt", Message: "pillow"}
	if _, ok := store.SuppressesInProject(project, scannedExternal(project, sameIDOtherScanner)); ok {
		t.Error("a dismissal for one scanner hid another scanner's finding with the same id")
	}
}

// A dismissal that names the matched text, as the Web UI records it, still
// covers exactly that finding and nothing broader.
func TestDismissalWithEvidenceStaysExact(t *testing.T) {
	project := t.TempDir()
	store := New()
	if _, _, err := store.Add(baseline.Item{Source: "semgrep", RuleID: "sqli", File: "a.php", Line: 4, Evidence: "$_GET['id']"}, "false-positive", "", "web"); err != nil {
		t.Fatal(err)
	}

	same := external.UnifiedFinding{Source: "semgrep", RuleID: "sqli", File: filepath.Join(project, "a.php"), Line: 9, Message: "$_GET['id']"}
	if _, ok := store.SuppressesInProject(project, scannedExternal(project, same)); !ok {
		t.Fatal("an exact dismissal stopped matching its own finding")
	}
	changed := same
	changed.Message = "$_POST['name']"
	if _, ok := store.SuppressesInProject(project, scannedExternal(project, changed)); ok {
		t.Error("an exact dismissal hid a different finding of the same rule in the same file")
	}

	// With evidence but no file the match stays exact, file included: it
	// covers findings reported without a file, such as an NFR check.
	recordLikeTheCLI(t, store, project, "nfr", "NFR-API-001", "", "No rate limiting", "wont-fix", "")
	nfrFinding := baseline.Relativize(project, baseline.FromNFR([]nfr.NFRFinding{{RuleID: "NFR-API-001", Message: "No rate limiting"}}))[0]
	if _, ok := store.SuppressesInProject(project, nfrFinding); !ok {
		t.Error("an exact project-level dismissal did not cover its finding")
	}
	recordLikeTheCLI(t, store, project, "trivy", "CVE-2026-3", "", "pillow 9.0", "false-positive", "")
	inAFile := external.UnifiedFinding{Source: "trivy", RuleID: "CVE-2026-3", File: "requirements.txt", Message: "pillow 9.0"}
	if _, ok := store.SuppressesInProject(project, scannedExternal(project, inAFile)); ok {
		t.Error("a dismissal recorded with evidence but no file widened to findings in a file")
	}
}

// Entries written before paths were made relative stored absolute paths. One
// recorded without evidence keeps covering its file in the original checkout
// and after the checkout moves.
func TestOlderDismissalWithoutEvidenceStillMatches(t *testing.T) {
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	store := New()
	if _, _, err := store.Add(baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: filepath.Join(oldRoot, "core", "fns.py")}, "false-positive", "", ""); err != nil {
		t.Fatal(err)
	}

	current := baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: "core/fns.py", Evidence: "CLIENT_SECRET = '...'"}
	if _, ok := store.SuppressesInProject(oldRoot, current); !ok {
		t.Error("an older dismissal without evidence stopped matching in its original checkout")
	}
	if _, ok := store.SuppressesInProject(newRoot, current); !ok {
		t.Error("an older dismissal without evidence stopped matching after the checkout moved")
	}
	current.File = "core/settings.py"
	if _, ok := store.SuppressesInProject(newRoot, current); ok {
		t.Error("an older dismissal for one file hid the rule in another file")
	}
}

// An older entry names one file by its absolute path. It was matched by the
// tail of that path, so one recorded without evidence, which covers every
// finding of its rule in its file, covered every file of that name in the
// project, and every file sharing a shorter tail of its path.
func TestOlderDismissalCoversOnlyTheFileItWasRecordedFor(t *testing.T) {
	project := t.TempDir()
	for _, file := range []string{"app/config.php", "config.php", "services/api/app/config.php"} {
		path := filepath.Join(project, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The absolute path an older entry recorded for a file of the project, in
	// this checkout and in one that has since moved.
	for name, recordedPath := range map[string]func(rel string) string{
		"same checkout": func(rel string) string { return filepath.Join(project, filepath.FromSlash(rel)) },
		"moved":         func(rel string) string { return "/home/alice/shop/" + rel },
	} {
		for _, tc := range []struct {
			recorded string   // the file the entry was recorded for
			covers   string   // the finding it covers
			spares   []string // findings of the same rule it must not cover
		}{
			{"app/config.php", "app/config.php", []string{"config.php"}},
			{"services/api/app/config.php", "services/api/app/config.php", []string{"app/config.php", "config.php"}},
		} {
			store := New()
			recorded := recordedPath(tc.recorded)
			if _, _, err := store.Add(baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: recorded}, ReasonFalsePositive, "", ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Add(baseline.Item{Source: "trivy", RuleID: "CVE-2026-1", File: recorded, Evidence: "pkg 1.0"}, ReasonFalsePositive, "", ""); err != nil {
				t.Fatal(err)
			}
			ruleWide := func(file string) baseline.Item {
				return baseline.Item{Source: "core", RuleID: "SECRET-ASSIGN", File: file, Evidence: "SECRET = '...'"}
			}
			exact := func(file string) baseline.Item {
				return baseline.Item{Source: "trivy", RuleID: "CVE-2026-1", File: file, Evidence: "pkg 1.0"}
			}

			if _, ok := store.SuppressesInProject(project, ruleWide(tc.covers)); !ok {
				t.Errorf("%s: the dismissal without evidence for %s stopped covering it", name, tc.recorded)
			}
			if _, ok := store.SuppressesInProject(project, exact(tc.covers)); !ok {
				t.Errorf("%s: the dismissal with evidence for %s stopped covering it", name, tc.recorded)
			}
			for _, other := range tc.spares {
				if _, ok := store.SuppressesInProject(project, ruleWide(other)); ok {
					t.Errorf("%s: the dismissal without evidence for %s covered %s", name, tc.recorded, other)
				}
				if _, ok := store.SuppressesInProject(project, exact(other)); ok {
					t.Errorf("%s: the dismissal with evidence for %s covered %s", name, tc.recorded, other)
				}
			}
		}
	}
}
