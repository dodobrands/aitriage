package baseline

import (
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
)

// Default credentials in Compose files were reported as
// compose_hardcoded_secret until they got an issue of their own. A baseline
// written before the split recorded them under the old id; the upgrade must
// not resurface them as new findings.
func TestBaselineEntriesUnderAPreviousRuleIDStillAccept(t *testing.T) {
	root := t.TempDir()
	finding := deployaudit.DeployFinding{
		File: "docker-compose.yml", Line: 7, Severity: "MEDIUM",
		Issue:    deployaudit.IssueComposeDefaultCredential,
		Evidence: "DB_PASSWORD: catalog",
	}
	split := FromDeploy([]deployaudit.DeployFinding{finding})[0]
	if split.PreviousRuleID != deployaudit.IssueComposeHardcodedSecret {
		t.Fatalf("previous rule id = %q", split.PreviousRuleID)
	}

	accepted := Item{
		Source: "deploy", RuleID: deployaudit.IssueComposeHardcodedSecret,
		File: "docker-compose.yml", Evidence: "DB_PASSWORD: catalog", Severity: "CRITICAL",
	}
	old := NewFromItems([]Item{accepted})
	if !old.AcceptsInProject(root, split) || !old.Accepts(split) {
		t.Fatal("a default credential accepted under its previous id came back as a new finding")
	}

	// A baseline of the absolute-path format, written before paths were made
	// relative, keeps matching too.
	legacy := accepted
	legacy.File = filepath.Join(root, "docker-compose.yml")
	older := NewFromItems([]Item{legacy})
	older.Version = SchemaVersion2
	if !older.AcceptsInProject(root, split) {
		t.Fatal("a default credential accepted by an older baseline format came back")
	}

	// The previous id widens nothing else: another value is another finding,
	// and an entry for the new issue does not accept a hardcoded secret.
	other := split
	other.Evidence = "DB_PASSWORD: ledger"
	if old.AcceptsInProject(root, other) {
		t.Error("an entry for one value accepted another")
	}
	secret := FromDeploy([]deployaudit.DeployFinding{{
		File: "docker-compose.yml", Line: 7, Severity: "CRITICAL",
		Issue: deployaudit.IssueComposeHardcodedSecret, Evidence: "DB_PASSWORD: catalog",
	}})[0]
	if NewFromItems([]Item{split}).AcceptsInProject(root, secret) {
		t.Error("an entry for a default credential accepted a hardcoded secret")
	}
}
