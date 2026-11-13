package suppression

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
)

func composeFinding(issue, evidence string) baseline.Item {
	return baseline.FromDeploy([]deployaudit.DeployFinding{{
		File: "docker-compose.yml", Line: 7, Issue: issue, Evidence: evidence,
	}})[0]
}

// A dismissal recorded for compose_hardcoded_secret, before default
// credentials had an issue of their own, still covers them; a dismissal of
// the new issue covers nothing it did not name.
func TestDecisionsRecordedUnderAPreviousRuleIDStillApply(t *testing.T) {
	root := t.TempDir()
	split := composeFinding(deployaudit.IssueComposeDefaultCredential, "DB_PASSWORD: catalog")

	ruleWide := New()
	if _, _, err := ruleWide.Add(item("deploy", deployaudit.IssueComposeHardcodedSecret, "docker-compose.yml", ""), "accepted-risk", "local stack only", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := ruleWide.SuppressesInProject(root, split); !ok {
		t.Error("a file-wide dismissal under the previous id no longer covers the default credential")
	}

	exact := New()
	if _, _, err := exact.Add(item("deploy", deployaudit.IssueComposeHardcodedSecret, "docker-compose.yml", "DB_PASSWORD: catalog"), "false-positive", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := exact.SuppressesInProject(root, split); !ok {
		t.Error("an exact dismissal under the previous id no longer covers the default credential")
	}
	if _, ok := exact.SuppressesInProject(root, composeFinding(deployaudit.IssueComposeDefaultCredential, "DB_PASSWORD: ledger")); ok {
		t.Error("an exact dismissal covered another value")
	}

	newer := New()
	if _, _, err := newer.Add(item("deploy", deployaudit.IssueComposeDefaultCredential, "docker-compose.yml", ""), "accepted-risk", "local stack only", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := newer.SuppressesInProject(root, composeFinding(deployaudit.IssueComposeHardcodedSecret, "DB_PASSWORD: catalog")); ok {
		t.Error("a dismissal of default credentials covered a hardcoded secret")
	}
}
