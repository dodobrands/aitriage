package orchestrator

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
)

// composeSecrets is a Compose file with a default credential on line 5 and a
// value that may be a live secret on line 7.
const composeSecrets = `services:
  catalog-db:
    environment:
      MARIADB_USER: catalog
      MARIADB_PASSWORD: catalog
      MARIADB_DATABASE: catalog
      MARIADB_ROOT_PASSWORD: 8f2Kq9vLx3TzR7mW4pYc
`

func composeIssues(result llm.RichScanResult) []string {
	var issues []string
	for _, f := range result.Deploy {
		issues = append(issues, f.Issue)
	}
	return issues
}

// Default credentials used to be reported as compose_hardcoded_secret. An
// ignore.rules entry or an inline directive written for that id keeps covering
// them; the new id silences default credentials alone.
func TestPreviousComposeIssueStillSilencesDefaultCredentials(t *testing.T) {
	deploy := func(root string) llm.RichScanResult {
		file := filepath.Join(root, "docker-compose.yml")
		return llm.RichScanResult{ProjectPath: root, Deploy: []deployaudit.DeployFinding{
			{File: file, Line: 5, Issue: deployaudit.IssueComposeDefaultCredential, Severity: "MEDIUM", Evidence: "MARIADB_PASSWORD: catalog"},
			{File: file, Line: 7, Issue: deployaudit.IssueComposeHardcodedSecret, Severity: "CRITICAL", Evidence: "MARIADB_ROOT_PASSWORD: 8f2Kq9vLx3TzR7mW4pY"},
		}}
	}

	t.Run("ignore.rules with the previous id", func(t *testing.T) {
		root := writeFixture(t, map[string]string{
			".aitriage.yaml":     "ignore:\n  rules:\n    - compose_hardcoded_secret\n",
			"docker-compose.yml": composeSecrets,
		})
		result := deploy(root)
		applyProjectSuppressions(&result)
		if len(result.Deploy) != 0 {
			t.Errorf("deploy = %v; the previous id silences both", composeIssues(result))
		}
		if want := map[string]int{"compose_hardcoded_secret": 2}; !reflect.DeepEqual(result.IgnoredByConfig, want) {
			t.Errorf("ignored by config = %v; want %v", result.IgnoredByConfig, want)
		}
	})

	t.Run("ignore.rules with the new id", func(t *testing.T) {
		root := writeFixture(t, map[string]string{
			".aitriage.yaml":     "ignore:\n  rules:\n    - deploy:compose_default_credential\n",
			"docker-compose.yml": composeSecrets,
		})
		result := deploy(root)
		applyProjectSuppressions(&result)
		if got := composeIssues(result); !reflect.DeepEqual(got, []string{deployaudit.IssueComposeHardcodedSecret}) {
			t.Errorf("deploy = %v; the new id silences default credentials alone", got)
		}
	})

	t.Run("inline directive with the previous id", func(t *testing.T) {
		root := writeFixture(t, map[string]string{"docker-compose.yml": `services:
  catalog-db:
    environment:
      MARIADB_USER: catalog
      MARIADB_PASSWORD: catalog  # aitriage-ignore: compose_hardcoded_secret (local stack)
      MARIADB_DATABASE: catalog
      MARIADB_ROOT_PASSWORD: 8f2Kq9vLx3TzR7mW4pYc
`})
		result := deploy(root)
		applyProjectSuppressions(&result)
		if got := composeIssues(result); !reflect.DeepEqual(got, []string{deployaudit.IssueComposeHardcodedSecret}) {
			t.Errorf("deploy = %v; want the directive to cover the default credential on its line", got)
		}
		if want := map[string]int{"deploy:compose_default_credential": 1}; !reflect.DeepEqual(result.SuppressedInline, want) {
			t.Errorf("suppressed inline = %v; want %v", result.SuppressedInline, want)
		}
	})
}

// Through the scan path: a default credential counts at MEDIUM in the score,
// under the hardcoded-secret class, next to a CRITICAL hardcoded secret.
func TestComposeDefaultCredentialIsScoredAtItsSeverity(t *testing.T) {
	root := writeFixture(t, map[string]string{"docker-compose.yml": composeSecrets})

	result := RunAllScanners(context.Background(), Options{ProjectPath: root})

	severities := map[string]string{}
	for _, f := range result.Deploy {
		severities[f.Issue] = f.Severity
	}
	if want := map[string]string{deployaudit.IssueComposeDefaultCredential: "MEDIUM", deployaudit.IssueComposeHardcodedSecret: "CRITICAL"}; !reflect.DeepEqual(severities, want) {
		t.Fatalf("deploy findings = %v; want %v", severities, want)
	}
	bd := result.Report.HealthCheck.Breakdown
	if bd.CountByClass["hardcoded_secret"] != 2 || bd.CountByRule[deployaudit.IssueComposeDefaultCredential] != 1 {
		t.Errorf("counts by class = %v, by rule = %v; want both under hardcoded_secret", bd.CountByClass, bd.CountByRule)
	}
	if bd.CountBySeverity["MEDIUM"] != 1 || bd.CountBySeverity["CRITICAL"] != 1 {
		t.Errorf("counts by severity = %v; want the default credential at MEDIUM", bd.CountBySeverity)
	}
}
