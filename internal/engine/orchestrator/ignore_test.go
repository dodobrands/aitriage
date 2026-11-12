package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	external.ResetScopeFilterCache()
	t.Cleanup(external.ResetScopeFilterCache)
	return root
}

// ignore.rules used to silence only the built-in engine's YAML rules. Each id
// below was listed in a project's configuration and still reported.
func TestIgnoreRulesApplyToEverySource(t *testing.T) {
	root := writeFixture(t, map[string]string{".aitriage.yaml": `
ignore:
  rules:
    - ENTR-SLOP-01
    - SECRET-LEAK-LOG
    - B105
    - gitleaks:generic-api-key
    - trivy:CVE-2024-1234
    - semgrep:python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
    - NFR-API-001
    - nginx_missing_server_tokens_off
    - port-53
`})

	result := llm.RichScanResult{
		ProjectPath: root,
		Report: scanner.ScanReport{Results: []core.CheckResult{
			{ID: "ENTR-SLOP-01", Status: core.Absent, File: filepath.Join(root, "web/forms.tsx")},
			{ID: "SECRET-LEAK-LOG", Status: core.Absent, File: filepath.Join(root, "core/fns.py"), Line: 3},
			{ID: "FAST-SUBPROCESS", Status: core.Absent, File: filepath.Join(root, "main.py"), Line: 11},
		}},
		External: []external.UnifiedFinding{
			{Source: "bandit", RuleID: "B105", File: filepath.Join(root, "core/fns.py"), Line: 3},
			{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, "core/fns.py"), Line: 3},
			// Same id from another scanner: the qualifier names gitleaks only.
			{Source: "semgrep", RuleID: "generic-api-key", File: filepath.Join(root, "core/fns.py"), Line: 3},
			{Source: "trivy", RuleID: "CVE-2024-1234", File: "requirements.txt"},
			{Source: "trivy", RuleID: "CVE-2024-9999", File: "requirements.txt"},
			{Source: "semgrep", RuleID: "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", File: filepath.Join(root, "main.py"), Line: 11},
		},
		NFR: []nfr.NFRFinding{{RuleID: "NFR-API-001"}, {RuleID: "NFR-API-003"}},
		Deploy: []deployaudit.DeployFinding{
			{Issue: "nginx_missing_server_tokens_off", File: filepath.Join(root, "nginx.conf"), Line: 1},
			{Issue: "nginx_missing_csp", File: filepath.Join(root, "nginx.conf"), Line: 1},
		},
		Network: []network.NetworkFinding{{Target: "app", Port: 53}, {Target: "db", Port: 5432}},
	}

	applyProjectSuppressions(&result)

	if got := coreIDs(result); !reflect.DeepEqual(got, []string{"FAST-SUBPROCESS"}) {
		t.Errorf("core = %v; want only FAST-SUBPROCESS", got)
	}
	var externalIDs []string
	for _, f := range result.External {
		externalIDs = append(externalIDs, f.Source+":"+f.RuleID)
	}
	if want := []string{"semgrep:generic-api-key", "trivy:CVE-2024-9999"}; !reflect.DeepEqual(externalIDs, want) {
		t.Errorf("external = %v; want %v", externalIDs, want)
	}
	if len(result.NFR) != 1 || result.NFR[0].RuleID != "NFR-API-003" {
		t.Errorf("nfr = %+v; want only NFR-API-003", result.NFR)
	}
	if len(result.Deploy) != 1 || result.Deploy[0].Issue != "nginx_missing_csp" {
		t.Errorf("deploy = %+v; want only nginx_missing_csp", result.Deploy)
	}
	if len(result.Network) != 1 || result.Network[0].Port != 5432 {
		t.Errorf("network = %+v; want only port 5432", result.Network)
	}

	want := map[string]int{
		"ENTR-SLOP-01": 1, "SECRET-LEAK-LOG": 1, "B105": 1, "gitleaks:generic-api-key": 1,
		"trivy:CVE-2024-1234": 1, "NFR-API-001": 1, "nginx_missing_server_tokens_off": 1, "port-53": 1,
		"semgrep:python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": 1,
	}
	if !reflect.DeepEqual(result.IgnoredByConfig, want) {
		t.Errorf("ignored by config = %v; want %v", result.IgnoredByConfig, want)
	}
}

// Inline directives used to work only for the built-in engine, so a reviewed
// "# aitriage-ignore: B105" still produced the Bandit finding it was written
// for.
func TestInlineDirectivesSilenceExternalAndDeployFindings(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"core/fns.py": "import os\n\nCLIENT_SECRET = 'abc'  # aitriage-ignore: B105 (allowed in tests)\n",
		"Dockerfile":  "FROM python:3.12\n# aitriage-ignore-next-line: dockerfile_root_user\nUSER root\nADD https://example.com/app.py /app/\n",
		"vendored.py": "# aitriage-ignore-file: B101\nassert x\n",
	})

	result := llm.RichScanResult{
		ProjectPath: root,
		NFR:         []nfr.NFRFinding{},
		External: []external.UnifiedFinding{
			{Source: "bandit", RuleID: "B105", File: filepath.Join(root, "core/fns.py"), Line: 3},
			{Source: "bandit", RuleID: "B105", File: "core/fns.py", Line: 3}, // root-relative path
			{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, "core/fns.py"), Line: 3},
			{Source: "semgrep", RuleID: "hardcoded-secret", File: filepath.Join(root, "core/fns.py"), Line: 3},
			{Source: "bandit", RuleID: "B101", File: filepath.Join(root, "vendored.py"), Line: 2},
			{Source: "bandit", RuleID: "B105", File: filepath.Join(root, "missing.py"), Line: 1},
		},
		Deploy: []deployaudit.DeployFinding{
			{Issue: "dockerfile_root_user", File: filepath.Join(root, "Dockerfile"), Line: 3},
			{Issue: "dockerfile_add_instead_of_copy", File: filepath.Join(root, "Dockerfile"), Line: 4},
		},
	}

	applyProjectSuppressions(&result)

	var kept []string
	for _, f := range result.External {
		kept = append(kept, f.Source+":"+f.RuleID+"@"+filepath.Base(f.File))
	}
	want := []string{"gitleaks:generic-api-key@fns.py", "semgrep:hardcoded-secret@fns.py", "bandit:B105@missing.py"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("external kept = %v; want %v", kept, want)
	}
	if len(result.Deploy) != 1 || result.Deploy[0].Issue != "dockerfile_add_instead_of_copy" {
		t.Errorf("deploy kept = %+v; want only the ADD finding", result.Deploy)
	}
	wantInline := map[string]int{"bandit:B105": 2, "bandit:B101": 1, "deploy:dockerfile_root_user": 1}
	if !reflect.DeepEqual(result.SuppressedInline, wantInline) {
		t.Errorf("suppressed inline = %v; want %v", result.SuppressedInline, wantInline)
	}
	if result.IgnoredByConfig != nil {
		t.Errorf("ignored by config = %v; nothing was configured", result.IgnoredByConfig)
	}
}

func TestProjectSuppressionsKeepEmptyCollectionsDistinctFromMissing(t *testing.T) {
	result := llm.RichScanResult{ProjectPath: t.TempDir(), NFR: []nfr.NFRFinding{}}

	applyProjectSuppressions(&result)

	if result.NFR == nil {
		t.Error("an empty NFR result must stay non-nil: nil means the scanner did not run")
	}
	if result.IgnoredByConfig != nil || result.SuppressedInline != nil {
		t.Error("nothing was suppressed, so nothing may be recorded")
	}
}

// End to end through the orchestrator: an ignored heuristic, NFR check and
// deploy issue leave the reported set, the counts say so, and the score no
// longer pays for them.
func TestRunAllScannersAppliesIgnoreRulesBeforeScoring(t *testing.T) {
	root := writeFixture(t, map[string]string{
		".aitriage.yaml": `
ignore:
  rules:
    - SECRET-AWS-AKID
    - NFR-API-001
    - deploy:dockerfile_root_user
`,
		"app/settings.py": "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
		"main.py":         "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/items')\ndef items():\n    return []\n",
		"Dockerfile":      "FROM python:3.12\nUSER root\nADD https://example.com/app.py /app/\n",
	})

	result := RunAllScanners(context.Background(), Options{ProjectPath: root})

	for _, r := range result.Report.Results {
		if r.ID == "SECRET-AWS-AKID" {
			t.Errorf("ignored heuristic still reported: %+v", r)
		}
	}
	nfrIDs := map[string]bool{}
	for _, f := range result.NFR {
		nfrIDs[f.RuleID] = true
	}
	if nfrIDs["NFR-API-001"] || !nfrIDs["NFR-API-003"] {
		t.Errorf("nfr = %v; want NFR-API-003 without NFR-API-001", nfrIDs)
	}
	deployIDs := map[string]bool{}
	for _, f := range result.Deploy {
		deployIDs[f.Issue] = true
	}
	if deployIDs["dockerfile_root_user"] || !deployIDs["dockerfile_add_instead_of_copy"] {
		t.Errorf("deploy = %v; want the ADD finding without the ignored root-user one", deployIDs)
	}

	want := map[string]int{"SECRET-AWS-AKID": 1, "NFR-API-001": 1, "deploy:dockerfile_root_user": 1}
	if !reflect.DeepEqual(result.IgnoredByConfig, want) {
		t.Errorf("ignored by config = %v; want %v", result.IgnoredByConfig, want)
	}
	if result.Report.IgnoredByConfig["SECRET-AWS-AKID"] != 1 {
		t.Errorf("core report counts = %v; the engine scan must record its own", result.Report.IgnoredByConfig)
	}

	classes := result.Report.HealthCheck.Breakdown.CountByClass
	for _, id := range []string{"SECRET-AWS-AKID", "NFR-API-001", "dockerfile_root_user"} {
		if classes[id] != 0 {
			t.Errorf("health check still counts ignored %s: %v", id, classes)
		}
	}
}

func coreIDs(result llm.RichScanResult) []string {
	var ids []string
	for _, r := range result.Report.Results {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}
