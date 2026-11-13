package orchestrator

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// Trivy has reported one check as KSV012, AVD-KSV-0012 and KSV-0012 in
// different releases, and ignore.rules and inline directives compared ids as
// written: an entry stopped matching when the scanner was upgraded.
// Advisories and the ids of other sources still compare as written.
func TestTrivyCheckSpellingsMatchIgnoreRulesAndInlineDirectives(t *testing.T) {
	root := writeFixture(t, map[string]string{
		".aitriage.yaml": "ignore:\n  rules:\n    - trivy:DS002\n    - AVD-KSV-0017\n    - CVE-2024-0042\n",
		"k8s/pod.yaml": `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        runAsUser: 0  # aitriage-ignore: KSV-0012
`,
	})
	misconfiguration := func(id, file string, line int) external.UnifiedFinding {
		return external.UnifiedFinding{Source: "trivy", Kind: external.KindMisconfiguration, RuleID: id, File: file, Line: line}
	}
	result := llm.RichScanResult{
		ProjectPath: root,
		External: []external.UnifiedFinding{
			misconfiguration("DS-0002", "Dockerfile", 0),
			misconfiguration("AVD-DS-0002", "build/Dockerfile", 0),
			misconfiguration("KSV017", "k8s/pod.yaml", 5),
			misconfiguration("KSV012", "k8s/pod.yaml", 7),
			misconfiguration("KSV-0014", "k8s/pod.yaml", 7),
			{Source: "trivy", RuleID: "CVE-2024-0042", Package: "requests", File: "requirements.txt"},
			{Source: "trivy", RuleID: "CVE-2024-42", Package: "requests", File: "requirements.txt"},
			{Source: "semgrep", RuleID: "KSV-0017", File: filepath.Join(root, "k8s/pod.yaml"), Line: 5},
		},
	}

	applyProjectSuppressions(&result)

	var kept []string
	for _, f := range result.External {
		kept = append(kept, f.Source+":"+f.RuleID)
	}
	if want := []string{"trivy:KSV-0014", "trivy:CVE-2024-42", "semgrep:KSV-0017"}; !reflect.DeepEqual(kept, want) {
		t.Errorf("kept %v; want %v", kept, want)
	}
	if want := map[string]int{"trivy:DS002": 2, "AVD-KSV-0017": 1, "CVE-2024-0042": 1}; !reflect.DeepEqual(result.IgnoredByConfig, want) {
		t.Errorf("ignored by config = %v; want %v", result.IgnoredByConfig, want)
	}
	if want := map[string]int{"trivy:KSV012": 1}; !reflect.DeepEqual(result.SuppressedInline, want) {
		t.Errorf("suppressed inline = %v; want %v", result.SuppressedInline, want)
	}
}
