package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
)

// A decision made in the container Web UI is kept under the reports directory,
// because the project is read-only there. The next scan in the container must
// apply it from that copy, or the decision is recorded and then ignored.
func TestWebScanInContainerAppliesDecisionsRecordedThere(t *testing.T) {
	root, reports := baselineTestProject(t)
	finding := scannedInnerHTML(t, root)
	containerBaselineEnv(t, reports)
	mountReadOnly(t, root)
	s := setupTestServer(t)
	s.hostPrefix = root
	scan := func() *llm.RichScanResult {
		t.Helper()
		rich := orchestrator.RunAllScanners(context.Background(), orchestrator.Options{ProjectPath: root})
		return &rich
	}
	status := func(rich *llm.RichScanResult) (core.AuditStatus, bool) {
		for _, r := range rich.Report.Results {
			if r.ID == finding.ID {
				return r.AuditStatus, true
			}
		}
		return "", false
	}

	callSuppressions(t, s, http.MethodPost, "/api/suppressions", dismissal(t, finding, "false_positive", ""))
	dismissed := scan()
	if _, err := applyScanDecisions(dismissed, root, false); err != nil {
		t.Fatal(err)
	}
	if got, ok := status(dismissed); !ok || got != core.AuditStatusIgnored {
		t.Fatalf("the finding dismissed in the container is %q (present=%v), want it marked %q", got, ok, core.AuditStatusIgnored)
	}

	callBaseline(t, s, http.MethodPost, "/api/baseline", `{}`)
	baselined := scan()
	hidden, err := applyScanDecisions(baselined, root, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := status(baselined); present || hidden == 0 {
		t.Fatalf("the baseline written in the container hid %d finding(s) and left %s in place=%v", hidden, finding.ID, present)
	}
}
