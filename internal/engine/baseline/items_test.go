package baseline

import (
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// A baseline that holds only the built-in engine's findings does not solve the
// problem it exists for. The pilot's PHP project reported twelve CVEs from
// composer.lock via Trivy; none of them could be accepted, so the gate stayed
// red whatever he did.

func TestBaselineAcceptsFindingsFromEveryScanner(t *testing.T) {
	items := []Item{
		{Source: "core", RuleID: "ENTR-17", File: "config.php", Evidence: "key=abc", Severity: "CRITICAL"},
		{Source: "trivy", RuleID: "CVE-2026-69246", File: "composer.lock", Evidence: "guzzle 7.8.1", Severity: "HIGH"},
		{Source: "gitleaks", RuleID: "generic-api-key", File: "app.php", Evidence: "sk_live_...", Severity: "CRITICAL"},
		{Source: "semgrep", RuleID: "php.tainted-sql", File: "index.php", Evidence: "$_GET[id]", Severity: "HIGH"},
		{Source: "bandit", RuleID: "B602", File: "run.py", Evidence: "shell=True", Severity: "MEDIUM"},
		{Source: "nfr", RuleID: "NFR-API-002", Evidence: "no rate limit", Severity: "MEDIUM"},
		{Source: "deploy", RuleID: "dockerfile_root_user", File: "Dockerfile", Evidence: "no USER", Severity: "HIGH"},
	}

	b := NewFromItems(items)

	if len(b.Findings) != len(items) {
		t.Fatalf("accepted %d of %d findings", len(b.Findings), len(items))
	}
	for _, item := range items {
		if !b.Accepts(item) {
			t.Errorf("a %s finding was not accepted by the baseline", item.Source)
		}
	}
}

func TestTwoScannersReportingTheSameLineStayDistinct(t *testing.T) {
	semgrep := Item{Source: "semgrep", RuleID: "sqli", File: "a.php", Line: 10, Evidence: "$_GET"}
	sonarLike := Item{Source: "bandit", RuleID: "sqli", File: "a.php", Line: 10, Evidence: "$_GET"}

	b := NewFromItems([]Item{semgrep})

	if !b.Accepts(semgrep) {
		t.Error("the accepted finding is not recognised")
	}
	if b.Accepts(sonarLike) {
		t.Error("accepting one scanner's finding also hid another scanner's; they are different findings")
	}
}

func TestLineShiftsDoNotResurfaceAnAcceptedFinding(t *testing.T) {
	original := Item{Source: "trivy", RuleID: "CVE-1", File: "composer.lock", Line: 4, Evidence: "pkg 1.0"}
	moved := original
	moved.Line = 900

	b := NewFromItems([]Item{original})

	if !b.Accepts(moved) {
		t.Error("an edit above the finding resurfaced it; line numbers must not be part of identity")
	}
}

func TestChangedEvidenceIsANewFinding(t *testing.T) {
	accepted := Item{Source: "trivy", RuleID: "CVE-1", File: "composer.lock", Evidence: "guzzle 7.8.1"}
	upgraded := accepted
	upgraded.Evidence = "guzzle 7.9.0"

	b := NewFromItems([]Item{accepted})

	if b.Accepts(upgraded) {
		t.Error("a different finding was hidden by the baseline; evidence is part of identity")
	}
}

// Upgrading AITriage must not resurface everything a team already accepted.
func TestVersionOneBaselineStillMatchesCoreFindings(t *testing.T) {
	legacyResults := []core.CheckResult{
		{ID: "ENTR-17", File: "config.php", Evidence: "key=abc", Severity: "CRITICAL", Name: "Hardcoded secret"},
	}
	legacy := New(legacyResults) // writes the version "1" shape

	if legacy.Version != Version {
		t.Fatalf("legacy baseline version = %q; want %q", legacy.Version, Version)
	}

	sameFinding := Item{Source: "core", RuleID: "ENTR-17", File: "config.php", Evidence: "key=abc"}
	if !legacy.Accepts(sameFinding) {
		t.Error("a finding accepted before the format change came back after it")
	}

	// A new-format baseline does not need the legacy fallback.
	modern := NewFromItems([]Item{sameFinding})
	if modern.Version != CurrentSchema {
		t.Errorf("new baseline version = %q; want %q", modern.Version, CurrentSchema)
	}
	if !modern.Accepts(sameFinding) {
		t.Error("the new format does not match its own findings")
	}
}

func TestVersionOneBaselineDoesNotSwallowExternalFindings(t *testing.T) {
	legacy := New([]core.CheckResult{{ID: "CVE-1", File: "composer.lock", Evidence: "pkg"}})

	// The legacy fallback applies to core findings only. A Trivy finding that
	// happens to share a rule id must not be treated as already accepted.
	external := Item{Source: "trivy", RuleID: "CVE-1", File: "composer.lock", Evidence: "pkg"}
	if legacy.Accepts(external) {
		t.Error("a version 1 baseline accepted an external finding it never contained")
	}
}

func TestAdaptersCarryTheIdentifyingDetail(t *testing.T) {
	ext := FromExternal([]external.UnifiedFinding{
		{Source: "trivy", RuleID: "CVE-9", File: "go.sum", Line: 3, Severity: "HIGH", Message: "stdlib 1.25.12"},
	})
	if len(ext) != 1 || ext[0].Evidence != "stdlib 1.25.12" || ext[0].Source != "trivy" {
		t.Errorf("external adapter lost detail: %+v", ext)
	}

	n := FromNFR([]nfr.NFRFinding{{RuleID: "NFR-1", Name: "n", Severity: "LOW", Message: "m"}})
	if len(n) != 1 || n[0].Source != "nfr" || n[0].Evidence != "m" {
		t.Errorf("nfr adapter lost detail: %+v", n)
	}

	d := FromDeploy([]deployaudit.DeployFinding{{Issue: "i", File: "Dockerfile", Line: 1, Severity: "HIGH", Evidence: "e"}})
	if len(d) != 1 || d[0].Source != "deploy" || d[0].Evidence != "e" {
		t.Errorf("deploy adapter lost detail: %+v", d)
	}

	c := FromCore([]core.CheckResult{{ID: "X", File: "f", Evidence: "e"}})
	if len(c) != 1 || c[0].Source != "core" {
		t.Errorf("core adapter lost detail: %+v", c)
	}
}

func TestFilterSplitsNewFromAccepted(t *testing.T) {
	accepted := Item{Source: "trivy", RuleID: "CVE-1", File: "composer.lock", Evidence: "a"}
	fresh := Item{Source: "trivy", RuleID: "CVE-2", File: "composer.lock", Evidence: "b"}

	b := NewFromItems([]Item{accepted})
	result := FilterItems([]Item{accepted, fresh}, b)

	if len(result.Accepted) != 1 || result.Accepted[0].RuleID != "CVE-1" {
		t.Errorf("accepted = %+v", result.Accepted)
	}
	if len(result.New) != 1 || result.New[0].RuleID != "CVE-2" {
		t.Errorf("new = %+v", result.New)
	}
}

func TestNoBaselineMeansNothingIsHidden(t *testing.T) {
	items := []Item{{Source: "trivy", RuleID: "CVE-1"}}

	if got := FilterItems(items, nil); len(got.New) != 1 || len(got.Accepted) != 0 {
		t.Errorf("a nil baseline hid a finding: %+v", got)
	}
	if got := FilterItems(items, NewFromItems(nil)); len(got.New) != 1 {
		t.Errorf("an empty baseline hid a finding: %+v", got)
	}
}

func TestSourceNamesAreNormalised(t *testing.T) {
	// The built-in engine reports itself as "core" in some paths and "aitriage"
	// in others; both must mean the same scanner.
	a := Item{Source: "core", RuleID: "X", File: "f", Evidence: "e"}
	b := Item{Source: "AITriage", RuleID: "X", File: "f", Evidence: "e"}
	blank := Item{Source: "", RuleID: "X", File: "f", Evidence: "e"}

	if FingerprintItem(a) != FingerprintItem(b) || FingerprintItem(a) != FingerprintItem(blank) {
		t.Error("the same finding fingerprints differently depending on how the source is spelled")
	}
}
