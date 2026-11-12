package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummariseBothFormats(t *testing.T) {
	files, err := collect([]string{"testdata"})
	if err != nil {
		t.Fatal(err)
	}
	stats, runs, err := summarise(files)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
	a := stats["RULE-A"]
	if a == nil || a.Findings != 3 || a.Runs != 2 || a.TP != 1 || a.FP != 2 || a.Mrg != 1 {
		t.Errorf("RULE-A = %+v", a)
	}
	if b := stats["B101"]; b == nil || b.FP != 1 || b.Source != "bandit" {
		t.Errorf("merged origin not attributed: %+v", b)
	}
	if b := stats["RULE-B"]; b == nil || b.NR != 1 || b.NRFallback != 1 {
		t.Errorf("RULE-B = %+v", b)
	}
	if c := stats["RULE-C"]; c == nil || c.TriageFailed != 1 {
		t.Errorf("RULE-C = %+v", c)
	}
	ranked := rank(stats, 1)
	if ranked[0].Rule != "RULE-A" {
		t.Errorf("noisiest rule = %s, want RULE-A", ranked[0].Rule)
	}
	var out bytes.Buffer
	if err := write(&out, ranked, runs, "md"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "/abs/path") {
		t.Error("output must not contain paths")
	}
	if !strings.Contains(out.String(), "| RULE-A | aitriage | 3 | 2 | 1 | 2 |") {
		t.Errorf("unexpected table:\n%s", out.String())
	}
}
