package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiffMatchesFindingsAcrossLocations(t *testing.T) {
	base, err := load("testdata/base")
	if err != nil {
		t.Fatal(err)
	}
	next, err := load("testdata/new")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := diff(&out, base, next); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"Findings: 3 → 3",
		"| R-LOST | 1 | 0 | 1 | 0 | CRITICAL → - |",
		"| R-NEW | 0 | 1 | 0 | 1 | - → MEDIUM |",
		"| R-SEV | 1 | 1 | 0 | 0 | CRITICAL → HIGH |",
		"- app R-LOST main.py:9",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "| R-KEEP |") {
		t.Errorf("unchanged rule must not be listed:\n%s", got)
	}
}
