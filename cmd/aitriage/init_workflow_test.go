package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The CI workflow written by `aitriage init` installs AITriage with
// `go install`, so its Go version must satisfy the module's go directive.
// A stale pin only worked by accident, through toolchain auto-download.
func TestGeneratedWorkflowGoVersionMatchesModule(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+)`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go directive not found in go.mod")
	}
	want := "go-version: '" + string(m[1]) + "'"
	if wf := generateCIWorkflow(); !strings.Contains(wf, want) {
		t.Fatalf("generated workflow does not pin %s (module requires go %s)", want, m[1])
	}
}
