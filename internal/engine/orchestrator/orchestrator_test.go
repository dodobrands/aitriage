package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunAllScanners_Integration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Write a dummy go file to trigger the scanner
	goFile := filepath.Join(tempDir, "main.go")
	err := os.WriteFile(goFile, []byte("package main\n\nfunc main() {\n\t// TODO: fix this\n}\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write dummy go file: %v", err)
	}

	// Write a dummy docker-compose file to trigger network and deploy audit
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	err = os.WriteFile(composeFile, []byte("version: '3'\nservices:\n  web:\n    image: nginx\n    privileged: true\n    ports:\n      - \"8080:80\"\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write dummy compose file: %v", err)
	}

	opts := Options{
		ProjectPath:  tempDir,
		ProbeHost:    "localhost",
		ForceStack:   "",
		RunExternal:  false, // We skip external tools (trivy, semgrep, gitleaks, bandit) to avoid dependencies
		FullPortScan: false,
		ProbeCompose: true, // compose probing is opt-in; this test exercises it
	}

	ctx := context.Background()

	result := RunAllScanners(ctx, opts)

	// Validate the result
	if result.ProjectPath != tempDir {
		t.Errorf("Expected ProjectPath %q, got %q", tempDir, result.ProjectPath)
	}

	// The network probe should have found the 8080 port from docker-compose
	foundDockerCompose := false
	for _, finding := range result.Network {
		if finding.Target == "web" || finding.Target == "docker-compose" {
			foundDockerCompose = true
			break
		}
	}
	if !foundDockerCompose && len(result.Network) > 0 {
		t.Logf("Warning: Expected network findings to include docker-compose ports, got: %v", result.Network)
	}

	// Scanner should run (Report struct is populated)
	if result.Report.ProjectPath == "" && len(result.Report.Results) == 0 {
		t.Logf("Scanner ran but returned empty/uninitialized report")
	}

	// Deploy audit should have found the docker-compose.yml
	if len(result.Deploy) == 0 {
		t.Errorf("Expected Deploy findings for docker-compose.yml, got none")
	}

	// NFR checks should run
	if result.NFR == nil {
		t.Errorf("Expected NFR findings to be initialized")
	}

	// Architecture diagram should run
	if result.Diagram == "" {
		t.Errorf("Expected Diagram to be generated")
	}
}

// Compose probing reports on the machine AITriage runs on, so it is opt-in like
// host probing. Running it unconditionally gave every CI run a MEDIUM "port-53"
// finding per service: Compose service names never resolve there.
func TestRunAllScannersDoesNotProbeComposeUnlessAsked(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  app:\n    image: example/app\n  db:\n    image: postgres\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	result := RunAllScanners(context.Background(), Options{ProjectPath: dir})

	if len(result.Network) != 0 {
		t.Fatalf("compose services were probed without being asked: %+v", result.Network)
	}
}

// The manifest and the summary scanner table read the per-scanner count from
// the execution record. NFR and deploy records left it out and showed 0.
func TestRunAllScannersRecordsNFRAndDeployFindingCounts(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"main.py":    "from fastapi import FastAPI\n\napp = FastAPI()\n",
		"Dockerfile": "FROM python:3.12-slim\nUSER root\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	result := RunAllScanners(context.Background(), Options{ProjectPath: dir})

	if len(result.NFR) == 0 || len(result.Deploy) == 0 {
		t.Fatalf("fixture must produce NFR and deploy findings: nfr=%d deploy=%d", len(result.NFR), len(result.Deploy))
	}
	recorded := map[string]int{}
	for _, execution := range result.ScannerExecutions {
		recorded[execution.Scanner] = execution.Findings
	}
	if recorded["nfr"] != len(result.NFR) {
		t.Errorf("nfr execution records %d findings; the result holds %d", recorded["nfr"], len(result.NFR))
	}
	if recorded["deploy"] != len(result.Deploy) {
		t.Errorf("deploy execution records %d findings; the result holds %d", recorded["deploy"], len(result.Deploy))
	}
}

func TestReportedFindingsIsZeroForAFailedRun(t *testing.T) {
	if got := reportedFindings(3, nil); got != 3 {
		t.Errorf("completed run: got %d, want 3", got)
	}
	if got := reportedFindings(3, os.ErrPermission); got != 0 {
		t.Errorf("failed run: got %d, want 0 (its partial list is not in the result)", got)
	}
}
