package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine/core"
)

func TestEngine_Run_WithConfig(t *testing.T) {
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	// Make sure we have ENTR-01 and ENTR-09 defined in default rules
	// ENTR-01: Hardcoded passwords
	// ENTR-09: Client-Side Secret Leak (process.env.SECRET)

	mockPath := filepath.Join("testdata", "mock-project")
	ws, err := core.NewWorkspace(mockPath)
	if err != nil {
		t.Fatalf("Failed to load workspace: %v", err)
	}

	// Create a dummy project context simulating universal
	proj := &core.ProjectContext{
		RootPath: mockPath,
		Files:    ws.Files,
		Stack:    "universal",
		Config:   ws.Config,
	}

	results := eng.Run(proj)

	// In testdata/mock-project we have leak.js (process.env.SECRET_KEY) and pass.js (password = '123')
	// ENTR-01 should match pass.js but it is ignored via aitriage.yaml
	// ENTR-09 (or whatever process.env secret is) should match leak.js

	var entropy01Found bool
	var leakFound bool

	for _, r := range results {
		if r.ID == "ENTR-01" && r.Status == core.Absent {
			entropy01Found = true
		}
		if r.ID == "ENTR-11" && r.Status == core.Absent {
			leakFound = true
		}
	}

	if entropy01Found {
		t.Errorf("ENTR-01 should be ignored via aitriage.yaml but was found")
	}

	if !leakFound {
		t.Errorf("ENTR-11 (placeholder leak) should be found but wasn't")
	}
}

func TestEngine_InlineIgnore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "aitriage-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	filePath := filepath.Join(tmpDir, "test.js")
	content := "password = 'secret' // aitriage:ignore ENTR-01\nsecret = '123'"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	eng, _ := NewEngine(cfg)

	// Add a rule that matches 'password'
	eng.Rules = append(eng.Rules, Rule{
		ID:              "ENTR-01",
		Pattern:         "password",
		CompiledPattern: regexp.MustCompile("password"),
		Extensions:      []string{".js"},
	})

	ws, _ := core.NewWorkspace(tmpDir)
	proj := &core.ProjectContext{
		RootPath: tmpDir,
		Files:    ws.Files,
		Stack:    "universal",
		Config:   cfg,
	}

	results := eng.Run(proj)

	found := false
	for _, r := range results {
		if r.ID == "ENTR-01" && r.Status == core.Absent {
			found = true
		}
	}

	if found {
		t.Errorf("Rule ENTR-01 should have been ignored by inline comment")
	}
}

func TestEngine_ExtensionlessDockerfileRuleRecognizesUser(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM python:3.12-slim\nUSER 65534:65534\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	results := eng.Run(&core.ProjectContext{RootPath: tmpDir, Files: ws.Files, Stack: "universal", Config: ws.Config})
	for _, result := range results {
		if result.ID == "DOCKER-NO-USER" {
			t.Fatalf("Dockerfile with USER must not report DOCKER-NO-USER: %+v", result)
		}
	}
}

func TestEngine_NotContainsConditionSuppressesMatchingRule(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "llm.py"), []byte("client.messages.create(max_tokens=200)\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	results := eng.Run(&core.ProjectContext{RootPath: tmpDir, Files: ws.Files, Stack: "universal", Config: ws.Config})
	for _, result := range results {
		if result.ID == "LLM-NO-TOKEN-LIMIT" {
			t.Fatalf("max_tokens must suppress LLM-NO-TOKEN-LIMIT: %+v", result)
		}
	}
}

func TestEngine_FastAPISecurityRulesNeedRelevantRuntimeEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte("from fastapi import FastAPI\napp = FastAPI()\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	results := eng.Run(&core.ProjectContext{RootPath: tmpDir, Files: ws.Files, Stack: "fastapi", Config: ws.Config})
	for _, result := range results {
		if result.ID == "FAST-CSRF" || result.ID == "FAST-ORM" {
			t.Fatalf("%s must require cookie/session or database evidence: %+v", result.ID, result)
		}
	}
}

func TestEngine_FastAPISecurityRulesFlagRelevantRuntimeEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte("import sqlite3\nresponse.set_cookie('session', 'value')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	results := eng.Run(&core.ProjectContext{RootPath: tmpDir, Files: ws.Files, Stack: "fastapi", Config: ws.Config})
	found := map[string]bool{}
	for _, result := range results {
		found[result.ID] = true
	}
	for _, id := range []string{"FAST-CSRF"} { // FAST-ORM was retired: a database driver without an ORM is not a vulnerability
		if !found[id] {
			t.Fatalf("expected %s for relevant runtime evidence", id)
		}
	}
}
