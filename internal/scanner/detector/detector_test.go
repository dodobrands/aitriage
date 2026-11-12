package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

func TestDetectProjects_Isolation(t *testing.T) {
	tmpDir := t.TempDir()

	// Setup directory structure
	// /tmp/monorepo/
	//   package.json (NextJS)
	//   app/layout.tsx
	//   backend/package.json (Express)
	//   backend/server.js
	//   other/requirements.txt (FastAPI)
	//   other/main.py

	files := map[string]string{
		"package.json":           `{"dependencies": {"next": "latest"}}`,
		"app/layout.tsx":         "import React from 'react'",
		"backend/package.json":   `{"dependencies": {"express": "latest"}}`,
		"backend/server.js":      "const express = require('express')",
		"other/requirements.txt": "fastapi\nuvicorn",
		"other/main.py":          "from fastapi import FastAPI",
	}

	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create workspace
	ws := &core.Workspace{
		RootPath: tmpDir,
	}
	for path := range files {
		fullPath := filepath.Join(tmpDir, path)
		ws.Files = append(ws.Files, &core.FileInfo{
			Path:      fullPath,
			Extension: filepath.Ext(path),
		})
	}

	projects := DetectProjects(ws)

	if len(projects) != 3 {
		t.Fatalf("Expected 3 projects, got %d", len(projects))
	}

	// Helper to find project by stack
	findProject := func(stack string) *core.ProjectContext {
		for _, p := range projects {
			if p.Stack == stack {
				return p
			}
		}
		return nil
	}

	nextProj := findProject("nextjs")
	expressProj := findProject("express")
	fastapiProj := findProject("fastapi")

	if nextProj == nil || expressProj == nil || fastapiProj == nil {
		t.Fatal("One of the projects was not detected")
		return
	}

	// Check isolation
	// NextJS project (root) should NOT contain files that belong to more specific sub-projects (backend, other)
	for _, f := range nextProj.Files {
		if strings.Contains(f.Path, "backend") {
			t.Errorf("NextJS project contains backend file: %s", f.Path)
		}
		if strings.Contains(f.Path, "other") {
			t.Errorf("NextJS project contains other file: %s", f.Path)
		}
	}

	// Express project should contain backend files
	foundServer := false
	for _, f := range expressProj.Files {
		if strings.Contains(f.Path, filepath.Join("backend", "server.js")) {
			foundServer = true
		}
	}
	if !foundServer {
		t.Error("Express project missing backend/server.js")
	}

	// FastAPI project should contain other files
	foundMain := false
	for _, f := range fastapiProj.Files {
		if strings.Contains(f.Path, filepath.Join("other", "main.py")) {
			foundMain = true
		}
	}
	if !foundMain {
		t.Error("FastAPI project missing other/main.py")
	}
}

func TestDetectProjects_ExpressDependencyNeedsRuntimeImport(t *testing.T) {
	tmpDir := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies": {"express": "^4.0.0", "react": "^19.0.0"}}`,
		"src/App.tsx":  "export function App() { return null }",
	}
	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	for _, project := range DetectProjects(ws) {
		if project.Stack == string(Express) {
			t.Fatal("unused express dependency must not activate Express rules")
		}
	}
}

func TestDetectProjects_TestFixturesCannotActivateStack(t *testing.T) {
	tmpDir := t.TempDir()
	files := map[string]string{
		"main.go":                "package main\n",
		"testdata/package.json":  `{"dependencies":{"next":"latest"}}`,
		"tests/requirements.txt": "fastapi\n",
		"__fixtures__/manage.py": "from django.core import management\n",
		"src/contest.go":         "package main\n",
		"src/latest.py":          "print('production')\n",
	}
	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ws, err := core.NewWorkspace(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	projects := DetectProjects(ws)
	for _, project := range projects {
		if project.Stack == string(NextJS) || project.Stack == string(FastAPI) || project.Stack == string(Django) {
			t.Fatalf("test-only fixture activated production stack %q", project.Stack)
		}
		for _, file := range project.Files {
			if file.IsTest {
				t.Fatalf("test-like file assigned to production project: %s", file.Path)
			}
		}
	}
}

func detectIn(t *testing.T, files map[string]string) []*core.ProjectContext {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ws, err := core.NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	return DetectProjects(ws)
}

func projectOf(projects []*core.ProjectContext, base string) *core.ProjectContext {
	for _, p := range projects {
		for _, f := range p.Files {
			if filepath.ToSlash(f.RelPath) == base || strings.HasSuffix(filepath.ToSlash(f.Path), "/"+base) {
				return p
			}
		}
	}
	return nil
}

func TestDetectProjects_FilesOutsideProjectsGetUniversalRules(t *testing.T) {
	projects := detectIn(t, map[string]string{
		"svc/api/go.mod":     "module example.com/api\n",
		"svc/api/main.go":    "package main\n",
		"Dockerfile":         "FROM alpine:3.20\n",
		"docker-compose.yml": "services:\n  app:\n    privileged: true\n",
	})
	for _, name := range []string{"Dockerfile", "docker-compose.yml"} {
		p := projectOf(projects, name)
		if p == nil {
			t.Fatalf("%s is not attached to any project", name)
		}
		if p.Stack != string(UnknownStack) {
			t.Errorf("%s attached to a %s project; want unknown", name, p.Stack)
		}
	}
	if p := projectOf(projects, "svc/api/main.go"); p == nil || p.Stack != string(Go) {
		t.Errorf("main.go should stay in the go project")
	}
}

func TestDetectProjects_EntryPointDoesNotSplitAnApplication(t *testing.T) {
	projects := detectIn(t, map[string]string{
		"requirements.txt":   "django==5.0\n",
		"manage.py":          "import django\n",
		"mysite/asgi.py":     "from django.core.asgi import get_asgi_application\n",
		"mysite/settings.py": "MIDDLEWARE = []\n",
		"blog/views.py":      "from django.http import HttpResponse\n",
	})
	root := projectOf(projects, "blog/views.py")
	if root == nil || root.Stack != string(Django) {
		t.Fatalf("views.py not in a django project")
	}
	if p := projectOf(projects, "mysite/settings.py"); p != root {
		t.Errorf("settings.py split into its own project %v", p)
	}
}

func TestDetectProjects_ManagePyMustBeDjango(t *testing.T) {
	projects := detectIn(t, map[string]string{
		"requirements.txt":        "fastapi==0.110\n",
		"main.py":                 "from fastapi import FastAPI\n",
		"app/database/manage.py":  "import alembic\n",
		"app/database/session.py": "engine = None\n",
	})
	for _, p := range projects {
		if p.Stack == string(Django) {
			t.Errorf("a non-Django manage.py created a django project at %s", p.RootPath)
		}
	}
}
