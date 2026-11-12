package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func indexedFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	ws, err := NewWorkspace(root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	defer ws.Close()
	files := map[string]bool{}
	for _, f := range ws.Files {
		rel, err := filepath.Rel(root, f.Path)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.ToSlash(rel)] = true
	}
	return files
}

// captureLegacyWarnings records compatibility warnings instead of logging them.
func captureLegacyWarnings(t *testing.T) *[]string {
	t.Helper()
	var got []string
	previous := warnLegacyIgnorePath
	warnLegacyIgnorePath = func(msg string, args ...any) {
		got = append(got, fmt.Sprint(append([]any{msg}, args...)...))
	}
	t.Cleanup(func() { warnLegacyIgnorePath = previous })
	return &got
}

// The defaults "aitriage init" writes include vendor/ and dist/. Matched as
// substrings they also removed the project's own src/vendors/ and
// distribution/ from the scan, and every finding in them with it.
func TestIgnorePathsDoNotDropProjectCodeThatSharesAName(t *testing.T) {
	root := t.TempDir()
	captureLegacyWarnings(t)
	writeTree(t, root, map[string]string{
		".aitriage.yaml":              "ignore:\n  paths:\n    - vendor/\n    - dist/\n    - legacy/\n",
		"src/vendors/api.py":          "API_KEY = 'x'\n",
		"distribution/app.py":         "print('app')\n",
		"src/legacy_tools/migrate.py": "print('migrate')\n",
		"legacy/old.py":               "print('old')\n",
		"src/legacy/older.py":         "print('older')\n",
	})

	files := indexedFiles(t, root)

	for _, kept := range []string{"src/vendors/api.py", "distribution/app.py", "src/legacy_tools/migrate.py"} {
		if !files[kept] {
			t.Errorf("%s was dropped from the scan; ignore.paths must not match by substring", kept)
		}
	}
	for _, dropped := range []string{"legacy/old.py", "src/legacy/older.py"} {
		if files[dropped] {
			t.Errorf("%s is under an ignored directory but was scanned", dropped)
		}
	}
}

// ignore.paths used to be checked against directories only, so an entry naming
// a file had no effect on the built-in engine.
func TestIgnorePathsExcludeFiles(t *testing.T) {
	root := t.TempDir()
	captureLegacyWarnings(t)
	writeTree(t, root, map[string]string{
		".aitriage.yaml":           "ignore:\n  paths:\n    - \"*_pb2.py\"\n    - config/settings_local.py\n",
		"api/service_pb2.py":       "X = 1\n",
		"api/service.py":           "X = 2\n",
		"config/settings_local.py": "DEBUG = True\n",
		"config/settings.py":       "DEBUG = False\n",
	})

	files := indexedFiles(t, root)

	if files["api/service_pb2.py"] || files["config/settings_local.py"] {
		t.Errorf("files named in ignore.paths were scanned: %v", files)
	}
	if !files["api/service.py"] || !files["config/settings.py"] {
		t.Errorf("files outside ignore.paths were dropped: %v", files)
	}
}

func TestLegacySubstringMatchesProduceOneWarningPerPattern(t *testing.T) {
	root := t.TempDir()
	warnings := captureLegacyWarnings(t)
	writeTree(t, root, map[string]string{
		".aitriage.yaml":            "ignore:\n  paths:\n    - tests\n",
		"tests/test_app.py":         "assert True\n",
		"unit_tests/test_api.py":    "assert True\n",
		"unit_tests/deep/test_x.py": "assert True\n",
		"contests/entry.py":         "print('entry')\n",
	})

	files := indexedFiles(t, root)
	if files["tests/test_app.py"] {
		t.Error("tests/ is ignored and must not be scanned")
	}
	if !files["unit_tests/test_api.py"] || !files["contests/entry.py"] {
		t.Errorf("directories that merely contain the pattern were dropped: %v", files)
	}

	if len(*warnings) != 1 {
		t.Fatalf("warnings = %q; want exactly one for the pattern", *warnings)
	}
	warning := (*warnings)[0]
	for _, want := range []string{`"tests"`, ".gitignore syntax"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning %q does not mention %s", warning, want)
		}
	}
	// The first directory the old rule matched in walk order is suggested.
	if !strings.Contains(warning, `"contests/"`) && !strings.Contains(warning, `"unit_tests/"`) {
		t.Errorf("warning %q does not suggest the path to add", warning)
	}

	// A second scan of the same project in the same process stays quiet.
	indexedFiles(t, root)
	if len(*warnings) != 1 {
		t.Errorf("warnings after a second scan = %q; want no repeat", *warnings)
	}
}

func TestPatternsTheNewMatcherHonoursProduceNoWarning(t *testing.T) {
	root := t.TempDir()
	warnings := captureLegacyWarnings(t)
	writeTree(t, root, map[string]string{
		".aitriage.yaml":         "ignore:\n  paths:\n    - generated/\n    - .cache\n",
		"generated/client.py":    "X = 1\n",
		"src/app/generated/x.py": "X = 2\n",
		"src/main.py":            "print('main')\n",
	})

	files := indexedFiles(t, root)
	if files["generated/client.py"] || files["src/app/generated/x.py"] {
		t.Errorf("ignored directories were scanned: %v", files)
	}
	if len(*warnings) != 0 {
		t.Errorf("warnings = %q; want none when both rules agree", *warnings)
	}
}

// Matched against the absolute path, a pattern that happened to occur in the
// directory a project was checked out to excluded the entire project.
func TestIgnorePathMatchingTheCheckoutDirectoryNoLongerEmptiesTheScan(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vendor-portal")
	warnings := captureLegacyWarnings(t)
	writeTree(t, root, map[string]string{
		".aitriage.yaml": "ignore:\n  paths:\n    - vendor\n",
		"app/main.py":    "print('main')\n",
	})

	files := indexedFiles(t, root)
	if !files["app/main.py"] {
		t.Fatalf("files = %v; the project itself must be scanned", files)
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "project directory itself") {
		t.Errorf("warnings = %q; want one explaining the project used to be skipped", *warnings)
	}
}

// The project directory is never excluded by its own name: a project checked
// out as "build" or "dist" was scanned as if it were empty.
func TestWorkspaceRootIsNeverExcludedByName(t *testing.T) {
	for _, name := range []string{"build", "dist", "vendor"} {
		root := filepath.Join(t.TempDir(), name)
		writeTree(t, root, map[string]string{"main.go": "package main\n", "vendor/lib.go": "package lib\n"})

		files := indexedFiles(t, root)
		var got []string
		for f := range files {
			got = append(got, f)
		}
		sort.Strings(got)
		if len(got) != 1 || got[0] != "main.go" {
			t.Errorf("root %q indexed %v; want only main.go", name, got)
		}
	}
}

// Go's standard layout keeps Dockerfiles and CI scripts in build/; the engine
// skipped them as generated output. Generated output is git-ignored, and the
// walker still honours that.
func TestCommittedBuildDirectoryIsIndexed(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"build/package/Dockerfile": "FROM alpine\n",
		"build/ci/deploy.sh":       "echo deploy\n",
	})
	files := indexedFiles(t, root)
	if !files["build/package/Dockerfile"] || !files["build/ci/deploy.sh"] {
		t.Errorf("files = %v; a committed build/ directory is the project's own", files)
	}

	ignored := t.TempDir()
	writeTree(t, ignored, map[string]string{".gitignore": "build/\n", "build/bundle.js": "x\n", "main.go": "package main\n"})
	if files := indexedFiles(t, ignored); files["build/bundle.js"] {
		t.Errorf("files = %v; git-ignored build output must not be scanned", files)
	}
}

// A negated entry re-includes a file under an ignored directory, so the walker
// must descend instead of pruning the directory.
func TestIgnorePathsNegationReincludesFile(t *testing.T) {
	root := t.TempDir()
	captureLegacyWarnings(t)
	writeTree(t, root, map[string]string{
		".aitriage.yaml":         "ignore:\n  paths:\n    - \"generated/*\"\n    - \"!generated/keep.py\"\n",
		"generated/keep.py":      "X = 1\n",
		"generated/throwaway.py": "X = 2\n",
	})

	files := indexedFiles(t, root)
	if !files["generated/keep.py"] || files["generated/throwaway.py"] {
		t.Errorf("files = %v; want keep.py only", files)
	}
}
