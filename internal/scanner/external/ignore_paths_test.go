package external

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ignore.paths in .aitriage.yaml used to reach only the built-in engine. A
// project that excluded a vendored WordPress plugin still got Gitleaks,
// Semgrep and Bandit findings from inside it, each sent to AI triage.

const akismetConfig = "ignore:\n  paths:\n    - wp-content/plugins/akismet/\n"

func akismetProject(t *testing.T) string {
	return writeProject(t, map[string]string{
		".aitriage.yaml":                          akismetConfig,
		"wp-content/plugins/akismet/akismet.php":  "<?php eval($_GET['code']);\n",
		"wp-content/plugins/akismet/helper.py":    "import subprocess\nsubprocess.call(cmd, shell=True)\n",
		"wp-content/plugins/other/plugin.php":     "<?php echo 1;\n",
		"main.py":                                 "print('app')\n",
		"src/vendors/api.py":                      "API_KEY = 'x'\n",
		"wp-content/plugins/akismet-fork/fork.py": "print('fork')\n",
	})
}

func TestScopeFilterHonoursIgnorePathsFromConfig(t *testing.T) {
	root := akismetProject(t)

	findings := []UnifiedFinding{
		{Source: "gitleaks", RuleID: "generic-api-key", File: filepath.Join(root, "wp-content/plugins/akismet/akismet.php"), Line: 1},
		{Source: "semgrep", RuleID: "php.lang.security.eval-use", File: filepath.Join(root, "wp-content/plugins/akismet/akismet.php"), Line: 1},
		{Source: "bandit", RuleID: "B602", File: filepath.Join(root, "wp-content/plugins/akismet/helper.py"), Line: 2},
		{Source: "trivy", RuleID: "CVE-2024-0001", File: "wp-content/plugins/akismet/composer.lock"},
		{Source: "semgrep", RuleID: "kept-other-plugin", File: filepath.Join(root, "wp-content/plugins/other/plugin.php"), Line: 1},
		{Source: "bandit", RuleID: "kept-main", File: filepath.Join(root, "main.py"), Line: 1},
		{Source: "gitleaks", RuleID: "kept-fork", File: filepath.Join(root, "wp-content/plugins/akismet-fork/fork.py"), Line: 1},
	}

	kept := FilterOutOfScope(root, findings)

	var ids []string
	for _, f := range kept {
		ids = append(ids, f.RuleID)
	}
	if len(kept) != 3 || !strings.HasPrefix(ids[0], "kept-") || !strings.HasPrefix(ids[1], "kept-") || !strings.HasPrefix(ids[2], "kept-") {
		t.Fatalf("kept %v; want only the findings outside wp-content/plugins/akismet/", ids)
	}

	filter := NewScopeFilter(root)
	if filter.DirInScope(filepath.Join(root, "wp-content/plugins/akismet")) {
		t.Error("a walker would still descend into the ignored plugin")
	}
	if !filter.DirInScope(filepath.Join(root, "wp-content/plugins")) {
		t.Error("the parent of the ignored plugin must stay in scope")
	}
}

func TestToolArgsCarryIgnorePaths(t *testing.T) {
	root := akismetProject(t)

	// "wp-content/plugins/akismet/" has a slash in the middle, so git anchors
	// it at the root, and every tool is told so.
	semgrep := SemgrepExcludeArgs(root)
	if !containsPair(semgrep, "--exclude", "/wp-content/plugins/akismet/") {
		t.Errorf("semgrep args %q do not exclude the ignored plugin at the root", semgrep)
	}

	trivy := TrivySkipDirArgs(root)
	anchored := filepath.ToSlash(filepath.Join(root, "wp-content/plugins/akismet"))
	if !containsPair(trivy, "--skip-dirs", anchored) {
		t.Errorf("trivy args %q do not skip the ignored plugin", trivy)
	}
	if containsPair(trivy, "--skip-dirs", "**/wp-content/plugins/akismet") {
		t.Errorf("trivy args %q skip the plugin at any depth", trivy)
	}
	// A directory-only entry must not become --skip-files: that would also
	// drop a file of the same name.
	if containsPair(trivy, "--skip-files", anchored) {
		t.Errorf("trivy args %q skip files for a directory-only entry", trivy)
	}

	bandit := banditExcludePaths(root)
	base := filepath.ToSlash(root)
	if !contains(bandit, base+"/wp-content/plugins/akismet/") {
		t.Errorf("bandit -x %q does not exclude the ignored plugin", bandit)
	}
	if contains(bandit, base+"/*/wp-content/plugins/akismet/*") {
		t.Errorf("bandit -x %q excludes the plugin at any depth", bandit)
	}

	config, cleanup, err := newGitleaksConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	content, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `wp-content/plugins/akismet/`) {
		t.Errorf("gitleaks config does not allowlist the ignored plugin:\n%s", content)
	}
	plugin := base + "/wp-content/plugins/akismet/akismet.php"
	nested := base + "/x/wp-content/plugins/akismet/akismet.php"
	allowed := false
	for _, re := range compileAll(t, gitleaksAllowlistPaths(root)) {
		allowed = allowed || re.MatchString(plugin)
		if re.MatchString(nested) {
			t.Errorf("gitleaks allowlist %q drops a plugin directory below the root", re)
		}
	}
	if !allowed {
		t.Errorf("no gitleaks allowlist pattern matches %s", plugin)
	}
}

// Every argument must exclude a subset of what the scope filter excludes: a
// tool that skips too much loses findings the post-filter can never restore.
//
// The filter itself is pinned too, with paths it must drop and near misses it
// must keep. Comparing the tools with the filter alone passed silently while
// both over-matched: "config/local_settings.py" also dropped
// src/config/local_settings.py from the filter and from every tool.
func TestToolArgsNeverExcludeMoreThanTheScopeFilter(t *testing.T) {
	cases := []struct {
		name   string
		config string
		out    []string // the scope filter drops these
		in     []string // near misses the scope filter keeps
		// skipped are out-of-scope paths every tool skips too, so the
		// arguments are not merely harmless. Wildcard and single-file
		// entries are left to the post-filter by some tools.
		skipped []string
	}{
		{
			name:    "directory",
			config:  akismetConfig,
			out:     []string{"wp-content/plugins/akismet/akismet.php", "wp-content/plugins/akismet/inc/a.php"},
			in:      []string{"x/wp-content/plugins/akismet/a.php", "wp-content/plugins/akismet-fork/f.py", "wp-content/plugins/other/p.php"},
			skipped: []string{"wp-content/plugins/akismet/akismet.php"},
		},
		{
			name:    "bare names",
			config:  "ignore:\n  paths:\n    - vendor\n    - tests\n    - build/\n",
			out:     []string{"vendor/lib.py", "src/vendor/lib.py", "src/tests/test_x.py", "build/out.js", "src/build/x.py"},
			in:      []string{"src/vendors/api.py", "unit_tests/test_x.py", "contests/entry.py", "main.py"},
			skipped: []string{"src/vendor/lib.py", "src/tests/test_x.py", "build/out.js"},
		},
		{
			name:    "anchored",
			config:  "ignore:\n  paths:\n    - /generated/\n    - ./out\n",
			out:     []string{"generated/client.py", "out/app.py"},
			in:      []string{"src/generated/client.py", "src/out/app.py"},
			skipped: []string{"generated/client.py", "out/app.py"},
		},
		{
			name:    "slash in the middle",
			config:  "ignore:\n  paths:\n    - app/legacy/\n    - api/internal\n",
			out:     []string{"app/legacy/handler.py", "app/legacy/sub/x.py", "api/internal/keys.go"},
			in:      []string{"services/billing/app/legacy/handler.py", "src/app/legacy/x.py", "app/legacy.py", "src/api/internal/keys.go", "api/internals/keys.go"},
			skipped: []string{"app/legacy/handler.py", "app/legacy/sub/x.py", "api/internal/keys.go"},
		},
		{
			name:   "wildcards",
			config: "ignore:\n  paths:\n    - \"*.min.js\"\n    - \"legacy/*.py\"\n    - \"docs/**\"\n    - \"generated/*\"\n",
			out:    []string{"static/app.min.js", "app.min.js", "legacy/old.py", "docs/guide/index.md", "generated/client.py"},
			in:     []string{"static/app.js", "legacy/sub/old.py", "src/legacy/old.py", "src/docs/x.md", "src/generated/client.py"},
		},
		{
			name:   "single file",
			config: "ignore:\n  paths:\n    - config/local_settings.py\n",
			out:    []string{"config/local_settings.py"},
			in:     []string{"src/config/local_settings.py", "config/local_settings.py.bak", "config/settings.py"},
		},
		{
			name:   "double asterisk",
			config: "ignore:\n  paths:\n    - \"**/fixtures/\"\n    - \"docs/**/examples/\"\n",
			out:    []string{"fixtures/a.json", "src/fixtures/b.json", "docs/examples/e.py", "docs/a/b/examples/e.py"},
			in:     []string{"fixturesdir/c.json", "lib/docs/a/examples/x.py", "docs/a/example/e.py"},
		},
	}
	// Every case also checks the paths of the others, so an entry cannot drop
	// something it was never written for.
	var paths []string
	for _, tc := range cases {
		paths = append(append(paths, tc.out...), tc.in...)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProject(t, map[string]string{".aitriage.yaml": tc.config})
			filter := NewScopeFilter(root)
			gitleaks := compileAll(t, gitleaksAllowlistPaths(root))
			bandit := banditExcludePaths(root)
			trivyDirs, trivyFiles := splitTrivyArgs(TrivySkipDirArgs(root))
			base := filepath.ToSlash(root)

			for _, rel := range tc.out {
				if filter.InScope(base + "/" + rel) {
					t.Errorf("%s must be out of scope", rel)
				}
			}
			for _, rel := range tc.in {
				if !filter.InScope(base + "/" + rel) {
					t.Errorf("%s must stay in scope", rel)
				}
			}

			for _, rel := range paths {
				abs := base + "/" + rel
				if !filter.InScope(abs) {
					continue
				}
				for _, re := range gitleaks {
					if re.MatchString(abs) {
						t.Errorf("gitleaks allowlist %q drops in-scope %s", re, rel)
					}
				}
				for _, entry := range bandit {
					if banditDrops(abs, entry) {
						t.Errorf("bandit -x entry %q drops in-scope %s", entry, rel)
					}
				}
				if trivySkips(base, rel, trivyDirs, trivyFiles) {
					t.Errorf("trivy skip args drop in-scope %s", rel)
				}
			}
			// The project directory itself is never matched: gitleaks would
			// skip the whole walk.
			for _, re := range gitleaks {
				if re.MatchString(base) {
					t.Errorf("gitleaks allowlist %q matches the project directory", re)
				}
			}

			for _, rel := range tc.skipped {
				abs := base + "/" + rel
				byGitleaks, byBandit := false, false
				for _, re := range gitleaks {
					byGitleaks = byGitleaks || re.MatchString(abs)
				}
				for _, entry := range bandit {
					byBandit = byBandit || banditDrops(abs, entry)
				}
				if !byGitleaks || !byBandit || !trivySkips(base, rel, trivyDirs, trivyFiles) {
					t.Errorf("%s: skipped by gitleaks=%t bandit=%t trivy=%t; want all", rel, byGitleaks, byBandit, trivySkips(base, rel, trivyDirs, trivyFiles))
				}
			}
		})
	}
}

func TestToolArgsLeaveNegatedAndAmbiguousEntriesToThePostFilter(t *testing.T) {
	root := writeProject(t, map[string]string{
		".aitriage.yaml": "ignore:\n  paths:\n    - generated/\n    - \"!generated/keep.go\"\n",
	})
	for _, arg := range SemgrepExcludeArgs(root) {
		if strings.Contains(arg, "generated") {
			t.Errorf("semgrep args %q carry an entry a negation re-includes from", SemgrepExcludeArgs(root))
		}
	}
	if !NewScopeFilter(root).InScope(filepath.Join(root, "generated/keep.go")) {
		t.Error("the negated entry must re-include generated/keep.go")
	}

	root = writeProject(t, map[string]string{
		".aitriage.yaml": "ignore:\n  paths:\n    - \"file?.py\"\n    - \"[ab]/\"\n    - plain/\n",
	})
	semgrep := strings.Join(SemgrepExcludeArgs(root), " ")
	if strings.Contains(semgrep, "file?.py") || strings.Contains(semgrep, "[ab]") || !strings.Contains(semgrep, "plain/") {
		t.Errorf("semgrep args %q; want only the unambiguous entry", semgrep)
	}
}

// A project located under a directory named like a vendored one ("dist",
// "vendor", or Bitbucket Pipelines' ".../agent/build") used to lose every
// external finding: the whole absolute path was searched for vendored names.
func TestScopeJudgesDirectoryNamesInsideTheProjectOnly(t *testing.T) {
	for _, layout := range []string{"dist", "vendor/app", "node_modules/app", "opt/atlassian/pipelines/agent/build"} {
		t.Run(layout, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), filepath.FromSlash(layout))
			if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
				t.Fatal(err)
			}
			ResetScopeFilterCache()
			t.Cleanup(ResetScopeFilterCache)
			filter := NewScopeFilter(root)

			kept := FilterOutOfScope(root, []UnifiedFinding{
				{Source: "semgrep", RuleID: "own", File: filepath.Join(root, "src", "main.go"), Line: 1},
				{Source: "semgrep", RuleID: "vendored", File: filepath.Join(root, "vendor", "lib.go"), Line: 1},
			})
			if len(kept) != 1 || kept[0].RuleID != "own" {
				t.Errorf("kept %+v; want the project's own finding and not the vendored one", kept)
			}
			if !filter.DirInScope(root) {
				t.Error("the project directory itself must be in scope")
			}
			for _, re := range compileAll(t, gitleaksAllowlistPaths(root)) {
				if re.MatchString(filepath.ToSlash(root)) || re.MatchString(filepath.ToSlash(filepath.Join(root, "main.go"))) {
					t.Errorf("gitleaks allowlist %q would skip the project", re)
				}
			}
			for _, entry := range banditExcludePaths(root) {
				if banditDrops(filepath.ToSlash(filepath.Join(root, "main.py")), entry) {
					t.Errorf("bandit -x entry %q would drop the project's own file", entry)
				}
			}
		})
	}
}

// The same holds when a tool reports paths through the resolved root: the
// filter could not place them before, so every absolute segment was judged.
func TestScopeRecognisesTheSymlinkResolvedRoot(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Join(base, "dist", "app")
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolved, ".aitriageignore"), []byte("/src/app/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "project-link")
	if err := os.Symlink(resolved, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	ResetScopeFilterCache()
	t.Cleanup(ResetScopeFilterCache)
	filter := NewScopeFilter(link)

	if !filter.InScope(filepath.Join(resolved, "src", "main.go")) {
		t.Error("a file reported through the resolved root was dropped")
	}
	if filter.InScope(filepath.Join(resolved, "src", "app", "x.py")) {
		t.Error("an anchored .aitriageignore entry did not apply to a path under the resolved root")
	}
}

// The container mount fallback looked for "/workspace/", "/src/" or "/app/"
// anywhere in a path, so a host path that merely contained one was cut at the
// wrong place and matched against the wrong patterns.
func TestContainerMountFallbackOnlyAppliesAtThePathStart(t *testing.T) {
	root := writeProject(t, map[string]string{".aitriageignore": "/app/\n"})
	filter := NewScopeFilter(root)

	if !filter.InScope("/home/dev/projects/src/app/main.py") {
		t.Error("a path with /src/ deeper inside was read as a container path")
	}
	if filter.InScope("/workspace/app/main.py") {
		t.Error("a path under the /workspace mount must be read relative to it")
	}
	if filter.InScope("/github/workspace/vendor/aws/api.json") {
		t.Error("a path under the GitHub Actions mount must be read relative to it")
	}
	if !filter.InScope("/github/workspace/src/app/main.py") {
		t.Error("src/app/ under the mount is not the ignored top-level app/")
	}
	if !filter.InScope(filepath.Join(root, "src", "app", "main.py")) {
		t.Error("src/app/ under the root is not the ignored top-level app/")
	}
}

// Go's standard layout keeps Dockerfiles and CI scripts in build/. A committed
// build directory is the project's own; generated output is git-ignored, and
// .gitignore still excludes it.
func TestCommittedBuildDirectoryIsInScope(t *testing.T) {
	root := writeProject(t, map[string]string{"build/package/Dockerfile": "FROM alpine\n"})
	kept := FilterOutOfScope(root, []UnifiedFinding{
		{Source: "semgrep", RuleID: "missing-user", File: filepath.Join(root, "build", "package", "Dockerfile"), Line: 1},
	})
	if len(kept) != 1 {
		t.Error("a finding in build/package/Dockerfile was dropped as vendored code")
	}
	if containsPair(SemgrepExcludeArgs(root), "--exclude", "build") || containsPair(TrivySkipDirArgs(root), "--skip-dirs", "**/build") {
		t.Error("the tools were still told to skip build/")
	}

	ignored := writeProject(t, map[string]string{".gitignore": "build/\n"})
	if NewScopeFilter(ignored).InScope(filepath.Join(ignored, "build", "bundle.js")) {
		t.Error("git-ignored build output must stay out of scope")
	}
}

// Long-running processes keep the filter cached; editing the configuration
// must still take effect on the next scan.
func TestScopeFilterPicksUpConfigurationChanges(t *testing.T) {
	root := writeProject(t, map[string]string{"main.py": "print(1)\n"})
	target := filepath.Join(root, "generated", "client.py")

	if !NewScopeFilter(root).InScope(target) {
		t.Fatal("nothing is ignored yet")
	}
	if err := os.WriteFile(filepath.Join(root, ".aitriage.yaml"), []byte("ignore:\n  paths: [generated/]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if NewScopeFilter(root).InScope(target) {
		t.Error("a cached filter ignored a new ignore.paths entry")
	}
}

func TestDirInScopePrunesOnlyWhenNothingBelowCanReturn(t *testing.T) {
	root := writeProject(t, map[string]string{".gitignore": "coverage/\n"})
	if NewScopeFilter(root).DirInScope(filepath.Join(root, "coverage")) {
		t.Error("a directory .gitignore excludes must be pruned")
	}

	root = writeProject(t, map[string]string{".gitignore": "coverage/*\n!coverage/keep.txt\n"})
	filter := NewScopeFilter(root)
	if !filter.DirInScope(filepath.Join(root, "coverage")) {
		t.Error("with a negated pattern the walker must descend")
	}
	if filter.InScope(filepath.Join(root, "coverage", "lcov.info")) {
		t.Error("files under the ignored directory must stay out of scope")
	}
}

// Any "!" line in .gitignore used to stop every excluded directory from being
// pruned, so the common "!.vscode/settings.json" sent walkers into dist/,
// coverage/ and the rest. Only a negation that can re-include something below
// a directory keeps it from being pruned.
func TestDirInScopeIsNotDisabledByAnUnrelatedNegation(t *testing.T) {
	root := writeProject(t, map[string]string{
		".gitignore": "coverage/\nreports/\n.vscode/*\n!.vscode/settings.json\n",
	})
	filter := NewScopeFilter(root)
	for _, dir := range []string{"coverage", "reports", "src/coverage"} {
		if filter.DirInScope(filepath.Join(root, dir)) {
			t.Errorf("%s/ is excluded and no negation reaches below it; it must be pruned", dir)
		}
	}
	if !filter.DirInScope(filepath.Join(root, ".vscode")) || !filter.InScope(filepath.Join(root, ".vscode", "settings.json")) {
		t.Error(".vscode/settings.json is re-included and must be reachable")
	}
	if filter.InScope(filepath.Join(root, ".vscode", "launch.json")) {
		t.Error(".vscode/launch.json stays excluded")
	}

	root = writeProject(t, map[string]string{
		".aitriageignore": "generated/\n!generated/keep.go\n",
		".aitriage.yaml":  "ignore:\n  paths:\n    - \"infra/\"\n    - \"!infra/prod/\"\n",
	})
	filter = NewScopeFilter(root)
	for dir, want := range map[string]bool{"generated": true, "infra": true, "infra/prod": true, "infra/dev": false} {
		if got := filter.DirInScope(filepath.Join(root, dir)); got != want {
			t.Errorf("DirInScope(%s) = %t; want %t", dir, got, want)
		}
	}
}

// .gitignore and .aitriageignore follow git's anchoring too: a pattern with a
// slash in the middle names a path from the project root.
func TestIgnoreFilesAnchorPatternsWithASlashInTheMiddle(t *testing.T) {
	root := writeProject(t, map[string]string{
		".gitignore":      "config/settings_local.py\n",
		".aitriageignore": "app/legacy/\n",
	})
	filter := NewScopeFilter(root)
	for rel, want := range map[string]bool{
		"config/settings_local.py":               false,
		"src/config/settings_local.py":           true,
		"app/legacy/handler.py":                  false,
		"services/billing/app/legacy/handler.py": true,
	} {
		if got := filter.InScope(filepath.Join(root, rel)); got != want {
			t.Errorf("InScope(%s) = %t; want %t", rel, got, want)
		}
	}
}

// A walker trusts DirInScope to skip a whole tree, so a directory it prunes
// must hold nothing InScope would keep.
func TestDirInScopeNeverPrunesAnInScopePath(t *testing.T) {
	files := []string{
		"infra/prod/Dockerfile", "infra/dev/Dockerfile", "deploy/prod/Dockerfile", "deploy/dev/Dockerfile",
		"generated/keep.go", "generated/other.go", "src/generated/keep.go", "logs/keep.log", "logs/app.log",
		"docs/a/examples/e.py", "docs/b/x.md", "app/legacy/h.py", "src/app/legacy/h.py", ".vscode/settings.json",
		".vscode/launch.json", "coverage/lcov.info", "main.go",
	}
	configs := []map[string]string{
		{".gitignore": "deploy/*\n!deploy/prod/\ncoverage/\n.vscode/*\n!.vscode/settings.json\n"},
		{".gitignore": "logs/\n!keep.log\n", ".aitriageignore": "docs/\n!docs/**/examples/\n"},
		{".aitriage.yaml": "ignore:\n  paths:\n    - \"infra/\"\n    - \"!infra/prod/\"\n    - generated/\n    - \"!**/keep.go\"\n"},
		{".aitriageignore": "app/legacy/\n*\n!*/\n!*.go\n"},
	}
	for i, ignoreFiles := range configs {
		project := map[string]string{}
		for _, file := range files {
			project[file] = "x\n"
		}
		for name, content := range ignoreFiles {
			project[name] = content
		}
		root := writeProject(t, project)
		filter := NewScopeFilter(root)
		for _, file := range files {
			for dir := filepath.Dir(file); dir != "."; dir = filepath.Dir(dir) {
				if !filter.DirInScope(filepath.Join(root, dir)) && filter.InScope(filepath.Join(root, file)) {
					t.Errorf("config %d: %s is in scope but DirInScope(%s) prunes it", i, file, dir)
				}
			}
		}
	}
}

func containsPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func compileAll(t *testing.T, patterns []string) []*regexp.Regexp {
	t.Helper()
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("allowlist pattern %q does not compile: %v", p, err)
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// banditDrops emulates Bandit's exclusion test for a file path: an fnmatch
// match ("*" crosses "/") or a plain substring. An entry naming an existing
// directory becomes "<entry>/*" first, so both forms are checked.
func banditDrops(path, entry string) bool {
	for _, candidate := range []string{entry, strings.TrimSuffix(entry, "/") + "/*"} {
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(candidate), `\*`, ".*") + "$"
		if regexp.MustCompile(pattern).MatchString(path) {
			return true
		}
	}
	return strings.Contains(path, entry)
}

func splitTrivyArgs(args []string) (dirs, files []string) {
	for i := 0; i+1 < len(args); i += 2 {
		switch args[i] {
		case "--skip-dirs":
			dirs = append(dirs, args[i+1])
		case "--skip-files":
			files = append(files, args[i+1])
		}
	}
	return dirs, files
}

// trivySkips emulates Trivy's walker: absolute skip paths are made relative to
// the target, a directory matching --skip-dirs is skipped with everything below
// it, and a file matching --skip-files is skipped.
func trivySkips(base, rel string, dirs, files []string) bool {
	match := func(pattern, path string) bool {
		pattern = strings.TrimPrefix(filepath.ToSlash(pattern), base+"/")
		return doublestarRegex(pattern).MatchString(path)
	}
	segments := strings.Split(rel, "/")
	for i := 1; i < len(segments); i++ {
		dir := strings.Join(segments[:i], "/")
		for _, p := range dirs {
			if match(p, dir) {
				return true
			}
		}
	}
	for _, p := range files {
		if match(p, rel) {
			return true
		}
	}
	return false
}

func doublestarRegex(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString(`(?:[^/]+/)*`)
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(`.*`)
			i++
		case pattern[i] == '*':
			b.WriteString(`[^/]*`)
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
