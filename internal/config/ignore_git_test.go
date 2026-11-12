package config

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// gitTree is the project every pattern set is checked against. Most paths come
// in pairs: one a pattern is about, and a near miss it must leave alone.
var gitTree = []string{
	"app/legacy/handler.py",
	"services/billing/app/legacy/handler.py",
	"config/settings_local.py",
	"src/config/settings_local.py",
	"build/out.js",
	"src/build/out.js",
	"generated/client.py",
	"generated/sub/deep.py",
	"src/generated/client.py",
	"legacy/old.py",
	"legacy/sub/older.py",
	"src/legacy/old.py",
	"static/app.min.js",
	"app.min.js",
	"docs/guide.md",
	"docs/examples/e.py",
	"docs/a/examples/e.py",
	"lib/docs/a/examples/x.py",
	"fixtures/f.json",
	"src/fixtures/f.json",
	"fixturesdir/c.json",
	"foo/bar/x.txt",
	"foo/y.txt",
	"a/b/c/d.txt",
	"x/a/b/c.txt",
	"file1.txt",
	"file12.txt",
	"dir/file2.txt",
	"abc/def.txt",
	"bbc/def.txt",
	"zbc/def.txt",
	"deploy/prod/Dockerfile",
	"deploy/dev/Dockerfile",
	"logs/app.log",
	"logs/keep.log",
	"coverage/lcov.info",
	"coverage/keep.txt",
	"infra/prod/Dockerfile",
	"infra/dev/Dockerfile",
	"vendor/lib.go",
	"src/vendors/api.py",
	"#hash.txt",
	"!bang.txt",
}

// gitPatternCases cover anchoring, trailing slashes, "**", "*" against "/",
// "?", brackets, escapes and negation.
var gitPatternCases = []struct {
	name  string
	lines []string
	// reincluded are paths git keeps ignored because a directory above them
	// is excluded, while PathMatcher applies the negation (see PathMatcher).
	reincluded []string
}{
	{name: "anchored directory", lines: []string{"app/legacy/"}},
	{name: "anchored path", lines: []string{"app/legacy"}},
	{name: "anchored file", lines: []string{"config/settings_local.py"}},
	{name: "leading slash", lines: []string{"/build/"}},
	{name: "unanchored directory", lines: []string{"build/"}},
	{name: "unanchored name", lines: []string{"legacy"}},
	{name: "anchored star", lines: []string{"generated/*"}},
	{name: "anchored star with extension", lines: []string{"legacy/*.py"}},
	{name: "unanchored glob", lines: []string{"*.min.js"}},
	{name: "double star in the middle", lines: []string{"docs/**/examples"}},
	{name: "double star in the middle to a file", lines: []string{"a/**/d.txt"}},
	{name: "leading double star", lines: []string{"**/fixtures/"}},
	{name: "leading double star with a path", lines: []string{"**/b/c"}},
	{name: "trailing double star", lines: []string{"foo/**"}},
	{name: "trailing double star directories", lines: []string{"foo/**/"}},
	{name: "double star alone", lines: []string{"**"}},
	{name: "star does not cross a slash", lines: []string{"*/b"}},
	{name: "star between slashes", lines: []string{"a/*/c"}},
	{name: "question mark", lines: []string{"file?.txt"}},
	{name: "bracket range", lines: []string{"[a-c]bc/"}},
	{name: "negated bracket", lines: []string{"[!a]bc/"}},
	{name: "escaped hash and bang", lines: []string{`\#hash.txt`, `\!bang.txt`}},
	{name: "comments and blank lines", lines: []string{"# vendor/", "", "vendor/"}},
	{name: "negation re-includes a directory", lines: []string{"deploy/*", "!deploy/prod/"}},
	{name: "negation by name", lines: []string{"*.log", "!keep.log"}},
	{name: "negation of a file", lines: []string{"coverage/*", "!coverage/keep.txt"}},
	{name: "negation before the pattern", lines: []string{"!vendor/lib.go", "vendor/"}},
	{
		name:       "negation below an excluded directory",
		lines:      []string{"infra/", "!infra/prod/"},
		reincluded: []string{"infra/prod", "infra/prod/Dockerfile"},
	},
	{
		name:       "negation by name below an excluded directory",
		lines:      []string{"logs/", "!keep.log"},
		reincluded: []string{"logs/keep.log"},
	},
}

// The matcher is checked against git itself: each pattern set becomes the
// .gitignore of a scratch repository, and `git check-ignore` decides every
// file and directory of gitTree. The same patterns are also checked as
// ignore.paths entries, which must read exactly like .gitignore lines.
func TestPathMatcherAgreesWithGitCheckIgnore(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, nil, "init", "-q")
	// macOS and Windows repositories default to case-insensitive matching;
	// the matcher, like git on Linux, is case-sensitive.
	runGit(t, repo, nil, "config", "core.ignorecase", "false")
	dirs := map[string]bool{}
	for _, file := range gitTree {
		full := filepath.Join(repo, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for dir := path.Dir(file); dir != "."; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	paths := append([]string(nil), gitTree...)
	for dir := range dirs {
		paths = append(paths, dir)
	}
	sort.Strings(paths)

	for _, tc := range gitPatternCases {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Join(tc.lines, "\n") + "\n"
			if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			ignoredByGit := gitCheckIgnore(t, repo, paths)
			reincluded := map[string]bool{}
			for _, p := range tc.reincluded {
				reincluded[p] = true
			}
			file := ParseIgnoreFile(content)
			entries := NewPathMatcher(tc.lines)

			for _, p := range paths {
				want := ignoredByGit[p]
				if reincluded[p] {
					if !want {
						t.Errorf("%s: git no longer keeps it ignored; drop it from reincluded", p)
					}
					want = false
				}
				if got := file.Excludes(p, dirs[p]); got != want {
					t.Errorf("%q: Excludes(%s) = %t; git says %t", tc.lines, p, got, want)
				}
				if got := entries.Excludes(p, dirs[p]); got != want {
					t.Errorf("%q as ignore.paths: Excludes(%s) = %t; git says %t", tc.lines, p, got, want)
				}
			}
			// A directory the matcher lets a walker skip must hold nothing
			// in scope.
			for dir := range dirs {
				if !file.ExcludesTree(dir) {
					continue
				}
				for _, p := range paths {
					if strings.HasPrefix(p, dir+"/") && !file.Excludes(p, dirs[p]) {
						t.Errorf("%q: ExcludesTree(%s) but %s below it is in scope", tc.lines, dir, p)
					}
				}
			}
		})
	}
}

// gitCheckIgnore returns which paths git ignores.
func gitCheckIgnore(t *testing.T, repo string, paths []string) map[string]bool {
	t.Helper()
	input := strings.Join(paths, "\x00") + "\x00"
	out := runGit(t, repo, []byte(input), "check-ignore", "--no-index", "--stdin", "-z", "-v", "-n")
	// -z -v -n prints source, line, pattern and path for every path; a path no
	// pattern matches has an empty source, and one a negated pattern matches
	// last is not ignored.
	fields := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(fields) != 4*len(paths) {
		t.Fatalf("unexpected git check-ignore output: %q", out)
	}
	ignored := map[string]bool{}
	for i := 0; i < len(fields); i += 4 {
		source, pattern, p := fields[i], fields[i+2], fields[i+3]
		ignored[p] = source != "" && !strings.HasPrefix(pattern, "!")
	}
	return ignored
}

// runGit runs git in repo, isolated from the user's and the system's
// configuration so a global excludes file cannot change the answer.
func runGit(t *testing.T, repo string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"HOME="+repo,
		"XDG_CONFIG_HOME="+repo,
	)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	// check-ignore exits 1 when no path is ignored.
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 && args[0] == "check-ignore" {
		err = nil
	}
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}
