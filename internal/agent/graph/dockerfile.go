package graph

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// ── Locating project-level findings ──────────────────────────────────────────
//
// The built-in DOCKER-NO-USER rule is evaluated per project ("no Dockerfile
// contains USER") and reports no file, while Semgrep (missing-user) and Trivy
// (DS-0002) report the same defect on the Dockerfile itself. A finding without
// a location cannot merge with them and reads "N/A" in every report. When the
// project leaves exactly one candidate, the finding is given that file. The
// scanner's own report is untouched: its origin keeps the project-level
// location, so baselines and recorded decisions keep matching it.

// dockerUserInstruction is the pattern DOCKER-NO-USER requires
// (rules/docker/security.yaml).
var dockerUserInstruction = regexp.MustCompile(`(?m)^USER\s+`)

// maxDockerfileBytes bounds what is read per candidate Dockerfile.
const maxDockerfileBytes = 1 << 20

// locateProjectLevelFindings gives a file to built-in project-level findings
// of a file-scoped class when it can be determined.
func locateProjectLevelFindings(projectPath string, findings []EnrichedFinding) {
	located := false
	var file string
	var line int
	for i := range findings {
		f := &findings[i]
		if f.File != "" || f.Line != 0 || !strings.EqualFold(f.Type, "core") {
			continue
		}
		if class, ok := findingClass(*f); !ok || class.Key != healthcheck.ClassContainerRunsAsRoot {
			continue
		}
		if !located {
			file, line = dockerfileWithoutUser(projectPath)
			located = true
		}
		if file == "" {
			return
		}
		f.File, f.Line = file, line
		f.Snippet = extractFullContext(projectPath, file, line)
	}
}

// dockerfileWithoutUser returns the only in-scope Dockerfile of the project
// that has no USER instruction, project-relative, with the line a reader
// should look at: the last CMD or ENTRYPOINT, else the last FROM. It returns
// "" when there is no such file or more than one.
func dockerfileWithoutUser(projectPath string) (string, int) {
	root := projectPath
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	scope := external.NewScopeFilter(root)
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && !scope.DirInScope(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		// The rule examines files named exactly Dockerfile.
		if !strings.EqualFold(d.Name(), "dockerfile") || !d.Type().IsRegular() || !scope.InScope(rel) {
			return nil
		}
		if data, ok := readBounded(path, maxDockerfileBytes); ok && !dockerUserInstruction.Match(data) {
			found = append(found, path)
		}
		if len(found) > 1 {
			return filepath.SkipAll
		}
		return nil
	})
	if len(found) != 1 {
		return "", 0
	}
	rel, err := filepath.Rel(root, found[0])
	if err != nil {
		return "", 0
	}
	return filepath.ToSlash(rel), dockerfileFocusLine(found[0])
}

// dockerfileFocusLine is the last CMD or ENTRYPOINT line, else the last FROM
// line, else 0.
func dockerfileFocusLine(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileBytes)
	run, from, n := 0, 0, 0
	for scanner.Scan() {
		n++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "CMD", "ENTRYPOINT":
			run = n
		case "FROM":
			from = n
		}
	}
	if run > 0 {
		return run
	}
	return from
}

func readBounded(path string, limit int64) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, false
	}
	data, err := os.ReadFile(path)
	return data, err == nil
}
