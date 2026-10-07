package detector

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

type Stack string

const (
	NextJS       Stack = "nextjs"
	FastAPI      Stack = "fastapi"
	Flask        Stack = "flask"
	Express      Stack = "express"
	Django       Stack = "django"
	AspNetCore   Stack = "aspnetcore"
	Go           Stack = "go"
	Universal    Stack = "universal"
	UnknownStack Stack = "unknown"
)

type scoreCard struct {
	scores map[Stack]int
}

// DetectProjects attempts to identify all technology stacks and their bounding boxes (ProjectContexts).
// It use a weighted scoring system to find project roots.
func DetectProjects(ws *core.Workspace) []*core.ProjectContext {
	dirScores := make(map[string]*scoreCard)

	// Step 1: Accumulate scores for each directory based on its files
	for _, f := range ws.Files {
		// Test, mock, fixture, and spec files are intentionally outside the
		// production audit surface. They must not activate a framework rule pack:
		// a fixture package.json under testdata/, for example, must not make an
		// otherwise unrelated repository look like a Next.js project.
		if f.IsTest {
			continue
		}
		dir := filepath.Dir(f.Path)
		base := filepath.Base(f.Path)

		if _, ok := dirScores[dir]; !ok {
			dirScores[dir] = &scoreCard{scores: make(map[Stack]int)}
		}
		sc := dirScores[dir]

		// Node.js / JS
		if base == "package.json" {
			if hasPackageJSONWithDep(f, "next") {
				sc.scores[NextJS] += 100
			} else if hasPackageJSONWithDep(f, "express") && hasExpressRuntimeImport(ws.Files, dir) {
				sc.scores[Express] += 100
			} else {
				sc.scores[UnknownStack] += 50 // Generic Node project
			}
		}
		if base == "next.config.js" || base == "next.config.mjs" {
			sc.scores[NextJS] += 80
		}
		if base == "tsconfig.json" {
			sc.scores[UnknownStack] += 20 // Suggests a JS/TS project
		}

		// Python — handle both root requirements.txt AND monorepo layouts (requirements/*.txt, *.in, uv.lock)
		isPythonDepFile := base == "requirements.txt" || base == "pyproject.toml" || base == "Pipfile" ||
			(strings.HasSuffix(base, ".txt") && strings.Contains(filepath.Dir(f.Path), "requirements")) ||
			(strings.HasSuffix(base, ".in") && strings.Contains(filepath.Dir(f.Path), "requirements"))
		if isPythonDepFile {
			if hasPythonDep(f, "fastapi") {
				sc.scores[FastAPI] += 100
			} else if hasPythonDep(f, "django") {
				sc.scores[Django] += 100
			} else if hasPythonDep(f, "flask") {
				sc.scores[Flask] += 100
			} else {
				sc.scores[UnknownStack] += 50
			}
		}
		// Fallback: scan .py files for framework imports when no requirements found
		if f.Extension == ".py" && (base == "main.py" || base == "app.py" || base == "asgi.py") {
			if hasPythonDep(f, "from fastapi") || hasPythonDep(f, "import fastapi") {
				sc.scores[FastAPI] += 80
			} else if hasPythonDep(f, "from django") || hasPythonDep(f, "import django") {
				sc.scores[Django] += 80
			} else if hasPythonDep(f, "from flask") || hasPythonDep(f, "import flask") {
				sc.scores[Flask] += 80
			}
		}
		if base == "manage.py" {
			sc.scores[Django] += 90
		}

		// .NET
		if strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") {
			if hasDotnetDep(f, "Microsoft.AspNetCore") || hasDotnetWebSDK(f) {
				sc.scores[AspNetCore] += 100
			}
		}

		// Go
		if base == "go.mod" {
			sc.scores[Go] += 100
		}
	}

	var projects []*core.ProjectContext

	// Step 2: Identify winning stacks for each directory
	for dir, sc := range dirScores {
		var topStack Stack
		topScore := 0
		for s, score := range sc.scores {
			if score > topScore {
				topScore = score
				topStack = s
			}
		}

		if topScore >= 80 {
			projects = append(projects, &core.ProjectContext{
				RootPath: dir,
				ScanRoot: ws.RootPath,
				Stack:    string(topStack),
				Config:   ws.Config,
			})
		} else if topScore >= 50 && topStack == UnknownStack {
			// If it's just a generic project, we still mark it
			projects = append(projects, &core.ProjectContext{
				RootPath: dir,
				ScanRoot: ws.RootPath,
				Stack:    string(UnknownStack),
				Config:   ws.Config,
			})
		}
	}

	// If nothing was detected at all, create a Universal fallback project
	if len(projects) == 0 {
		projects = append(projects, &core.ProjectContext{
			RootPath: ws.RootPath,
			ScanRoot: ws.RootPath,
			Stack:    string(UnknownStack),
			Config:   ws.Config,
		})
	}

	// Step 3: Assign files to the closest project root
	for _, f := range ws.Files {
		// Keep the same policy for rule execution as for stack detection. The
		// workspace still indexes these files (and reports them in TotalFiles), but
		// no deterministic production finding is created from their contents.
		if f.IsTest {
			continue
		}
		var bestProject *core.ProjectContext
		bestLen := -1

		for _, p := range projects {
			if isSubPath(f.Path, p.RootPath) {
				pathLen := len(p.RootPath)
				if pathLen > bestLen {
					bestLen = pathLen
					bestProject = p
				}
			}
		}

		if bestProject != nil {
			bestProject.Files = append(bestProject.Files, f)
		}
	}

	return projects
}

func isSubPath(path, rootPath string) bool {
	if path == rootPath {
		return true
	}
	return strings.HasPrefix(path, rootPath+string(filepath.Separator))
}

func hasPackageJSONWithDep(f *core.FileInfo, dep string) bool {
	content, err := f.GetContent()
	if err != nil {
		return false
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return false
	}
	_, hasDep := pkg.Dependencies[dep]
	_, hasDevDep := pkg.DevDependencies[dep]
	return hasDep || hasDevDep
}

var expressRuntimeImport = regexp.MustCompile(`(?m)(?:\bfrom\s*["']express["']|\brequire\s*\(\s*["']express["']\s*\))`)

// hasExpressRuntimeImport prevents a transitive or unused express dependency
// from activating the full Express rule pack for a frontend-only project.
func hasExpressRuntimeImport(files []*core.FileInfo, projectRoot string) bool {
	for _, f := range files {
		if !isSubPath(f.Path, projectRoot) {
			continue
		}
		switch f.Extension {
		case ".js", ".cjs", ".mjs", ".ts", ".tsx":
		default:
			continue
		}
		content, err := f.GetContent()
		if err == nil && expressRuntimeImport.Match(content) {
			return true
		}
	}
	return false
}

func hasPythonDep(f *core.FileInfo, dep string) bool {
	content, err := f.GetContent()
	if err != nil {
		return false
	}
	strContent := strings.ToLower(string(content))
	return strings.Contains(strContent, strings.ToLower(dep))
}

func hasDotnetDep(f *core.FileInfo, dep string) bool {
	content, err := f.GetContent()
	if err != nil {
		return false
	}
	strContent := string(content)
	return strings.Contains(strContent, "PackageReference") && strings.Contains(strContent, dep)
}

func hasDotnetWebSDK(f *core.FileInfo) bool {
	content, err := f.GetContent()
	if err != nil {
		return false
	}
	strContent := string(content)
	return strings.Contains(strContent, `Sdk="Microsoft.NET.Sdk.Web"`) || strings.Contains(strContent, `Sdk='Microsoft.NET.Sdk.Web'`)
}
