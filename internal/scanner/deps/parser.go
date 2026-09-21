package deps

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

var goModLineRegex = regexp.MustCompile(`^\s*([a-zA-Z0-9\.\-\/\_]+)\s+v([a-zA-Z0-9\.\-\+]+)(\s+// indirect)?`)
var gemfileRegex = regexp.MustCompile(`gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
var requirementsRegex = regexp.MustCompile(`^([a-zA-Z0-9\.\-\_]+)(==|>=|<=|>|<|~=)(.*)`)

type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`      // "prod", "dev", "indirect", "root"
	Ecosystem string `json:"ecosystem"` // "npm", "go", "pypi", etc.
}

type DependencyGraph struct {
	Nodes []Dependency
	Edges map[string][]string // Parent ID -> []Children (IDs)
}

func (d Dependency) ID() string {
	name := d.Name
	if d.Version != "" && d.Version != "unknown" && d.Version != "latest" {
		// Normalize version for ID purposes: remove range prefixes
		ver := d.Version
		ver = strings.TrimPrefix(ver, "^")
		ver = strings.TrimPrefix(ver, "~")
		ver = strings.TrimPrefix(ver, ">=")
		ver = strings.TrimPrefix(ver, "<=")

		// For Go, versions usually start with 'v'.
		// For consistency in graph matching, we ensure 'v' prefix for Go ecosystem.
		if d.Ecosystem == "go" && !strings.HasPrefix(ver, "v") && ver != "" {
			ver = "v" + ver
		}

		return name + "@" + ver
	}
	return name
}

func GenerateGraph(ws *core.Workspace) DependencyGraph {
	graph := DependencyGraph{
		Edges: make(map[string][]string),
	}

	var manifestDeps []Dependency

	// 1. Initial nodes and static edges from manifest files
	for _, f := range ws.Files {
		dir := filepath.Dir(f.Path)
		if strings.HasSuffix(f.Path, "package.json") {
			deps, rootID := parsePackageJSON(f, dir, &graph)
			manifestDeps = append(manifestDeps, deps...)
			parseNPMGraph(dir, rootID, &graph)
		} else if strings.HasSuffix(f.Path, "go.mod") {
			deps, rootID := parseGoMod(f, dir, &graph)
			manifestDeps = append(manifestDeps, deps...)
			parseGoGraph(dir, rootID, &graph)
		} else if strings.HasSuffix(f.Path, "requirements.txt") {
			deps, _ := parseRequirementsTxt(f, dir, &graph)
			manifestDeps = append(manifestDeps, deps...)
		} else if strings.HasSuffix(f.Path, "composer.json") {
			deps, _ := parseComposerJSON(f, dir, &graph)
			manifestDeps = append(manifestDeps, deps...)
		} else if strings.HasSuffix(f.Path, "Gemfile") {
			deps, _ := parseGemfile(f, dir, &graph)
			manifestDeps = append(manifestDeps, deps...)
		} else if strings.HasSuffix(f.Path, "Cargo.toml") {
			deps, _ := parseCargoToml(f, dir, &graph)
			manifestDeps = append(manifestDeps, deps...)
		}
	}

	// 2. Normalization and Reconcilliation
	finalNodes := make(map[string]Dependency)

	// Pre-populate with manifest dependencies (they have Type info)
	for _, d := range manifestDeps {
		finalNodes[d.ID()] = d
	}

	// Ensure all nodes referenced in edges exist
	// Also deduplicate edges
	dedupedEdges := make(map[string][]string)

	for parent, children := range graph.Edges {
		ensureNodeExists(parent, &finalNodes)
		seen := make(map[string]bool)
		for _, child := range children {
			if !seen[child] {
				ensureNodeExists(child, &finalNodes)
				dedupedEdges[parent] = append(dedupedEdges[parent], child)
				seen[child] = true
			}
		}
	}
	graph.Edges = dedupedEdges

	// Convert map back to slice
	graph.Nodes = make([]Dependency, 0, len(finalNodes))
	for _, node := range finalNodes {
		graph.Nodes = append(graph.Nodes, node)
	}

	return graph
}

func ensureNodeExists(id string, nodes *map[string]Dependency) {
	if _, exists := (*nodes)[id]; exists {
		return
	}

	newNode := createSyntheticNode(id)

	for _, existingNode := range *nodes {
		if existingNode.Name == newNode.Name {
			newNode.Type = existingNode.Type
			newNode.Ecosystem = existingNode.Ecosystem
			break
		}
	}

	(*nodes)[id] = newNode
}

func parseGoGraph(dir string, rootID string, graph *DependencyGraph) {
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return
	}

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			parent := parts[0]
			child := parts[1]
			graph.Edges[parent] = append(graph.Edges[parent], child)
		}
	}
}

func parseNPMGraph(dir string, rootID string, graph *DependencyGraph) {
	cmd := exec.Command("npm", "list", "--all", "--json")
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return
	}

	var data interface{}
	if err := json.Unmarshal(out.Bytes(), &data); err != nil {
		return
	}

	var traverse func(string, interface{})
	traverse = func(parent string, node interface{}) {
		m, ok := node.(map[string]interface{})
		if !ok {
			return
		}

		deps, ok := m["dependencies"].(map[string]interface{})
		if !ok {
			return
		}

		for name, details := range deps {
			child := name
			if d, ok := details.(map[string]interface{}); ok {
				if v, ok := d["version"].(string); ok {
					child = name + "@" + v
				}
			}
			graph.Edges[parent] = append(graph.Edges[parent], child)
			traverse(child, details)
		}
	}

	if m, ok := data.(map[string]interface{}); ok {
		traverse(rootID, m)
	}
}

func getFallbackName(dir string) string {
	name := filepath.Base(dir)
	if name == "." || name == "" {
		name = "project-root"
	}
	return name
}

func parsePackageJSON(f *core.FileInfo, dir string, graph *DependencyGraph) ([]Dependency, string) {
	content, err := f.GetContent()
	if err != nil {
		return nil, ""
	}

	var pkg struct {
		Name             string            `json:"name"`
		Version          string            `json:"version"`
		Dependencies     map[string]string `json:"dependencies"`
		DevDependencies  map[string]string `json:"devDependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}

	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, ""
	}

	name := pkg.Name
	if name == "" {
		name = getFallbackName(dir)
	}

	rootDep := Dependency{Name: name, Version: pkg.Version, Type: "root", Ecosystem: "npm"}
	var deps []Dependency
	deps = append(deps, rootDep)
	rootID := rootDep.ID()

	addDep := func(depName, depVer, depType string) {
		dep := Dependency{Name: depName, Version: depVer, Type: depType, Ecosystem: "npm"}
		deps = append(deps, dep)
		graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
	}

	for n, v := range pkg.Dependencies {
		addDep(n, v, "prod")
	}
	for n, v := range pkg.DevDependencies {
		addDep(n, v, "dev")
	}
	for n, v := range pkg.PeerDependencies {
		addDep(n, v, "peer")
	}

	return deps, rootID
}

func parseGoMod(f *core.FileInfo, dir string, graph *DependencyGraph) ([]Dependency, string) {
	content, err := f.GetContent()
	if err != nil {
		return nil, ""
	}

	var deps []Dependency
	lines := strings.Split(string(content), "\n")

	re := goModLineRegex

	moduleName := ""
	inRequireBlock := false

	// First pass to find module name
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			moduleName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			break
		}
	}

	if moduleName == "" {
		moduleName = getFallbackName(dir)
	}

	rootDep := Dependency{Name: moduleName, Version: "", Type: "root", Ecosystem: "go"}
	deps = append(deps, rootDep)
	rootID := rootDep.ID()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "go ") || strings.HasPrefix(line, "module ") {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequireBlock {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			name := matches[1]
			ver := matches[2]
			typ := "prod"
			if len(matches) > 3 && strings.Contains(matches[3], "indirect") {
				typ = "indirect"
			}
			dep := Dependency{Name: name, Version: "v" + ver, Type: typ, Ecosystem: "go"}
			deps = append(deps, dep)
			graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
		}
	}

	return deps, rootID
}

func parseComposerJSON(f *core.FileInfo, dir string, graph *DependencyGraph) ([]Dependency, string) {
	content, err := f.GetContent()
	if err != nil {
		return nil, ""
	}
	var pkg struct {
		Name       string            `json:"name"`
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, ""
	}

	name := pkg.Name
	if name == "" {
		name = getFallbackName(dir)
	}

	rootDep := Dependency{Name: name, Version: "", Type: "root", Ecosystem: "php"}
	var deps []Dependency
	deps = append(deps, rootDep)
	rootID := rootDep.ID()

	// composer.json holds version constraints ("^7.2"); composer.lock holds the
	// versions actually installed. Prefer the lockfile so the SBOM and any CVE
	// matching describe what ships, not what is merely allowed.
	resolved := parseComposerLock(dir)

	addDep := func(depName, depVer, depType string) {
		if locked, ok := resolved[depName]; ok && locked != "" {
			depVer = locked
		}
		dep := Dependency{Name: depName, Version: depVer, Type: depType, Ecosystem: "php"}
		deps = append(deps, dep)
		graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
	}

	for n, v := range pkg.Require {
		addDep(n, v, "prod")
	}
	for n, v := range pkg.RequireDev {
		addDep(n, v, "dev")
	}

	// Transitive packages appear only in the lockfile. Without them the PHP
	// inventory would list a handful of direct requirements and miss the tree
	// that is actually deployed.
	declared := make(map[string]bool, len(pkg.Require)+len(pkg.RequireDev))
	for n := range pkg.Require {
		declared[n] = true
	}
	for n := range pkg.RequireDev {
		declared[n] = true
	}
	for depName, depVer := range resolved {
		if declared[depName] {
			continue
		}
		dep := Dependency{Name: depName, Version: depVer, Type: "transitive", Ecosystem: "php"}
		deps = append(deps, dep)
		graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
	}

	return deps, rootID
}

// parseComposerLock reads the resolved package versions from composer.lock.
// A missing or unreadable lockfile is not an error here: the caller falls back
// to the constraints declared in composer.json.
func parseComposerLock(dir string) map[string]string {
	content, err := os.ReadFile(filepath.Join(dir, "composer.lock"))
	if err != nil {
		return nil
	}

	var lock struct {
		Packages    []composerLockPackage `json:"packages"`
		PackagesDev []composerLockPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil
	}

	resolved := make(map[string]string, len(lock.Packages)+len(lock.PackagesDev))
	for _, group := range [][]composerLockPackage{lock.Packages, lock.PackagesDev} {
		for _, entry := range group {
			if entry.Name == "" {
				continue
			}
			resolved[entry.Name] = strings.TrimPrefix(entry.Version, "v")
		}
	}
	return resolved
}

type composerLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseGemfile(f *core.FileInfo, dir string, graph *DependencyGraph) ([]Dependency, string) {
	content, err := f.GetContent()
	if err != nil {
		return nil, ""
	}

	name := getFallbackName(dir)
	rootDep := Dependency{Name: name, Version: "", Type: "root", Ecosystem: "ruby"}
	var deps []Dependency
	deps = append(deps, rootDep)
	rootID := rootDep.ID()

	lines := strings.Split(string(content), "\n")
	re := gemfileRegex
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			ver := "latest"
			if len(matches) >= 3 && matches[2] != "" {
				ver = matches[2]
			}
			dep := Dependency{Name: matches[1], Version: ver, Type: "prod", Ecosystem: "ruby"}
			deps = append(deps, dep)
			graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
		}
	}
	return deps, rootID
}

func parseCargoToml(f *core.FileInfo, dir string, graph *DependencyGraph) ([]Dependency, string) {
	content, err := f.GetContent()
	if err != nil {
		return nil, ""
	}

	lines := strings.Split(string(content), "\n")
	name := getFallbackName(dir)

	// Try to find package name
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if strings.TrimSpace(parts[0]) == "name" {
				name = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				break
			}
		}
	}

	rootDep := Dependency{Name: name, Version: "", Type: "root", Ecosystem: "rust"}
	var deps []Dependency
	deps = append(deps, rootDep)
	rootID := rootDep.ID()

	inDeps := false
	inDevDeps := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[dependencies]" {
			inDeps = true
			inDevDeps = false
			continue
		}
		if line == "[dev-dependencies]" {
			inDeps = false
			inDevDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDeps = false
			inDevDeps = true
			continue
		}
		if (inDeps || inDevDeps) && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			depName := strings.TrimSpace(parts[0])
			ver := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			typ := "prod"
			if inDevDeps {
				typ = "dev"
			}
			dep := Dependency{Name: depName, Version: ver, Type: typ, Ecosystem: "rust"}
			deps = append(deps, dep)
			graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
		}
	}
	return deps, rootID
}

func createSyntheticNode(id string) Dependency {
	lastAt := strings.LastIndex(id, "@")
	if lastAt > 0 && lastAt < len(id)-1 {
		name := id[:lastAt]
		ver := id[lastAt+1:]
		return Dependency{Name: name, Version: ver, Type: "indirect"}
	}
	return Dependency{Name: id, Version: "", Type: "indirect"}
}

func parseRequirementsTxt(f *core.FileInfo, dir string, graph *DependencyGraph) ([]Dependency, string) {
	content, err := f.GetContent()
	if err != nil {
		return nil, ""
	}

	name := getFallbackName(dir)
	rootDep := Dependency{Name: name, Version: "", Type: "root", Ecosystem: "pypi"}
	var deps []Dependency
	deps = append(deps, rootDep)
	rootID := rootDep.ID()

	lines := strings.Split(string(content), "\n")
	re := requirementsRegex
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var dep Dependency
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 4 {
			dep = Dependency{Name: matches[1], Version: matches[2] + matches[3], Type: "prod", Ecosystem: "pypi"}
		} else {
			parts := strings.Fields(line)
			if len(parts) > 0 && !strings.ContainsAny(parts[0], "=><~") {
				dep = Dependency{Name: parts[0], Version: "latest", Type: "prod", Ecosystem: "pypi"}
			} else {
				continue
			}
		}
		deps = append(deps, dep)
		graph.Edges[rootID] = append(graph.Edges[rootID], dep.ID())
	}
	return deps, rootID
}
