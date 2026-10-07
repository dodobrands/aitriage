package engine

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// npmWorkspaceContains is deliberately conservative: an unrelated ancestor's
// lockfile must not hide an unpinned package. It never runs a package manager.
func npmWorkspaceContains(root, member string) bool {
	rel, err := filepath.Rel(root, member)
	if err != nil || !isStrictlyInside(member, root) {
		return false
	}
	rel = filepath.ToSlash(rel)
	var patterns []string
	if data, err := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml")); err == nil {
		var workspace struct {
			Packages []string `yaml:"packages"`
		}
		if yaml.Unmarshal(data, &workspace) != nil {
			return false
		}
		patterns = workspace.Packages
	} else if data, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		var manifest struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if json.Unmarshal(data, &manifest) != nil {
			return false
		}
		if json.Unmarshal(manifest.Workspaces, &patterns) != nil {
			var workspace struct {
				Packages []string `json:"packages"`
			}
			if json.Unmarshal(manifest.Workspaces, &workspace) != nil {
				return false
			}
			patterns = workspace.Packages
		}
	}
	included := false
	for _, pattern := range patterns {
		excluded := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(pattern, "!"), "./"), "/")
		if workspacePatternMatches(pattern, rel) {
			if excluded {
				return false
			}
			included = true
		}
	}
	return included
}

func workspacePatternMatches(pattern, member string) bool {
	parts, names := strings.Split(pattern, "/"), strings.Split(member, "/")
	var match func(int, int) bool
	match = func(p, n int) bool {
		if p == len(parts) {
			return n == len(names)
		}
		if parts[p] == "**" {
			if match(p+1, n) {
				return true
			}
			return n < len(names) && match(p, n+1)
		}
		if n == len(names) {
			return false
		}
		ok, err := path.Match(parts[p], names[n])
		return err == nil && ok && match(p+1, n+1)
	}
	return match(0, 0)
}
