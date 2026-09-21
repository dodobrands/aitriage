// Package packs reads the rule packs installed on this machine.
//
// Listing rule packs was CLI-only, so an agent in an IDE could not answer "what
// rules is this scan actually running?" — a question that decides whether a
// clean result means anything.
//
// Reading is exposed everywhere. Installing is not: a pack is rule content
// fetched from elsewhere and written to disk, and a Web server is reachable by
// more people than a terminal is. Install and remove stay in the CLI, where the
// person running the command is the person at the keyboard.
package packs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// Manifest describes an installed pack.
type Manifest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	RuleCount   int    `json:"rule_count"`
	Author      string `json:"author,omitempty"`
	Stack       string `json:"stack,omitempty"`
}

// Installed is one pack on disk.
type Installed struct {
	Manifest
	Path string `json:"path"`
}

// Dir is where packs are installed.
func Dir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aitriage", "packs")
}

// List returns the installed packs, sorted by name so output is stable.
// A missing directory is not an error: it means nothing is installed.
func List() []Installed {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		return nil
	}

	out := make([]Installed, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(Dir(), entry.Name())
		data, err := os.ReadFile(filepath.Join(path, "manifest.json"))
		if err != nil {
			// A directory without a manifest is not a pack; skipping it is
			// correct, and reporting it would be noise.
			continue
		}
		var m Manifest
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if m.Name == "" {
			m.Name = entry.Name()
		}
		out = append(out, Installed{Manifest: m, Path: path})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Find returns one installed pack by name.
func Find(name string) (Installed, bool) {
	for _, pack := range List() {
		if pack.Name == name {
			return pack, true
		}
	}
	return Installed{}, false
}
