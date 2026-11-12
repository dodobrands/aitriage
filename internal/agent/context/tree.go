package agentcontext

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// defaultSkipDirs are always skipped (same as core.Workspace).
var defaultSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "venv": true, ".venv": true,
	"__pycache__": true, ".next": true, "dist": true, "build": true,
	".nuxt": true, "vendor": true, ".idea": true, ".vscode": true,
	".terraform": true, "target": true, "coverage": true,
	// AITriage and coding-client runtime state must never become repository
	// evidence. Host-agent runs persist a request/response after every deferred
	// model turn; including those files would change the next prompt fingerprint
	// and prevent the stored response from being replayed.
	"aitriage-reports": true, ".aitriage": true, ".aitriage-cache": true,
	".codex": true, ".claude": true,
}

// defaultSkipExts are always skipped.
var defaultSkipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".svg": true, ".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".bz2": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".pyc": true, ".class": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".lock": true,
}

// treeNode is an internal node for building the tree structure.
type treeNode struct {
	name     string
	isDir    bool
	children []*treeNode
}

// BuildProjectTree generates a text-based tree representation of the project.
// Uses filepath.Walk with filtering (gitignore dirs, binary extensions, etc.).
// Returns a string like:
//
//	├── cmd/
//	│   └── main.go
//	├── internal/
//	│   └── handler/
//	└── Dockerfile
func BuildProjectTree(projectPath string, maxDepth, maxFiles int) string {
	if maxDepth <= 0 {
		maxDepth = 4
	}
	if maxFiles <= 0 {
		maxFiles = 300
	}

	absRoot, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Sprintf("(error resolving path: %v)", err)
	}

	// Collect relative paths.
	var paths []string
	count := 0

	_ = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(absRoot, path)
		if relPath == "." {
			return nil
		}

		// Skip directories.
		if info.IsDir() {
			if defaultSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			// Depth check.
			depth := strings.Count(relPath, string(os.PathSeparator)) + 1
			if depth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files by extension.
		ext := strings.ToLower(filepath.Ext(path))
		if defaultSkipExts[ext] {
			return nil
		}

		// Skip minified and large bundles.
		base := strings.ToLower(filepath.Base(path))
		if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.css") ||
			strings.Contains(base, ".bundle.") {
			return nil
		}

		// Depth check for files.
		depth := strings.Count(relPath, string(os.PathSeparator)) + 1
		if depth > maxDepth {
			return nil
		}

		// File count limit.
		count++
		if count > maxFiles {
			return filepath.SkipAll
		}

		paths = append(paths, relPath)
		return nil
	})

	if len(paths) == 0 {
		return "(empty project)"
	}

	sort.Strings(paths)

	// Build tree structure.
	root := &treeNode{name: filepath.Base(absRoot), isDir: true}
	for _, p := range paths {
		parts := strings.Split(p, string(os.PathSeparator))
		insertPath(root, parts)
	}

	// Render tree.
	var sb strings.Builder
	renderTree(&sb, root, "", true)

	if count > maxFiles {
		fmt.Fprintf(&sb, "\n... truncated (%d+ files, showing first %d)\n", count, maxFiles)
	}

	return sb.String()
}

// insertPath inserts a file path (split into parts) into the tree.
func insertPath(node *treeNode, parts []string) {
	if len(parts) == 0 {
		return
	}

	name := parts[0]
	isLeaf := len(parts) == 1

	// Find existing child.
	for _, child := range node.children {
		if child.name == name {
			if !isLeaf {
				insertPath(child, parts[1:])
			}
			return
		}
	}

	// Create new child.
	child := &treeNode{name: name, isDir: !isLeaf}
	node.children = append(node.children, child)

	if !isLeaf {
		insertPath(child, parts[1:])
	}
}

// renderTree renders the tree to a string builder with proper box-drawing characters.
func renderTree(sb *strings.Builder, node *treeNode, prefix string, isRoot bool) {
	if isRoot {
		// Don't render the root itself, just its children.
		sortChildren(node)
		for i, child := range node.children {
			isLast := i == len(node.children)-1
			renderChild(sb, child, "", isLast)
		}
		return
	}
}

func renderChild(sb *strings.Builder, node *treeNode, prefix string, isLast bool) {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	name := node.name
	if node.isDir {
		name += "/"
	}
	sb.WriteString(prefix + connector + name + "\n")

	if node.isDir && len(node.children) > 0 {
		sortChildren(node)
		childPrefix := prefix + "│   "
		if isLast {
			childPrefix = prefix + "    "
		}
		for i, child := range node.children {
			childIsLast := i == len(node.children)-1
			renderChild(sb, child, childPrefix, childIsLast)
		}
	}
}

func sortChildren(node *treeNode) {
	sort.Slice(node.children, func(i, j int) bool {
		// Dirs before files, then alphabetical.
		if node.children[i].isDir != node.children[j].isDir {
			return node.children[i].isDir
		}
		return strings.ToLower(node.children[i].name) < strings.ToLower(node.children[j].name)
	})
}
