package core

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/regions"
	"github.com/dodobrands/aitriage/internal/scanner/ast"
	"github.com/dodobrands/aitriage/internal/scanner/entropy"
	"github.com/dodobrands/aitriage/internal/scanner/pathpolicy"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// Status represents the presence status of a security practice
type Status string

const (
	Present Status = "PRESENT"
	Absent  Status = "ABSENT"
	Unknown Status = "UNKNOWN"
)

type CheckResult struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Status         Status      `json:"status"`
	AuditStatus    AuditStatus `json:"audit_status,omitempty"`
	Evidence       string      `json:"evidence"`
	Suggestion     string      `json:"suggestion"`
	Framework      string      `json:"framework"`
	Severity       string      `json:"severity"`
	Line           int         `json:"line"`
	File           string      `json:"file"`
	Confidence     float64     `json:"confidence"`
	OWASPMapping   string      `json:"owasp_mapping,omitempty"`
	ReasoningChain []string    `json:"reasoning_chain,omitempty"`
}

// FileInfo holds metadata and cached content for a single file.
type FileInfo struct {
	Path string
	// RelPath is Path relative to the scanned project root, with forward
	// slashes. Path-based decisions (vendored directories, rule exclude_paths)
	// must use it: the root's own parent directories are not part of the
	// project, and a checkout under e.g. /agent/build/ must not look vendored.
	RelPath   string
	Extension string
	IsBinary  bool
	IsTest    bool

	// Setup Cache
	mu            sync.Mutex
	rawCache      []byte
	strippedCache []byte
	docsCache     []byte
	treeCache     *tree_sitter.Tree
	regionsCache  []regions.Kind
	noCommentText []byte
	hasRegions    bool
	hasRaw        bool
	hasStripped   bool
	hasDocs       bool
	hasTree       bool
}

// Close releases the tree-sitter tree if it exists.
func (fi *FileInfo) Close() {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.hasTree && fi.treeCache != nil {
		fi.treeCache.Close()
		fi.treeCache = nil
		fi.hasTree = false
	}
}

// GetContent reads the file content from disk. Content is cached in memory.
func (fi *FileInfo) GetContent() ([]byte, error) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if fi.hasRaw {
		return fi.rawCache, nil
	}

	stat, err := os.Stat(fi.Path)
	if err != nil {
		return nil, err
	}

	// Max size 10MB
	if stat.Size() > 10*1024*1024 {
		return nil, fmt.Errorf("file %s is too large (%d bytes)", fi.Path, stat.Size())
	}

	content, err := os.ReadFile(fi.Path)
	if err == nil {
		// Better binary detection
		limit := 512
		if len(content) < limit {
			limit = len(content)
		}

		contentType := http.DetectContentType(content[:limit])
		if !strings.HasPrefix(contentType, "text/") && contentType != "application/json" {
			fi.IsBinary = true
		} else {
			// Fallback check for null bytes
			for i := 0; i < limit; i++ {
				if content[i] == 0 {
					fi.IsBinary = true
					break
				}
			}
		}

		fi.rawCache = content
		fi.hasRaw = true
	}
	return content, err
}

// GetStrippedContent gets the entropy-stripped code content (strings and comments removed), correctly cached.
func (fi *FileInfo) GetStrippedContent() ([]byte, error) {
	fi.mu.Lock()
	if fi.hasStripped {
		fi.mu.Unlock()
		return fi.strippedCache, nil
	}
	fi.mu.Unlock()

	content, err := fi.GetContent() // calls GetContent which has its own lock, so we must unlock first
	if err != nil || fi.IsBinary {
		return nil, err
	}

	tree, _ := fi.GetTree()

	fi.mu.Lock()
	defer fi.mu.Unlock()

	if !fi.hasStripped { // check again to prevent data race
		var res entropy.StripResult
		if tree != nil {
			res = entropy.StripWithAST(string(content), tree)
		} else {
			res = entropy.Strip(string(content))
		}
		fi.strippedCache = []byte(res.CodeOnly)
		fi.docsCache = []byte(res.DocsAndStrings)
		fi.hasStripped = true
		fi.hasDocs = true
	}

	return fi.strippedCache, nil
}

// GetDocsOnlyContent gets the docs and strings portion of the source code, correctly cached.
func (fi *FileInfo) GetDocsOnlyContent() ([]byte, error) {
	fi.mu.Lock()
	if fi.hasDocs {
		fi.mu.Unlock()
		return fi.docsCache, nil
	}
	fi.mu.Unlock()

	content, err := fi.GetContent()
	if err != nil || fi.IsBinary {
		return nil, err
	}

	tree, _ := fi.GetTree()

	fi.mu.Lock()
	defer fi.mu.Unlock()

	if !fi.hasDocs {
		var res entropy.StripResult
		if tree != nil {
			res = entropy.StripWithAST(string(content), tree)
		} else {
			res = entropy.Strip(string(content))
		}
		fi.strippedCache = []byte(res.CodeOnly)
		fi.docsCache = []byte(res.DocsAndStrings)
		fi.hasStripped = true
		fi.hasDocs = true
	}

	return fi.docsCache, nil
}

// GetRegions classifies every byte of the file as code, comment or string
// literal. Configuration formats that SyntaxForPath leaves unknown (YAML,
// .env, TOML, INI) are read with "#" comments.
func (fi *FileInfo) GetRegions() ([]regions.Kind, error) {
	content, err := fi.GetContent()
	if err != nil {
		return nil, err
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if !fi.hasRegions {
		fi.regionsCache = regions.Bytes(content, ruleSyntax(fi.Path))
		fi.noCommentText = make([]byte, len(content))
		for i, b := range content {
			if fi.regionsCache[i] == regions.Comment && b != '\n' {
				b = ' '
			}
			fi.noCommentText[i] = b
		}
		fi.hasRegions = true
	}
	return fi.regionsCache, nil
}

// GetNonCommentContent returns the file with every comment byte replaced by a
// space, so offsets and line numbers match the raw content.
func (fi *FileInfo) GetNonCommentContent() ([]byte, error) {
	if _, err := fi.GetRegions(); err != nil {
		return nil, err
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.noCommentText, nil
}

// ruleSyntax picks the comment and string syntax used by detection rules.
func ruleSyntax(path string) regions.Syntax {
	if s := regions.SyntaxForPath(path); s.Known() {
		return s
	}
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, ".env") || base == "containerfile" || strings.HasPrefix(base, "containerfile.") {
		return regions.HashComments
	}
	switch filepath.Ext(base) {
	case ".yaml", ".yml", ".env", ".toml", ".properties", ".ini", ".cfg", ".conf", ".txt", ".in":
		return regions.HashComments
	}
	return regions.SyntaxForPath(path)
}

// GetTree parses the file and returns the tree-sitter AST tree.
func (fi *FileInfo) GetTree() (*tree_sitter.Tree, error) {
	fi.mu.Lock()
	if fi.hasTree {
		tree := fi.treeCache
		fi.mu.Unlock()
		return tree, nil
	}
	fi.mu.Unlock()

	content, err := fi.GetContent()
	if err != nil {
		return nil, err
	}

	lang, err := ast.GetLanguage(fi.Extension)
	if err != nil {
		return nil, err
	}

	parser := ast.GetParser()
	defer ast.PutParser(parser)

	if err := parser.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("failed to set language: %v", err)
	}
	tree := parser.Parse(content, nil)
	if tree == nil {
		return nil, fmt.Errorf("failed to parse file: %s", fi.Path)
	}

	fi.mu.Lock()
	defer fi.mu.Unlock()

	// Double check
	if fi.hasTree {
		tree.Close()
		return fi.treeCache, nil
	}

	fi.treeCache = tree
	fi.hasTree = true
	return tree, nil
}

// Workspace represents the entire directory being scanned, containing all files.
type Workspace struct {
	RootPath string
	Files    []*FileInfo
	Projects []*ProjectContext
	Config   *config.Config
}

// Close releases resources (like AST trees) for all files in the workspace.
func (w *Workspace) Close() {
	for _, f := range w.Files {
		f.Close()
	}
}

// ProjectContext represents a single logical codebase (like a frontend or backend app)
// with its own subset of files.
type ProjectContext struct {
	RootPath string
	ScanRoot string
	Files    []*FileInfo
	Stack    string
	Config   *config.Config

	mu      sync.RWMutex
	fileMap map[string]*FileInfo
}

// FindFilesByExtension returns all files matching the given extensions in the project.
func (ctx *ProjectContext) FindFilesByExtension(extensions ...string) []*FileInfo {
	extMap := make(map[string]bool)
	var globs []string
	for _, ext := range extensions {
		lower := strings.ToLower(ext)
		extMap[lower] = true
		if strings.ContainsAny(lower, "*?[") {
			globs = append(globs, lower)
		}
	}

	var matched []*FileInfo
	for _, f := range ctx.Files {
		// Most rules match extensions (for example, ".go"), but some
		// configuration files such as Dockerfile have no extension. Let those
		// rules match the filename, or a base-name glob such as "Dockerfile.*",
		// without changing FileInfo.Extension semantics.
		base := strings.ToLower(filepath.Base(f.Path))
		if extMap[strings.ToLower(f.Extension)] || extMap[base] || matchesAnyGlob(globs, base) {
			matched = append(matched, f)
		}
	}
	return matched
}

func matchesAnyGlob(globs []string, base string) bool {
	for _, g := range globs {
		if ok, err := filepath.Match(g, base); err == nil && ok {
			return true
		}
	}
	return false
}

// GetFile expects a relative path relative to the PROJECT root and returns its FileInfo if it exists.
func (ctx *ProjectContext) GetFile(relPath string) *FileInfo {
	target := filepath.Join(ctx.RootPath, relPath)

	ctx.mu.RLock()
	if ctx.fileMap != nil {
		f := ctx.fileMap[target]
		ctx.mu.RUnlock()
		return f
	}
	ctx.mu.RUnlock()

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Double-checked locking
	if ctx.fileMap == nil {
		ctx.fileMap = make(map[string]*FileInfo, len(ctx.Files))
		for _, f := range ctx.Files {
			ctx.fileMap[f.Path] = f
		}
	}

	return ctx.fileMap[target]
}

// defaultIgnoreDirs contains directories that should always be ignored.
// "build" is not one of them, for the same reason the external scanners'
// scope keeps it: generated build output is git-ignored, and a committed build
// directory (Go's build/package, build/ci) is the project's own.
var defaultIgnoreDirs = map[string]bool{
	".git":             true,
	"aitriage-reports": true, // AITriage's own scan/run artifacts — never re-scan them
	"node_modules":     true,
	"venv":             true,
	".venv":            true,
	"__pycache__":      true,
	".next":            true,
	"dist":             true,
	".nuxt":            true,
	"vendor":           true,
}

// defaultIgnoreExts contains file extensions we never want to analyze.
var defaultIgnoreExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".pyc": true, ".class": true,
}

// AITriageArtifactMarker tags reports that AITriage itself generates. A later
// scan recognizes this marker and skips the file, so AITriage never re-flags
// the vulnerability examples/snippets inside its own report as new findings.
const AITriageArtifactMarker = "<!-- aitriage:generated-report -->"

// isAITriageGeneratedArtifact reports whether a file is AITriage's own output
// (a generated report), which must never be scanned as if it were source code.
// It matches the stable runway-report filename cheaply, and falls back to the
// content marker for any other generated report.
func isAITriageGeneratedArtifact(path string, size int64) bool {
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, "runway-report-") && strings.HasSuffix(base, ".md") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	if (ext == ".md" || ext == ".markdown") && size > 0 && size < 5*1024*1024 {
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer func() { _ = f.Close() }()
		buf := make([]byte, 512)
		n, _ := f.Read(buf)
		if bytes.Contains(buf[:n], []byte(AITriageArtifactMarker)) {
			return true
		}
	}
	return false
}

// NewWorkspace initializes a central file index by walking the directory once.
func NewWorkspace(rootPath string) (*Workspace, error) {
	ws := &Workspace{
		RootPath: rootPath,
		Files:    make([]*FileInfo, 0),
		Projects: make([]*ProjectContext, 0),
		Config:   config.LoadConfig(rootPath),
	}

	// .gitignore, .aitriageignore and ignore.paths are read by the matcher the
	// external scanners' scope filter uses, and combined the same way: each
	// excludes on its own, and a directory is skipped only when nothing below
	// it can be re-included. A walker that pruned with its own rules dropped
	// directories the scope filter keeps, such as deploy/prod/ under
	// "deploy/*" and "!deploy/prod/".
	gitIgnore := config.ReadIgnoreFile(filepath.Join(rootPath, ".gitignore"))
	aitriageIgnore := config.ReadIgnoreFile(filepath.Join(rootPath, ".aitriageignore"))
	var userPatterns []string
	if ws.Config != nil {
		userPatterns = ws.Config.Ignore.Paths
	}
	ignorePaths := config.NewPathMatcher(userPatterns)
	legacy := newLegacyIgnoreWarner(rootPath, userPatterns)

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we don't have permission to read
		}

		// Fast relative path for gitignore check
		relPath, _ := filepath.Rel(rootPath, path)

		// Always skip hardcoded massive build directories as a fallback
		if info.IsDir() {
			// Exclusions describe paths inside the project. The project
			// directory itself is never excluded, whatever it is called.
			if relPath == "." {
				legacy.checkRoot(path)
				return nil
			}

			if defaultIgnoreDirs[info.Name()] {
				return filepath.SkipDir
			}

			if ignorePaths.ExcludesTree(relPath) || aitriageIgnore.ExcludesTree(relPath) || gitIgnore.ExcludesTree(relPath) {
				return filepath.SkipDir
			}

			if !ignorePaths.Excludes(relPath, true) {
				legacy.checkDir(path, relPath)
			}
			return nil
		}

		if ignorePaths.Excludes(relPath, false) || aitriageIgnore.Excludes(relPath, false) || gitIgnore.Excludes(relPath, false) {
			return nil
		}

		// Never scan AITriage's own generated reports: their embedded examples
		// and evidence snippets would otherwise be re-flagged as new findings.
		if isAITriageGeneratedArtifact(path, info.Size()) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if defaultIgnoreExts[ext] {
			return nil
		}

		// Skip minified JS and common large bundles
		base := strings.ToLower(filepath.Base(path))
		if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.css") || strings.Contains(base, ".bundle.") || strings.Contains(base, "swagger-ui") || strings.Contains(base, "redoc.standalone") {
			return nil
		}

		if info.Size() > 10*1024*1024 {
			// Skip files larger than 10MB to prevent OOM
			return nil
		}

		fi := &FileInfo{
			Path:      path,
			RelPath:   filepath.ToSlash(relPath),
			Extension: ext,
			IsTest:    pathpolicy.IsTestLike(relPath),
		}
		ws.Files = append(ws.Files, fi)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return ws, nil
}
