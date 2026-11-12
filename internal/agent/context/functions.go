package agentcontext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner/ast"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// FunctionContext holds the extracted function body and surrounding context.
type FunctionContext struct {
	Name      string `json:"name"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Body      string `json:"body"`
	Imports   string `json:"imports"`
}

// functionQuery holds tree-sitter queries for function extraction per language.
type functionQuery struct {
	funcQueries   []string // Queries to find function-like nodes.
	importQueries []string // Queries to find import statements.
}

// Language-specific tree-sitter queries for function extraction.
var langQueries = map[string]functionQuery{
	".go": {
		funcQueries: []string{
			"(function_declaration) @func",
			"(method_declaration) @func",
		},
		importQueries: []string{
			"(import_declaration) @import",
		},
	},
	".py": {
		funcQueries: []string{
			"(function_definition) @func",
			"(class_definition) @func",
		},
		importQueries: []string{
			"(import_statement) @import",
			"(import_from_statement) @import",
		},
	},
	".js": {
		funcQueries: []string{
			"(function_declaration) @func",
			"(method_definition) @func",
			"(export_statement (function_declaration) @func)",
		},
		importQueries: []string{
			"(import_statement) @import",
		},
	},
	".ts": {
		funcQueries: []string{
			"(function_declaration) @func",
			"(method_definition) @func",
			"(export_statement (function_declaration) @func)",
		},
		importQueries: []string{
			"(import_statement) @import",
		},
	},
}

func init() {
	// JSX/TSX share queries with JS/TS.
	langQueries[".jsx"] = langQueries[".js"]
	langQueries[".tsx"] = langQueries[".ts"]
}

// ExtractFunction finds the function/method/class containing the given line
// in the specified file. Uses tree-sitter AST for precise extraction.
// Falls back to a generous line window if AST parsing fails.
func ExtractFunction(filePath string, line int) (*FunctionContext, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	// Try AST-based extraction first.
	if queries, ok := langQueries[ext]; ok {
		if result := extractWithAST(ext, content, line, queries); result != nil {
			return result, nil
		}
	}

	// Fallback: generous window (±30 lines).
	return extractFallback(content, line, filePath), nil
}

// extractWithAST uses tree-sitter to find the enclosing function for a line.
func extractWithAST(ext string, content []byte, targetLine int, queries functionQuery) *FunctionContext {
	lang, err := ast.GetLanguage(ext)
	if err != nil {
		return nil
	}

	parser := ast.GetParser()
	defer ast.PutParser(parser)

	if err := parser.SetLanguage(lang); err != nil {
		return nil
	}

	tree := parser.Parse(content, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()

	// Find the innermost function containing the target line.
	var bestNode *tree_sitter.Node
	var bestName string

	for _, queryStr := range queries.funcQueries {
		results, err := ast.MatchInTree(lang, tree, content, queryStr)
		if err != nil {
			continue
		}

		for _, r := range results {
			if r.Node == nil {
				continue
			}

			startRow := int(r.Node.StartPosition().Row) + 1 // 0-indexed → 1-indexed
			endRow := int(r.Node.EndPosition().Row) + 1

			if targetLine >= startRow && targetLine <= endRow {
				// Prefer the innermost (smallest) enclosing function.
				if bestNode == nil || nodeSize(r.Node) < nodeSize(bestNode) {
					node := *r.Node
					bestNode = &node
					bestName = extractFuncName(r.Node, content)
				}
			}
		}
	}

	if bestNode == nil {
		return nil
	}

	startRow := int(bestNode.StartPosition().Row) + 1
	endRow := int(bestNode.EndPosition().Row) + 1
	body := string(content[bestNode.StartByte():bestNode.EndByte()])

	// Extract imports.
	imports := extractImports(lang, tree, content, queries.importQueries)

	return &FunctionContext{
		Name:      bestName,
		StartLine: startRow,
		EndLine:   endRow,
		Body:      body,
		Imports:   imports,
	}
}

// extractFuncName tries to extract the function name from the AST node.
func extractFuncName(node *tree_sitter.Node, content []byte) string {
	// Walk children looking for a "name" or "identifier" field.
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(uint(i))
		if child == nil {
			continue
		}
		typ := child.Kind()
		if typ == "identifier" || typ == "property_identifier" || typ == "name" {
			return string(content[child.StartByte():child.EndByte()])
		}
		// For method declarations, the name might be nested.
		if typ == "field_identifier" {
			return string(content[child.StartByte():child.EndByte()])
		}
	}
	return "(anonymous)"
}

// extractImports collects all import statements from the file.
func extractImports(lang *tree_sitter.Language, tree *tree_sitter.Tree, content []byte, importQueries []string) string {
	var parts []string
	for _, queryStr := range importQueries {
		results, err := ast.MatchInTree(lang, tree, content, queryStr)
		if err != nil {
			continue
		}
		for _, r := range results {
			if r.Node != nil {
				text := string(content[r.Node.StartByte():r.Node.EndByte()])
				parts = append(parts, text)
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n")
}

// fallbackRadius is how many lines on each side of the target extractFallback
// returns.
const fallbackRadius = 30

// extractFallback returns a generous window of lines around the target.
//
// The line comes from scanner output, which can be stale: the file may have
// been shortened since, so the line can lie past its end. The window is then
// the last lines of the file. Slicing with an unclamped line panicked, and the
// panic ended the whole run.
func extractFallback(content []byte, line int, filePath string) *FunctionContext {
	lines := strings.Split(string(content), "\n")
	name := fmt.Sprintf("(around line %d)", line)
	idx := line - 1
	if idx >= len(lines) {
		name = fmt.Sprintf("(line %d is past the end of the file; its last lines)", line)
		idx = len(lines) - 1
	}
	if idx < 0 {
		idx = 0
	}

	start := idx - fallbackRadius
	if start < 0 {
		start = 0
	}
	end := idx + fallbackRadius
	if end > len(lines) {
		end = len(lines)
	}

	// Try to extract imports from the top of the file.
	var imports []string
	for _, l := range lines[:min(30, len(lines))] {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") ||
			strings.HasPrefix(trimmed, "require(") || strings.HasPrefix(trimmed, "const ") && strings.Contains(trimmed, "require(") {
			imports = append(imports, l)
		}
	}

	return &FunctionContext{
		Name:      name,
		StartLine: start + 1,
		EndLine:   end,
		Body:      strings.Join(lines[start:end], "\n"),
		Imports:   strings.Join(imports, "\n"),
	}
}

func nodeSize(n *tree_sitter.Node) uint {
	return n.EndByte() - n.StartByte()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
