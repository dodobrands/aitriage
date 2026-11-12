package ast

import (
	"fmt"
	"sync"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_js "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_py "github.com/tree-sitter/tree-sitter-python/bindings/go"
	tree_sitter_ts "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

var (
	langCache = make(map[string]*tree_sitter.Language)
	langMu    sync.RWMutex
)

// GetLanguage returns the tree-sitter language for a given file extension
func GetLanguage(ext string) (*tree_sitter.Language, error) {
	langMu.RLock()
	if lang, ok := langCache[ext]; ok {
		langMu.RUnlock()
		return lang, nil
	}
	langMu.RUnlock()

	langMu.Lock()
	defer langMu.Unlock()

	// Double check
	if lang, ok := langCache[ext]; ok {
		return lang, nil
	}

	var newLang *tree_sitter.Language
	switch ext {
	case ".go":
		newLang = tree_sitter.NewLanguage(tree_sitter_go.Language())
	case ".js", ".jsx":
		newLang = tree_sitter.NewLanguage(tree_sitter_js.Language())
	case ".py":
		newLang = tree_sitter.NewLanguage(tree_sitter_py.Language())
	case ".ts":
		newLang = tree_sitter.NewLanguage(tree_sitter_ts.LanguageTypescript())
	case ".tsx":
		newLang = tree_sitter.NewLanguage(tree_sitter_ts.LanguageTSX())
	default:
		return nil, fmt.Errorf("unsupported language for extension: %s", ext)
	}

	langCache[ext] = newLang
	return newLang, nil
}

// MatchResult contains information about a query match
type MatchResult struct {
	Node      *tree_sitter.Node
	Variables map[string]string // $VAR -> captured source code
}

// MatchInTree executes a query against an existing tree and returns results
func MatchInTree(lang *tree_sitter.Language, tree *tree_sitter.Tree, content []byte, queryString string) ([]MatchResult, error) {
	query, err := tree_sitter.NewQuery(lang, queryString)
	if err != nil {
		return nil, fmt.Errorf("invalid query: %v", err)
	}
	defer query.Close()

	cursor := tree_sitter.NewQueryCursor()
	defer cursor.Close()

	var results []MatchResult
	captures := cursor.Captures(query, tree.RootNode(), content)

	for {
		match, _ := captures.Next()
		if match == nil {
			break
		}

		// Initial results for this match
		res := MatchResult{
			Variables: make(map[string]string),
		}

		captureNames := query.CaptureNames()
		validMatch := true

		// Process all captures in this match
		for i := range match.Captures {
			capture := &match.Captures[i]
			captureName := captureNames[capture.Index]

			// Extract node content
			start := capture.Node.StartByte()
			end := capture.Node.EndByte()
			text := string(content[start:end])

			varName := "$" + captureName

			// Unification: if variable already exists, it MUST have the same content
			if existing, ok := res.Variables[varName]; ok {
				if existing != text {
					validMatch = false
					break
				}
			}

			res.Variables[varName] = text

			// Set the primary node (usually the first capture)
			if i == 0 {
				node := capture.Node
				res.Node = &node
			}
		}

		if validMatch {
			results = append(results, res)
		}
	}

	return results, nil
}

// ParserPool provides a pool of tree-sitter parsers to avoid allocations
var ParserPool = sync.Pool{
	New: func() interface{} {
		return tree_sitter.NewParser()
	},
}

// GetParser returns a parser from the pool
func GetParser() *tree_sitter.Parser {
	return ParserPool.Get().(*tree_sitter.Parser)
}

// PutParser returns a parser to the pool
func PutParser(p *tree_sitter.Parser) {
	ParserPool.Put(p)
}
