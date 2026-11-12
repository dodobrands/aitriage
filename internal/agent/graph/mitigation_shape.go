package graph

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner/ast"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/dodobrands/aitriage/internal/regions"
)

// ── The shape of a code mitigation ───────────────────────────────────────────
//
// Sharing a name with the flagged statement does not make a line a
// mitigation. Models cited the assignment that produces the tainted value
// (`cmd = "ls " + request.args["dir"]`), a log call that mentions it, and a
// check in the previous function, and each was accepted. A cited line is now
// accepted only when it is
//   - a guard of a shared name: an if or elif whose condition checks it and
//     that encloses the flagged statement or exits early (return, raise,
//     throw, continue, break, or an abort/exit/panic call), an early exit
//     inside such an if, or an assertion of it; or
//   - a re-assignment of a shared name through a call that takes it:
//     x = f(x), or x = x.f(...),
// and it lies in the same function as the flagged line. Where the repository
// has a tree-sitter grammar for the language (Python, Go, JavaScript,
// TypeScript) the syntax tree decides all of this. Elsewhere the line is read
// as text and the function cannot be checked, so code_mitigation is accepted
// that way only for MEDIUM and LOW findings; a HIGH finding is left for a
// person.

// mitigationGrammars maps source extensions to the grammar that parses them
// (see internal/scanner/ast). The JavaScript grammar parses JSX.
var mitigationGrammars = map[string]string{
	".py": ".py", ".pyw": ".py", ".pyi": ".py",
	".go": ".go",
	".js": ".js", ".jsx": ".js", ".mjs": ".js", ".cjs": ".js",
	".ts": ".ts", ".mts": ".ts", ".cts": ".ts",
	".tsx": ".tsx",
}

func mitigationGrammar(path string) string {
	return mitigationGrammars[strings.ToLower(filepath.Ext(path))]
}

var (
	// functionNodeKinds are the function-like nodes of the supported grammars.
	functionNodeKinds = stringSet(
		"function_definition", "lambda", // Python
		"function_declaration", "method_declaration", "func_literal", // Go
		"function_expression", "function", "arrow_function", "method_definition",
		"generator_function_declaration", "generator_function", // JavaScript, TypeScript
	)
	// blockNodeKinds hold statements.
	blockNodeKinds = stringSet("block", "statement_block", "statement_list")
	// boundaryNodeKinds end the search for the construct a cited line is part
	// of: past them the line is a plain statement of a block.
	boundaryNodeKinds = stringSet("module", "program", "source_file", "class_body", "class_definition", "class_declaration", "ERROR",
		"block", "statement_block", "statement_list")
	conditionalNodeKinds  = stringSet("if_statement", "elif_clause")
	exitNodeKinds         = stringSet("return_statement", "raise_statement", "throw_statement", "continue_statement", "break_statement")
	callNodeKinds         = stringSet("call", "call_expression")
	reassignmentNodeKinds = stringSet("assignment", "assignment_statement", "short_var_declaration", "assignment_expression", "variable_declarator")
	// exitCallNames end the current request or process when called (compared
	// in lower case): Flask's abort, sys.exit, os.Exit, process.exit, panic,
	// log.Fatal and log.Panic with their f/ln variants.
	exitCallNames = stringSet("abort", "exit", "_exit", "panic", "panicf", "panicln", "fatal", "fatalf", "fatalln")
)

// errNoMitigationShape marks a cited line that is neither a guard nor a
// re-assignment through a call.
var errNoMitigationShape = errors.New("neither a guard nor a re-assignment through a call")

// checkMitigationShape requires the cited line to be a guard of a shared
// name or a re-assignment of one through a call, in the same function as the
// flagged line. starts are the byte offsets of the cited text's code
// occurrences on the cited line.
func checkMitigationShape(path string, source []byte, lines []string, lineKinds [][]regions.Kind, finding EnrichedFinding, evidence *DispositionEvidence, starts []int, shared map[string]bool) error {
	lead := len(evidence.Observed) - len(strings.TrimLeft(evidence.Observed, " \t"))
	points := make([]int, len(starts))
	for i, start := range starts {
		points[i] = start + lead
	}
	if grammar := mitigationGrammar(path); grammar != "" {
		if rejection, parsed := treeMitigationCheck(grammar, source, lines, finding.Line, evidence.Line, points, shared); parsed {
			return rejection
		}
	}
	if !belowHigh(finding.Severity) {
		return fmt.Errorf("code_mitigation evidence for a %s finding must be tied to the flagged statement's function, and AITriage has no parser for %s: %w",
			strings.ToUpper(strings.TrimSpace(firstNonEmpty(finding.Severity, "unrated"))), filepath.Base(path), errPersonMustDecide)
	}
	if err := textMitigationCheck(lines[evidence.Line-1], lineKinds[evidence.Line-1], shared); err != nil {
		return shapeRejection(evidence.Line, shared, err)
	}
	return nil
}

// belowHigh reports whether a severity is MEDIUM, LOW or INFO. An unknown
// severity cannot be shown to be below HIGH.
func belowHigh(severity string) bool {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "MEDIUM", "LOW", "INFO":
		return true
	}
	return false
}

// shapeRejection phrases why a cited line is not a mitigation. The role
// errors are noun phrases describing the line.
func shapeRejection(line int, shared map[string]bool, err error) error {
	name := firstName(shared)
	return fmt.Errorf("code_mitigation evidence rejected: line %d is %w; cite an if, elif or assert in the same function that checks %s (or an early exit under such a check), or a re-assignment through a call such as %s = f(%s)",
		line, err, sortedNames(shared), name, name)
}

// treeMitigationCheck decides on the syntax tree. parsed is false when the
// file cannot be parsed reliably at the two lines; the caller then treats the
// language as one without a grammar.
func treeMitigationCheck(grammar string, source []byte, lines []string, flaggedLine, citedLine int, starts []int, shared map[string]bool) (rejection error, parsed bool) {
	lang, err := ast.GetLanguage(grammar)
	if err != nil {
		return nil, false
	}
	parser := ast.GetParser()
	defer ast.PutParser(parser)
	if err := parser.SetLanguage(lang); err != nil {
		return nil, false
	}
	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, false
	}
	defer tree.Close()
	root := tree.RootNode()

	flagged := firstCodePoint(lines, flaggedLine)
	flaggedNode := root.NamedDescendantForPointRange(flagged, flagged)
	if flaggedNode == nil || insideError(flaggedNode) {
		return nil, false
	}
	flaggedFunction := enclosingFunction(flaggedNode)

	m := mitigationTree{source: source, flagged: flagged, flaggedLine: flaggedLine, citedLine: citedLine, shared: shared}
	for _, start := range starts {
		point := tree_sitter.Point{Row: uint(citedLine - 1), Column: uint(start)}
		node := root.NamedDescendantForPointRange(point, point)
		if node == nil || insideError(node) {
			return nil, false
		}
		if !sameNode(enclosingFunction(node), flaggedFunction) {
			rejection = fmt.Errorf("code_mitigation evidence rejected: line %d is in a different function than the flagged line %d; a mitigation must run in the same function, before the flagged statement", citedLine, flaggedLine)
			continue
		}
		err := m.role(node, point)
		if err == nil {
			return nil, true
		}
		if rejection == nil || errors.Is(rejection, errNoMitigationShape) {
			rejection = shapeRejection(citedLine, shared, err)
		}
	}
	return rejection, true
}

// mitigationTree holds what one tree check compares the cited line against.
type mitigationTree struct {
	source                 []byte
	flagged                tree_sitter.Point
	flaggedLine, citedLine int
	shared                 map[string]bool
}

// role classifies the construct the cited point is part of.
func (m mitigationTree) role(node *tree_sitter.Node, point tree_sitter.Point) error {
	// The condition of an if or elif, Go's initializer included.
	for cur := node; cur != nil; cur = cur.Parent() {
		kind := cur.Kind()
		if conditionalNodeKinds[kind] {
			if inHeader(cur, point) {
				return m.guard(cur)
			}
			break
		}
		if functionNodeKinds[kind] || boundaryNodeKinds[kind] {
			break
		}
	}
	// Otherwise the statement the point lies in.
	for cur := node; cur != nil; cur = cur.Parent() {
		kind := cur.Kind()
		switch {
		case kind == "assert_statement":
			if m.mentions(cur) {
				return nil
			}
			return fmt.Errorf("an assert that does not check %s", sortedNames(m.shared))
		case reassignmentNodeKinds[kind]:
			return m.reassignment(cur)
		case exitNodeKinds[kind]:
			return m.guardedExit(cur)
		case kind == "expression_statement":
			call := firstNamedChild(cur)
			switch {
			case call != nil && callNodeKinds[call.Kind()] && m.isAssertCall(call):
				if m.mentions(call.ChildByFieldName("arguments")) {
					return nil
				}
				return fmt.Errorf("an assertion that does not check %s", sortedNames(m.shared))
			case call != nil && callNodeKinds[call.Kind()] && m.isExitCall(call):
				return m.guardedExit(cur)
			}
			return errNoMitigationShape
		case functionNodeKinds[kind] || boundaryNodeKinds[kind]:
			return errNoMitigationShape
		}
	}
	return errNoMitigationShape
}

// guard accepts an if or elif whose condition checks a shared name and that
// either encloses the flagged statement or exits early.
func (m mitigationTree) guard(conditional *tree_sitter.Node) error {
	if !m.mentions(conditional.ChildByFieldName("condition")) && !m.mentions(conditional.ChildByFieldName("initializer")) {
		return fmt.Errorf("a condition that does not check %s", sortedNames(m.shared))
	}
	consequence := conditional.ChildByFieldName("consequence")
	if consequence == nil {
		return errNoMitigationShape
	}
	if containsPoint(consequence, m.flagged) || m.exitsEarly(consequence) {
		return nil
	}
	return fmt.Errorf("a check of %s that neither exits early (return, raise, throw, abort) nor encloses the flagged line %d", sortedNames(m.shared), m.flaggedLine)
}

// guardedExit accepts an early exit that is the body of an if or elif
// checking a shared name.
func (m mitigationTree) guardedExit(exit *tree_sitter.Node) error {
	for cur := exit.Parent(); cur != nil; cur = cur.Parent() {
		kind := cur.Kind()
		if blockNodeKinds[kind] {
			continue
		}
		if conditionalNodeKinds[kind] {
			consequence := cur.ChildByFieldName("consequence")
			if consequence == nil || !containsNode(consequence, exit) {
				break
			}
			if m.mentions(cur.ChildByFieldName("condition")) || m.mentions(cur.ChildByFieldName("initializer")) {
				return nil
			}
			return fmt.Errorf("an early exit under a condition that does not check %s", sortedNames(m.shared))
		}
		break
	}
	return fmt.Errorf("an early exit that is not under a check of %s", sortedNames(m.shared))
}

// reassignment accepts x = f(x) and x = x.f(...) for a shared name x.
func (m mitigationTree) reassignment(assign *tree_sitter.Node) error {
	var targets []*tree_sitter.Node
	var value *tree_sitter.Node
	if assign.Kind() == "variable_declarator" {
		targets, value = []*tree_sitter.Node{assign.ChildByFieldName("name")}, assign.ChildByFieldName("value")
	} else {
		targets, value = assignmentTargets(assign.ChildByFieldName("left")), assign.ChildByFieldName("right")
	}
	if value == nil {
		return errNoMitigationShape
	}
	assigned := ""
	for _, target := range targets {
		if target == nil || !m.mentions(target) {
			continue
		}
		name := m.text(target)
		if m.passesThroughCall(value, name) {
			return nil
		}
		assigned = name
	}
	if assigned == "" {
		return fmt.Errorf("an assignment to something other than %s", sortedNames(m.shared))
	}
	return fmt.Errorf("an assignment of %s that does not pass %s through a call: the assignment that produces a value is not its mitigation, only %s = f(%s) is", assigned, assigned, assigned, assigned)
}

// passesThroughCall reports whether value contains a call that takes the
// assigned expression as an argument or as its receiver.
func (m mitigationTree) passesThroughCall(value *tree_sitter.Node, assigned string) bool {
	found := false
	walkOutsideFunctions(value, func(n *tree_sitter.Node) bool {
		if found {
			return false
		}
		if callNodeKinds[n.Kind()] {
			function := n.ChildByFieldName("function")
			receiver := function != nil && function.Kind() != "identifier" && m.containsText(function, assigned)
			if receiver || m.containsText(n.ChildByFieldName("arguments"), assigned) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// exitsEarly reports whether a block (or a single statement) ends the current
// path with one of its top-level statements.
func (m mitigationTree) exitsEarly(body *tree_sitter.Node) bool {
	for _, statement := range topLevelStatements(body) {
		if exitNodeKinds[statement.Kind()] {
			return true
		}
		if statement.Kind() == "expression_statement" {
			if call := firstNamedChild(statement); call != nil && callNodeKinds[call.Kind()] && m.isExitCall(call) {
				return true
			}
		}
	}
	return false
}

// calleeName splits a call's function into the receiver text and the last
// name: "logging.info" is ("logging", "info").
func (m mitigationTree) calleeName(call *tree_sitter.Node) (string, string) {
	function := call.ChildByFieldName("function")
	if function == nil {
		return "", ""
	}
	text := m.text(function)
	if i := strings.LastIndex(text, "."); i >= 0 {
		return text[:i], text[i+1:]
	}
	return "", text
}

func (m mitigationTree) isExitCall(call *tree_sitter.Node) bool {
	_, name := m.calleeName(call)
	return exitCallNames[strings.ToLower(name)]
}

// isAssertCall recognises assert(x), assert.ok(x), assertValid(x),
// assert_safe(x), invariant(x) and precondition(x). console.assert only logs.
func (m mitigationTree) isAssertCall(call *tree_sitter.Node) bool {
	receiver, name := m.calleeName(call)
	lower := strings.ToLower(name)
	switch {
	case receiver == "console":
		return false
	case receiver == "assert", strings.HasPrefix(lower, "assert"), lower == "invariant", lower == "precondition":
		return true
	}
	return false
}

// mentions reports whether a subtree names a shared identifier outside nested
// functions.
func (m mitigationTree) mentions(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	found := false
	walkOutsideFunctions(n, func(child *tree_sitter.Node) bool {
		if found {
			return false
		}
		if strings.HasSuffix(child.Kind(), "identifier") && m.shared[strings.TrimLeft(m.text(child), "$")] {
			found = true
			return false
		}
		return true
	})
	return found
}

// containsText reports whether a subtree has a node whose text is exactly
// text, outside nested functions.
func (m mitigationTree) containsText(n *tree_sitter.Node, text string) bool {
	if n == nil || text == "" {
		return false
	}
	found := false
	walkOutsideFunctions(n, func(child *tree_sitter.Node) bool {
		if found {
			return false
		}
		if m.text(child) == text {
			found = true
			return false
		}
		return true
	})
	return found
}

func (m mitigationTree) text(n *tree_sitter.Node) string {
	start, end := n.StartByte(), n.EndByte()
	if end > uint(len(m.source)) || start > end {
		return ""
	}
	return strings.TrimSpace(string(m.source[start:end]))
}

// walkOutsideFunctions visits n and its named descendants, not entering
// nested functions; visit returns false to skip a node's children.
func walkOutsideFunctions(n *tree_sitter.Node, visit func(*tree_sitter.Node) bool) {
	if !visit(n) {
		return
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		if child == nil || functionNodeKinds[child.Kind()] {
			continue
		}
		walkOutsideFunctions(child, visit)
	}
}

// assignmentTargets lists the assigned expressions: Go's expression_list and
// Python's tuple and list targets name several.
func assignmentTargets(left *tree_sitter.Node) []*tree_sitter.Node {
	if left == nil {
		return nil
	}
	switch left.Kind() {
	case "expression_list", "pattern_list", "tuple_pattern", "list_pattern", "tuple", "list":
		var targets []*tree_sitter.Node
		for i := uint(0); i < left.NamedChildCount(); i++ {
			targets = append(targets, left.NamedChild(i))
		}
		return targets
	}
	return []*tree_sitter.Node{left}
}

// topLevelStatements returns the statements of a block, or the statement
// itself when the body is a single statement (JavaScript `if (x) return;`).
func topLevelStatements(body *tree_sitter.Node) []*tree_sitter.Node {
	if !blockNodeKinds[body.Kind()] {
		return []*tree_sitter.Node{body}
	}
	var statements []*tree_sitter.Node
	for i := uint(0); i < body.NamedChildCount(); i++ {
		child := body.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Kind() == "statement_list" {
			statements = append(statements, topLevelStatements(child)...)
			continue
		}
		statements = append(statements, child)
	}
	return statements
}

func firstNamedChild(n *tree_sitter.Node) *tree_sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

// enclosingFunction returns the innermost function around n, n included, or
// nil at module level.
func enclosingFunction(n *tree_sitter.Node) *tree_sitter.Node {
	for cur := n; cur != nil; cur = cur.Parent() {
		if functionNodeKinds[cur.Kind()] {
			return cur
		}
	}
	return nil
}

func sameNode(a, b *tree_sitter.Node) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equals(*b)
}

// insideError reports whether a node lies in a part of the file the parser
// could not make sense of.
func insideError(n *tree_sitter.Node) bool {
	for cur := n; cur != nil; cur = cur.Parent() {
		if cur.IsError() || cur.IsMissing() {
			return true
		}
	}
	return false
}

// inHeader reports whether point lies between the start of an if or elif and
// the end of its condition (and Go's initializer).
func inHeader(conditional *tree_sitter.Node, point tree_sitter.Point) bool {
	end := conditional.StartPosition()
	for _, field := range []string{"initializer", "condition"} {
		if part := conditional.ChildByFieldName(field); part != nil && pointLess(end, part.EndPosition()) {
			end = part.EndPosition()
		}
	}
	return !pointLess(point, conditional.StartPosition()) && pointLess(point, end)
}

func containsPoint(n *tree_sitter.Node, point tree_sitter.Point) bool {
	return !pointLess(point, n.StartPosition()) && pointLess(point, n.EndPosition())
}

func containsNode(outer, inner *tree_sitter.Node) bool {
	return outer.StartByte() <= inner.StartByte() && inner.EndByte() <= outer.EndByte()
}

func pointLess(a, b tree_sitter.Point) bool {
	return a.Row < b.Row || (a.Row == b.Row && a.Column < b.Column)
}

// firstCodePoint is the position of the first non-blank byte of a line.
func firstCodePoint(lines []string, line int) tree_sitter.Point {
	text := lines[line-1]
	return tree_sitter.Point{Row: uint(line - 1), Column: uint(len(text) - len(strings.TrimLeft(text, " \t")))}
}

// ── Without a grammar ────────────────────────────────────────────────────────

var (
	// textGuardPattern: a line that opens a conditional.
	textGuardPattern = regexp.MustCompile(`^\s*(?:\}\s*)?(?:else\s+if|elif|elsif|if|unless|guard)\b`)
	// textAssertPattern: an assertion call or statement.
	textAssertPattern = regexp.MustCompile(`^\s*(?:[A-Za-z_$][\w$]*(?:::|->|\.))*(?:assert\w*|invariant|precondition|require)\s*[(!]`)
	// textExitModifierPattern: Ruby and Perl's `return unless valid?(x)`.
	textExitModifierPattern = regexp.MustCompile(`^\s*(?:return|raise|throw|die|exit|abort|next|break|continue)\b.*\b(?:if|unless)\b`)
	// textAssignmentPattern: `x = ...`, `$x = ...`, `final String x = ...`.
	textAssignmentPattern = regexp.MustCompile(`^\s*(?:[A-Za-z_][\w<>\[\],.?]*\s+)*\$?([A-Za-z_]\w*)\s*:?=\s*(.*)$`)
)

// textMitigationCheck is the shape check for languages without a grammar:
// the code of the cited line opens a conditional, asserts, or exits under a
// condition, naming a shared identifier, or re-assigns a shared name through
// a call that takes it.
func textMitigationCheck(line string, kinds []regions.Kind, shared map[string]bool) error {
	code := codeOnly(line, kinds)
	names := map[string]bool{}
	for _, span := range identifierSpans(code) {
		if name := strings.TrimLeft(code[span[0]:span[1]], "$"); shared[name] {
			names[name] = true
		}
	}
	if len(names) > 0 && (textGuardPattern.MatchString(code) || textAssertPattern.MatchString(code) || textExitModifierPattern.MatchString(code)) {
		return nil
	}
	if match := textAssignmentPattern.FindStringSubmatch(code); match != nil && shared[match[1]] {
		value := strings.TrimSpace(match[2])
		if value != "" && value[0] != '=' && value[0] != '>' && textPassesThroughCall(value, match[1]) {
			return nil
		}
	}
	return errNoMitigationShape
}

// textPassesThroughCall reports whether value calls something with name
// among its arguments (f(x)) or as its receiver (x.f(), $x->f()).
func textPassesThroughCall(value, name string) bool {
	word := regexp.MustCompile(`(?:^|[^\w$])\$?` + regexp.QuoteMeta(name) + `\b`)
	receiver := regexp.MustCompile(`^\$?` + regexp.QuoteMeta(name) + `\s*(?:\.|->)\s*[A-Za-z_]\w*\s*\(`)
	if receiver.MatchString(value) {
		return true
	}
	for open := 0; open < len(value); open++ {
		if value[open] != '(' || open == 0 || !isCallee(value[:open]) {
			continue
		}
		depth := 0
		for end := open; end < len(value); end++ {
			switch value[end] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				if word.MatchString(value[open+1 : end]) {
					return true
				}
				break
			}
		}
	}
	return false
}

// isCallee reports whether the text before an opening parenthesis ends with
// something that can be called: a name, a closing bracket or parenthesis.
func isCallee(before string) bool {
	before = strings.TrimRight(before, " \t")
	if before == "" {
		return false
	}
	last := before[len(before)-1]
	return isIdentifierPart(last) || last == ']' || last == ')'
}

// codeOnly blanks the comment and string-literal bytes of a line.
func codeOnly(line string, kinds []regions.Kind) string {
	if len(kinds) != len(line) {
		return ""
	}
	out := []byte(line)
	for i := range out {
		if kinds[i] != regions.Code {
			out[i] = ' '
		}
	}
	return string(out)
}

func sortedNames(names map[string]bool) string {
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	return strings.Join(list, ", ")
}

func firstName(names map[string]bool) string {
	list := strings.Split(sortedNames(names), ", ")
	if list[0] == "" {
		return "x"
	}
	return list[0]
}
