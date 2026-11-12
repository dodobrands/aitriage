package tui

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/deps"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// ChatMessage represents a single message in the AI chat
type ChatMessage struct {
	Sender   string
	Content  string
	Rendered string // Cached glamour output
}

// PromptAction represents a quick action command in the chat view
type PromptAction struct {
	Label       string // Display text
	Description string // Subtext/description
	Command     string // Internal command identifier (e.g., "GEN_SPEC")
}

// We don't need list.Item anymore since we use table.Model.
// Finding results will be looked up by ID.

// ViewType defines the different screens in the TUI
type ViewType int

const (
	ViewFileViewer ViewType = -2 // Fullscreen file viewer
	ViewBrowser    ViewType = -1 // File browser — start screen before scanning
)

// TopologyNode represents a node in the flattened dependency tree for navigation
type TopologyNode struct {
	ID       string // package/module ID
	Name     string // display name
	Version  string
	Depth    int      // indentation level
	IsRoot   bool     // true if root module
	HasKids  bool     // true if has children
	Children []string // child IDs
}

// LoadingStep represents a step in the Virtual Foundry loading sequence
type LoadingStep struct {
	Label string // e.g. "Initializing rule engine"
	Done  bool   // true if completed
}

const (
	ViewDashboard ViewType = iota
	ViewTriage
	ViewSAST
	ViewAudit
	ViewReports
	ViewChat
	ViewDeps  // Unified Dependency Audit
	ViewGraph // Dependency Graph Visualization
	ViewInfra
	ViewLogs
	ViewConfig // Configuration management
)

// DashFileData represents a file with vulnerability counts for dashboard caching
type DashFileData struct {
	Path  string
	Count int
}

// DashCatData represents a vulnerability category for dashboard caching
type DashCatData struct {
	Name     string
	Count    int
	Severity string
}

// DashOWASPData represents an OWASP category for dashboard caching
type DashOWASPData struct {
	Name  string
	Count int
}

// DashboardModel is the core state of the TUI
type DashboardModel struct {
	Report     scanner.ScanReport
	ActiveView ViewType

	// Dashboard Caches (Anti-Flicker)
	DashFiles []DashFileData
	DashCats  []DashCatData
	DashOWASP []DashOWASPData

	// Audit Persistence
	AuditStore  *core.AuditStore
	ShowIgnored bool

	// Dashboard Navigation
	DashFocusPanel int // 0: None, 1: FINDINGS.MAP, 2: TOP.FILES
	DashMapCursor  int
	DashFileCursor int

	// External scanner findings (from orchestrator)
	ExternalFindings []external.UnifiedFinding
	NFRFindings      []nfr.NFRFinding
	DeployFindings   []deployaudit.DeployFinding
	NetworkFindings  []network.NetworkFinding

	// View-specific models
	Table               table.Model          // For ViewTriage
	SASTTable           table.Model          // For ViewSAST (external findings)
	DepsTable           table.Model          // For ViewDeps
	InfraTable          table.Model          // For ViewInfra
	Viewport            viewport.Model       // For ViewCode and Detail views (Code Preview in Triage)
	FileViewport        viewport.Model       // For ViewFileViewer (Full screen file viewing)
	RemediationViewport viewport.Model       // For Remediation details in Triage
	SASTViewport        viewport.Model       // For SAST detail pane
	ChatViewport        viewport.Model       // For ViewChat history
	GraphViewport       viewport.Model       // For ViewGraph visualization
	DepGraph            deps.DependencyGraph // For graph tab
	TextInput           textinput.Model      // For ViewChat
	ChatHistory         []ChatMessage        // For ViewChat
	Ready               bool

	// ViewConfig state
	ConfigInputs     []textinput.Model
	ConfigFocusIndex int
	ConfigSavedMsg   string
	ConfigSavedTTL   int

	// Window dimensions
	Width  int
	Height int

	// Agent execution state
	ExecutingAgent bool
	ScanInProgress bool
	LLMClient      llm.Client

	// Metadata
	Version       string
	ScanStartTime time.Time

	// Animation state
	TickCount int

	// Panel focus: Tab toggles between table (left) and detail viewport (right)
	SASTFocusDetail   bool // true = arrows scroll SAST detail viewport
	TriageFocusDetail bool // true = arrows scroll Triage remediation viewport

	// AI analysis cache: persists results so they survive navigation
	SASTAnalysisCache   map[string]string // key = "SOURCE:RULE_ID"
	TriageAnalysisCache map[string]string // key = finding ID
	SASTLastCursor      int               // detect cursor change → reset focus
	TriageLastCursor    int               // detect cursor change → reset focus

	// AI loading animation state
	TriageAnalyzing   bool   // true when AI is processing a triage finding
	TriageAnalyzingID string // ID of the finding being analyzed
	SASTAnalyzing     bool   // true when AI is processing a SAST finding
	SASTAnalyzingKey  string // key of the finding being analyzed

	// Dashboard AI summary
	DashboardSummary        string // cached AI executive summary
	DashboardSummaryLoading bool   // true when generating summary

	// Chat state — Security Operations Center (split-pane)
	ChatAnalyzing bool           // true when waiting for AI chat response
	QuickPrompts  []PromptAction // Available quick actions (categorized)
	PromptCursor  int            // Currently selected quick action index
	ChatFocusMode int            // 0 = Command Panel (left), 1 = Chat History (right), 2 = Text Input

	// Toast notification
	StatusMsg string // temporary status message shown in footer
	StatusTTL int    // ticks remaining before clearing StatusMsg

	// Token usage tracking
	TokensUsed int // Total tokens consumed by LLM interactions

	// Tab 9 — Operational Logs
	LogViewport   viewport.Model
	LogEntries    []LogEntry
	LogAutoScroll bool
	LogFilter     LogLevel

	// Graph rendering cache
	GraphTreeCache string // cached RenderDependencyTree output

	// Tab 8 — Topology: Interactive dependency tree
	TopologyNodes    []TopologyNode  // flattened tree for navigation
	TopologyCursor   int             // selected node index
	TopologyExpanded map[string]bool // which nodes are expanded (by ID)
	TopologyFilter   string          // search filter text
	TopologyDetail   string          // cached detail for selected node

	// Tab 9 — Ops Center: unified operations view
	InfraCategory     int            // 0=ALL, 1=NFR, 2=DEPLOY, 3=NETWORK
	InfraDetailCache  map[int]string // cached AI analysis per row index
	InfraAnalyzing    bool           // true when AI is analyzing an infra finding
	InfraAnalyzingIdx int            // index of finding being analyzed

	// Search and Filtering
	SearchMode       bool            // true when user is typing in the deep search bar
	SearchInput      textinput.Model // the input model for the search bar
	SearchQuery      string          // current active filter string
	InfraFocusDetail bool            // true = arrows control detail viewport
	InfraDetailVP    viewport.Model  // right panel viewport for ops center

	// Unified loading overlay (Virtual Foundry style)
	LoadingActive bool          // true = show loading overlay
	LoadingSteps  []LoadingStep // steps to display
	LoadingStep   int           // current step index

	// File Browser state
	BrowserDir     string         // current directory being browsed
	BrowserEntries []BrowserEntry // visible entries in current dir
	BrowserCursor  int            // selected entry index
	BrowserScroll  int            // scroll offset for large directories

	// Rule Builder state
	RuleBuilderActive bool            // true when Rule Builder UI is active
	RuleBuilderTarget string          // file path being analyzed for rule generation
	RuleBuilderInput  textinput.Model // input field for rule generation intent
	RuleGenerating    bool            // true when rule is being generated
}

// Init initializes the tea program
func (m DashboardModel) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type tickMsg time.Time

// buildDepsRows constructs table rows from dependencies
func buildDepsRows(dependencies []deps.Dependency) []table.Row {
	rows := make([]table.Row, 0, len(dependencies))
	for _, d := range dependencies {
		rows = append(rows, table.Row{
			truncate(d.Name, 35),
			truncate(d.Version, 20),
			d.Type,
			d.Ecosystem,
		})
	}
	return rows
}

// buildSASTRows constructs table rows from all external/NFR findings
func buildSASTRows(ext []external.UnifiedFinding, nfrF []nfr.NFRFinding) []table.Row {
	rows := make([]table.Row, 0, len(ext)+len(nfrF))
	for _, f := range ext {
		rows = append(rows, table.Row{
			strings.ToUpper(f.Source),
			f.RuleID,
			f.Severity,
			truncate(f.Message, 35),
			f.File,
		})
	}
	for _, f := range nfrF {
		rows = append(rows, table.Row{
			"NFR",
			f.RuleID,
			f.Severity,
			truncate(f.Name, 35),
			"",
		})
	}
	return rows
}

// buildInfraRows constructs table rows from deploy and network findings
func buildInfraRows(deploy []deployaudit.DeployFinding, net []network.NetworkFinding) []table.Row {
	rows := make([]table.Row, 0, len(deploy)+len(net))
	for _, f := range deploy {
		rows = append(rows, table.Row{
			"IaC",
			f.Severity,
			truncate(f.Issue, 45),
			f.File,
		})
	}
	for _, f := range net {
		rows = append(rows, table.Row{
			"NETWORK",
			f.Severity,
			truncate(fmt.Sprintf("Port %d (%s): %s", f.Port, f.Service, f.Message), 45),
			f.Target,
		})
	}
	return rows
}

func buildSASTRowsFiltered(ext []external.UnifiedFinding, nfrF []nfr.NFRFinding, query string) []table.Row {
	var rows []table.Row
	for _, f := range ext {
		if query == "" || strings.Contains(strings.ToLower(f.Source), query) || strings.Contains(strings.ToLower(f.RuleID), query) || strings.Contains(strings.ToLower(f.Message), query) || strings.Contains(strings.ToLower(f.File), query) {
			rows = append(rows, table.Row{
				strings.ToUpper(f.Source),
				f.RuleID,
				f.Severity,
				truncate(f.Message, 35),
				f.File,
			})
		}
	}
	for _, f := range nfrF {
		if query == "" || strings.Contains(strings.ToLower(f.RuleID), query) || strings.Contains(strings.ToLower(f.Name), query) {
			rows = append(rows, table.Row{
				"NFR",
				f.RuleID,
				f.Severity,
				truncate(f.Name, 35),
				"",
			})
		}
	}
	return rows
}

func buildInfraRowsFiltered(deploy []deployaudit.DeployFinding, net []network.NetworkFinding, query string) []table.Row {
	var rows []table.Row
	for _, f := range deploy {
		if query == "" || strings.Contains(strings.ToLower(f.Issue), query) || strings.Contains(strings.ToLower(f.File), query) {
			rows = append(rows, table.Row{
				"IaC",
				f.Severity,
				truncate(f.Issue, 45),
				f.File,
			})
		}
	}
	for _, f := range net {
		if query == "" || strings.Contains(strings.ToLower(f.Message), query) || strings.Contains(strings.ToLower(f.Target), query) || strings.Contains(strings.ToLower(f.Service), query) {
			rows = append(rows, table.Row{
				"NETWORK",
				f.Severity,
				truncate(fmt.Sprintf("Port %d (%s): %s", f.Port, f.Service, f.Message), 45),
				f.Target,
			})
		}
	}
	return rows
}

func buildDepsRowsFiltered(depsGraph []deps.Dependency, query string) []table.Row {
	var rows []table.Row
	for _, d := range depsGraph {
		if query == "" || strings.Contains(strings.ToLower(d.Name), query) || strings.Contains(strings.ToLower(d.Type), query) || strings.Contains(strings.ToLower(d.Ecosystem), query) {
			rows = append(rows, table.Row{
				truncate(d.Name, 35),
				truncate(d.Version, 20),
				d.Type,
				d.Ecosystem,
			})
		}
	}
	return rows
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// updateViewportContent updates the right panes with the currently selected item's details
func (m *DashboardModel) updateViewportContent() {
	row := m.Table.SelectedRow()
	if row == nil {
		m.Viewport.SetContent("No vulnerability selected.")
		m.RemediationViewport.SetContent("")
		return
	}

	id := row[0]
	var res *core.CheckResult
	for _, r := range m.Report.Results {
		if r.ID == id {
			res = &r
			break
		}
	}

	if res == nil {
		return
	}

	// 1. Update Code Viewport
	if res.File != "" {
		codeCtx := readCodeContext(res.File, res.Line, 8) // More context for the split view
		if codeCtx != "" {
			m.Viewport.SetContent(codeCtx)
		} else {
			m.Viewport.SetContent(fmt.Sprintf("Could not read file: %s", res.File))
		}
	} else {
		m.Viewport.SetContent("No file information available.")
	}

	// 2. Update Remediation Viewport — check cache FIRST
	if cached, ok := m.TriageAnalysisCache[id]; ok {
		m.RemediationViewport.SetContent(cached)
		return
	}

	// No cache — show default finding details
	var rb strings.Builder

	rb.WriteString(lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("FINDING: "+res.Name) + "\n\n")

	fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("SEVERITY:"), m.getSeverityStyled(res.Severity))
	fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("FILE:    "), res.File)
	fmt.Fprintf(&rb, "%s %d\n", labelStyle.Render("LINE:    "), res.Line)
	if res.OWASPMapping != "" {
		fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("OWASP:   "), res.OWASPMapping)
	}
	rb.WriteString("\n")

	rb.WriteString(labelStyle.Render("DESCRIPTION / SUGGESTION:") + "\n")
	rb.WriteString(res.Suggestion + "\n\n")

	if res.Evidence != "" {
		rb.WriteString(labelStyle.Render("EVIDENCE:") + "\n")
		rb.WriteString(lipgloss.NewStyle().Foreground(colorGray).Render(res.Evidence) + "\n")
	}

	rb.WriteString("\n" + lipgloss.NewStyle().Foreground(colorGray).Italic(true).Render("Press ENTER for AI analysis") + "\n")

	m.RemediationViewport.SetContent(rb.String())
}

// updateSASTViewportContent updates the SAST detail pane
func (m *DashboardModel) updateSASTViewportContent() {
	row := m.SASTTable.SelectedRow()
	if row == nil {
		m.SASTViewport.SetContent("No finding selected.")
		return
	}

	source := row[0]
	ruleID := row[1]
	sev := row[2]
	file := row[4]

	// Check SAST cache FIRST
	cacheKey := source + ":" + ruleID
	if cached, ok := m.SASTAnalysisCache[cacheKey]; ok {
		m.SASTViewport.SetContent(cached)
		return
	}

	// No cache — show default finding details
	var rb strings.Builder

	rb.WriteString(lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("EXTERNAL FINDING") + "\n\n")
	fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("SOURCE:  "), lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Render(source))
	fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("RULE:    "), ruleID)
	fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("SEVERITY:"), m.getSeverityStyled(sev))
	if file != "" {
		fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("FILE:    "), file)
	}
	rb.WriteString("\n")

	// Find full details from the findings slices
	switch source {
	case "SEMGREP", "GITLEAKS", "TRIVY", "BANDIT":
		for _, f := range m.ExternalFindings {
			if strings.ToUpper(f.Source) == source && f.RuleID == ruleID {
				rb.WriteString(labelStyle.Render("MESSAGE:") + "\n")
				rb.WriteString(lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Render(f.Message) + "\n\n")
				if f.Suggestion != "" {
					rb.WriteString(labelStyle.Render("SUGGESTION:") + "\n")
					rb.WriteString(lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(f.Suggestion) + "\n")
				}
				if f.OWASP != "" {
					fmt.Fprintf(&rb, "%s %s\n", labelStyle.Render("OWASP:   "), f.OWASP)
				}

				// Show code context if file+line available
				if f.File != "" && f.Line > 0 {
					codeCtx := readCodeContext(f.File, f.Line, 5)
					if codeCtx != "" {
						rb.WriteString("\n" + labelStyle.Render("SOURCE CODE:") + "\n")
						rb.WriteString(codeCtx)
					}
				}
				break
			}
		}
	case "NFR":
		for _, f := range m.NFRFindings {
			if f.RuleID == ruleID {
				rb.WriteString(labelStyle.Render("NAME:") + "\n")
				rb.WriteString(lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Render(f.Name) + "\n\n")
				rb.WriteString(labelStyle.Render("MESSAGE:") + "\n")
				rb.WriteString(lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(f.Message) + "\n\n")
				if f.Advice != "" {
					rb.WriteString(labelStyle.Render("ADVICE:") + "\n")
					rb.WriteString(lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(f.Advice) + "\n")
				}
				break
			}
		}
	case "DEPLOY":
		for _, f := range m.DeployFindings {
			if f.Issue == ruleID {
				rb.WriteString(labelStyle.Render("EVIDENCE:") + "\n")
				rb.WriteString(lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Render(f.Evidence) + "\n\n")
				rb.WriteString(labelStyle.Render("ADVICE:") + "\n")
				rb.WriteString(lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(f.Advice) + "\n")

				if f.File != "" && f.Line > 0 {
					codeCtx := readCodeContext(f.File, f.Line, 5)
					if codeCtx != "" {
						rb.WriteString("\n" + labelStyle.Render("SOURCE CODE:") + "\n")
						rb.WriteString(codeCtx)
					}
				}
				break
			}
		}
	}

	rb.WriteString("\n" + lipgloss.NewStyle().Foreground(colorGray).Italic(true).Render("Press ENTER for AI analysis") + "\n")

	m.SASTViewport.SetContent(rb.String())
}

func (m DashboardModel) getSeverityStyled(sev string) string {
	switch sev {
	case "CRITICAL":
		return criticalStyle.Render(sev)
	case "HIGH":
		return highStyle.Render(sev)
	case "MEDIUM":
		return mediumStyle.Render(sev)
	default:
		return lowStyle.Render(sev)
	}
}

func (m *DashboardModel) updateChatViewport() {
	var b strings.Builder

	// Unified styles — ALL use colorBG (#0d1515) for consistent background
	userPrompt := lipgloss.NewStyle().Foreground(colorPrimaryCont).Background(colorBG).Bold(true)
	userText := lipgloss.NewStyle().Foreground(colorText).Background(colorBG)
	aiLabel := lipgloss.NewStyle().Foreground(colorSecondary).Background(colorBG).Bold(true)
	thinkStyle := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Italic(true)
	sysText := lipgloss.NewStyle().Foreground(colorError).Background(colorBG)

	wrapWidth := m.ChatViewport.Width - 4
	if wrapWidth < 20 {
		wrapWidth = 60
	}

	// Initialize glamour renderer for markdown ONLY if we need to render new messages
	renderer, _ := glamour.NewTermRenderer(
		glamour.WithStandardStyle("dark"),
		glamour.WithWordWrap(wrapWidth),
	)

	for i, msg := range m.ChatHistory {
		switch msg.Sender {
		case "USER":
			b.WriteString(userPrompt.Render("❯ ") + userText.Render(msg.Content) + "\n")
		case "AI":
			b.WriteString(aiLabel.Render("AI") + "\n")
			// Use cached rendering if available
			if msg.Rendered != "" {
				b.WriteString(msg.Rendered + "\n")
			} else if renderer != nil {
				rendered, err := renderer.Render(msg.Content)
				if err == nil {
					rendered = strings.TrimRight(rendered, "\n")
					m.ChatHistory[i].Rendered = rendered
					b.WriteString(rendered + "\n")
				} else {
					b.WriteString(wordWrap(msg.Content, wrapWidth) + "\n")
				}
			} else {
				b.WriteString(wordWrap(msg.Content, wrapWidth) + "\n")
			}
		case "THINKING":
			// Animated thinking indicator — NOT cached since it changes every tick
			b.WriteString(thinkStyle.Render(msg.Content) + "\n")
		case "SYSTEM":
			b.WriteString(sysText.Render("⚠ "+msg.Content) + "\n")
		default:
			b.WriteString(lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(msg.Content) + "\n")
		}
	}
	m.ChatViewport.SetContent(b.String())
	m.ChatViewport.GotoBottom()
}

// wordWrap breaks text into lines of at most width characters, respecting word boundaries.
func wordWrap(text string, width int) string {
	if width <= 0 || len(text) <= width {
		return text
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
		} else {
			line += " " + w
		}
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n")
}

// highlightCode applies syntax highlighting to the code string based on filename.
func highlightCode(filename string, code string) string {
	lexer := lexers.Match(filename)
	if lexer == nil {
		lexer = lexers.Fallback
	}
	lexer = chroma.Coalesce(lexer)

	style := styles.Get("monokai") // Silent Luxury appropriate dark theme
	if style == nil {
		style = styles.Fallback
	}
	formatter := formatters.Get("terminal256")
	if formatter == nil {
		formatter = formatters.Fallback
	}

	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return code
	}

	var b strings.Builder
	err = formatter.Format(&b, style, iterator)
	if err != nil {
		return code
	}
	return b.String()
}

// readCodeContext reads the target file and returns a formatted snippet around targetLine
func readCodeContext(filepath string, targetLine int, context int) string {
	file, err := os.Open(filepath)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	currentLine := 1
	startLine := targetLine - context
	if startLine < 1 {
		startLine = 1
	}
	endLine := targetLine + context

	var rawLines []string
	var lineNumbers []int

	for scanner.Scan() {
		if currentLine >= startLine && currentLine <= endLine {
			lineText := scanner.Text()
			lineText = strings.ReplaceAll(lineText, "\t", "    ")
			rawLines = append(rawLines, lineText)
			lineNumbers = append(lineNumbers, currentLine)
		}
		if currentLine > endLine {
			break
		}
		currentLine++
	}

	// Apply Syntax Highlighting to the entire block
	rawBlock := strings.Join(rawLines, "\n")
	highlightedBlock := highlightCode(filepath, rawBlock)
	highlightedLines := strings.Split(highlightedBlock, "\n")

	var b strings.Builder
	bgHighlight := lipgloss.NewStyle().Background(lipgloss.Color("#2A2A2A")) // Subdued luxury highlight

	for i, lineNum := range lineNumbers {
		linePrefix := fmt.Sprintf("%4d │ ", lineNum)
		hl := ""
		if i < len(highlightedLines) {
			hl = highlightedLines[i]
		}

		if lineNum == targetLine {
			// Prefix gets primary color, content gets background highlight but retains Chroma colors
			prefix := lipgloss.NewStyle().Foreground(colorPrimaryCont).Bold(true).Render(linePrefix)
			content := bgHighlight.Render(hl)
			b.WriteString(prefix + content + "\n")
		} else {
			prefix := lipgloss.NewStyle().Foreground(colorGray).Render(linePrefix)
			b.WriteString(prefix + hl + "\n")
		}
	}

	return b.String()
}

// rebuildTableRows reconstructs the table rows from the current Report.
// Called after a re-scan completes to refresh the triage view.
func (m *DashboardModel) rebuildTableRows() {
	query := strings.ToLower(m.SearchQuery)
	rows := make([]table.Row, 0, len(m.Report.Results))
	for _, res := range m.Report.Results {
		if query != "" {
			match := strings.Contains(strings.ToLower(res.Name), query) ||
				strings.Contains(strings.ToLower(res.File), query) ||
				strings.Contains(strings.ToLower(res.ID), query) ||
				strings.Contains(strings.ToLower(res.Severity), query)
			if !match {
				continue
			}
		}
		rows = append(rows, table.Row{
			res.ID,
			res.Severity,
			res.Name,
			res.File,
			string(res.Status),
		})
	}
	m.Table.SetRows(rows)
}

// rebuildSASTTableRows reconstructs the SAST table from current external findings.
func (m *DashboardModel) rebuildSASTTableRows() {
	m.SASTTable.SetRows(buildSASTRows(m.ExternalFindings, m.NFRFindings))
}

// rebuildInfraTableRows reconstructs the Infra table from current findings.
func (m *DashboardModel) rebuildInfraTableRows() {
	m.InfraTable.SetRows(buildInfraRows(m.DeployFindings, m.NetworkFindings))
}

// rebuildDepsTableRows reconstructs the Deps table from current report dependencies.
func (m *DashboardModel) rebuildDepsTableRows() {
	m.DepsTable.SetRows(buildDepsRows(m.Report.Dependencies))
}

// rebuildGraphCache re-renders the dependency tree and updates the graph viewport.
func (m *DashboardModel) rebuildGraphCache() {
	m.DepGraph = m.Report.DependencyGraph
	m.GraphTreeCache = RenderDependencyTree(m.DepGraph)
	m.GraphViewport.SetContent(m.GraphTreeCache)
	m.rebuildTopologyNodes()
}

// InitialBrowserModel creates a DashboardModel in file browser mode.
// No scan is performed — the user selects a project directory first.
func InitialBrowserModel(startDir string, version string) DashboardModel {
	absDir, err := filepath.Abs(startDir)
	if err != nil {
		absDir = startDir
	}

	entries, _ := scanDirectory(absDir)

	// ── Tables (empty but focused, ready for post-scan population) ──
	emptyCol := []table.Column{{Title: "—", Width: 10}}
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorOutline).
		BorderBottom(true).
		Bold(false).
		Foreground(colorGray).
		Background(colorBG)
	s.Selected = s.Selected.
		Foreground(colorOnPrimary).
		Background(colorPrimaryCont).
		Bold(true)
	s.Cell = s.Cell.Background(colorBG)

	t := table.New(
		table.WithColumns(emptyCol),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(15),
	)
	t.SetStyles(s)

	st := table.New(
		table.WithColumns(emptyCol),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(15),
	)
	st.SetStyles(s)

	dt := table.New(
		table.WithColumns(emptyCol),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(15),
	)
	dt.SetStyles(s)

	it := table.New(
		table.WithColumns(emptyCol),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(15),
	)
	it.SetStyles(s)

	// ── Viewports ──
	vpStyle := lipgloss.NewStyle().Background(colorBG).Foreground(colorText).ColorWhitespace(true)
	vp := viewport.New(0, 0)
	vp.Style = vpStyle
	fvp := viewport.New(0, 0)
	fvp.Style = vpStyle
	rvp := viewport.New(0, 0)
	rvp.Style = vpStyle
	svp := viewport.New(0, 0)
	svp.Style = vpStyle
	cvp := viewport.New(0, 0)
	cvp.Style = vpStyle
	gvp := viewport.New(0, 0)
	gvp.Style = vpStyle
	ivp := viewport.New(0, 0)
	ivp.Style = vpStyle

	// ── Text inputs ──
	ti := textinput.New()
	ti.Placeholder = "Ask the AI Consultant..."
	ti.Blur()

	si := textinput.New()
	si.Placeholder = "Search... (ESC to cancel)"
	si.Prompt = "/ "
	si.PromptStyle = lipgloss.NewStyle().Foreground(colorSecondary).Bold(true)
	si.TextStyle = lipgloss.NewStyle().Foreground(colorText).Background(colorSurfaceHigh)
	si.PlaceholderStyle = lipgloss.NewStyle().Foreground(colorGray).Background(colorSurfaceHigh)
	si.Cursor.Style = lipgloss.NewStyle().Foreground(colorSecondary)
	si.Blur()

	return DashboardModel{
		ActiveView:          ViewBrowser,
		Version:             version,
		ScanStartTime:       time.Now(),
		BrowserDir:          absDir,
		BrowserEntries:      entries,
		BrowserCursor:       0,
		Table:               t,
		SASTTable:           st,
		DepsTable:           dt,
		InfraTable:          it,
		Viewport:            vp,
		FileViewport:        fvp,
		RemediationViewport: rvp,
		SASTViewport:        svp,
		ChatViewport:        cvp,
		GraphViewport:       gvp,
		InfraDetailVP:       ivp,
		TextInput:           ti,
		SearchInput:         si,
		SearchQuery:         "",
		SASTAnalysisCache:   make(map[string]string),
		TriageAnalysisCache: make(map[string]string),
		SASTLastCursor:      -1,
		TriageLastCursor:    -1,
		ChatAnalyzing:       false,
		PromptCursor:        0,
		QuickPrompts: []PromptAction{
			// ── ANALYSIS ──
			{Label: "[BRIEF] Full Security Briefing", Description: "Executive summary of all findings, risk score, and immediate action plan", Command: "FULL_BRIEFING"},
			{Label: "[CRIT]  Critical Path Analysis", Description: "Map exploitability chains from entry points to critical assets", Command: "CRIT_PATH"},
			{Label: "[CVE]   Top 3 Critical CVEs", Description: "Deep-dive the 3 most dangerous vulnerabilities with CVSS breakdown", Command: "TOP_CRIT"},
			{Label: "[STRIDE] Threat Model", Description: "STRIDE-based threat model of the project architecture", Command: "THREAT_MODEL"},
			// ── REMEDIATION ──
			{Label: "[FIX]   Auto-Fix Plan", Description: "Prioritized remediation backlog with code examples", Command: "FIX_PLAN"},
			{Label: "[SECRETS] Secrets Remediation", Description: "Identify and rotate all leaked credentials and secrets", Command: "SECRETS_FIX"},
			{Label: "[DEPS]  Dependency Hardening", Description: "Pin versions, remove unused deps, enforce lockfiles", Command: "DEP_HARDEN"},
			{Label: "[NET]   Network Attack Surface", Description: "Analyze exposed ports, unauth endpoints, CORS, rate limits", Command: "NET_SURFACE"},
			// ── COMPLIANCE ──
			{Label: "[OWASP] Top 10 Audit", Description: "Map findings to OWASP Top 10 2021 categories", Command: "OWASP_AUDIT"},
			{Label: "[SPEC]  Generate CLAUDE.md", Description: "AI-ready project specification for security workflows", Command: "GEN_SPEC"},
			{Label: "[SAST]  Coverage Report", Description: "What code paths are covered vs. blind spots", Command: "SAST_COVERAGE"},
			{Label: "[NFR]   Security Check", Description: "Auth, rate limiting, CORS, logging, and error handling gaps", Command: "NFR_CHECK"},
		},
		TopologyExpanded: make(map[string]bool),
		InfraDetailCache: make(map[int]string),
		LogViewport:      viewport.New(0, 0),
		LogAutoScroll:    true,
		LogFilter:        -1,
		ConfigInputs:     make([]textinput.Model, 0),
	}
}

// loadBrowserDir reads a directory and updates browser state.
func (m *DashboardModel) loadBrowserDir(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return
	}
	entries, err := scanDirectory(absDir)
	if err != nil {
		return
	}

	if m.SearchQuery != "" {
		var filtered []BrowserEntry
		q := strings.ToLower(m.SearchQuery)
		for _, e := range entries {
			// Always keep '..' navigation
			if e.Name == ".." {
				filtered = append(filtered, e)
				continue
			}
			if strings.Contains(strings.ToLower(e.Name), q) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	m.BrowserDir = absDir
	m.BrowserEntries = entries
	m.BrowserCursor = 0
	m.BrowserScroll = 0
}

func (m *DashboardModel) updateDashboardData() {
	if len(m.Report.Results) == 0 {
		m.DashFiles = nil
		m.DashCats = nil
		m.DashOWASP = nil
		return
	}

	// 1. Findings Map (Categories)
	catCounts := make(map[string]int)
	catSev := make(map[string]string)
	sevOrd := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for _, res := range m.Report.Results {
		cat := res.ID
		if idx := strings.Index(res.ID, "-"); idx > 0 {
			cat = res.ID[:idx]
		}
		catCounts[cat]++
		if sevOrd[res.Severity] > sevOrd[catSev[cat]] {
			catSev[cat] = res.Severity
		}
	}
	m.DashCats = nil
	for k, v := range catCounts {
		m.DashCats = append(m.DashCats, DashCatData{k, v, catSev[k]})
	}
	for i := 0; i < len(m.DashCats); i++ {
		for j := i + 1; j < len(m.DashCats); j++ {
			if m.DashCats[j].Count > m.DashCats[i].Count || (m.DashCats[j].Count == m.DashCats[i].Count && m.DashCats[j].Name < m.DashCats[i].Name) {
				m.DashCats[i], m.DashCats[j] = m.DashCats[j], m.DashCats[i]
			}
		}
	}

	// 2. Top Files
	fileCnt := make(map[string]int)
	for _, r := range m.Report.Results {
		if r.File != "" {
			fileCnt[r.File]++
		}
	}
	m.DashFiles = nil
	for k, v := range fileCnt {
		m.DashFiles = append(m.DashFiles, DashFileData{k, v})
	}
	for i := 0; i < len(m.DashFiles); i++ {
		for j := i + 1; j < len(m.DashFiles); j++ {
			if m.DashFiles[j].Count > m.DashFiles[i].Count || (m.DashFiles[j].Count == m.DashFiles[i].Count && m.DashFiles[j].Path < m.DashFiles[i].Path) {
				m.DashFiles[i], m.DashFiles[j] = m.DashFiles[j], m.DashFiles[i]
			}
		}
	}

	// 3. OWASP Map
	owaspH := make(map[string]int)
	for _, r := range m.Report.Results {
		if r.OWASPMapping != "" {
			owaspH[r.OWASPMapping]++
		}
	}
	m.DashOWASP = nil
	for k, v := range owaspH {
		m.DashOWASP = append(m.DashOWASP, DashOWASPData{k, v})
	}
	for i := 0; i < len(m.DashOWASP); i++ {
		for j := i + 1; j < len(m.DashOWASP); j++ {
			if m.DashOWASP[j].Count > m.DashOWASP[i].Count || (m.DashOWASP[j].Count == m.DashOWASP[i].Count && m.DashOWASP[j].Name < m.DashOWASP[i].Name) {
				m.DashOWASP[i], m.DashOWASP[j] = m.DashOWASP[j], m.DashOWASP[i]
			}
		}
	}
}

// updateTriageTable rebuilds the rows based on ShowIgnored and AuditStatus
func (m *DashboardModel) updateTriageTable() {
	rows := make([]table.Row, 0)
	for _, res := range m.Report.Results {
		if !m.ShowIgnored && res.AuditStatus == core.AuditStatusIgnored {
			continue
		}

		status := string(res.Status)
		if res.AuditStatus != "" && res.AuditStatus != core.AuditStatusOpen {
			status = string(res.AuditStatus)
		}

		rows = append(rows, table.Row{
			res.ID,
			res.Severity,
			res.Name,
			res.File,
			status,
		})
	}
	m.Table.SetRows(rows)
}
