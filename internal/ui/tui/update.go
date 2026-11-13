package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	lipgloss "github.com/charmbracelet/lipgloss"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/remedy"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/scanner/network"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
	"github.com/dodobrands/aitriage/internal/telemetry"
)

// ── Cyrillic → Latin QWERTY normalization ────────────────────────────────────
// Maps physical key positions from ЙЦУКЕН to QWERTY so hotkeys work
// regardless of the active keyboard layout (Russian, Ukrainian, etc.)
var cyrToLatin = map[rune]rune{
	'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y', 'г': 'u', 'ш': 'i', 'щ': 'o', 'з': 'p',
	'х': '[', 'ъ': ']',
	'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f', 'п': 'g', 'р': 'h', 'о': 'j', 'л': 'k', 'д': 'l',
	'ж': ';', 'э': '\'',
	'я': 'z', 'ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n', 'ь': 'm',
	'б': ',', 'ю': '.',
	// Uppercase
	'Й': 'Q', 'Ц': 'W', 'У': 'E', 'К': 'R', 'Е': 'T', 'Н': 'Y', 'Г': 'U', 'Ш': 'I', 'Щ': 'O', 'З': 'P',
	'Х': '{', 'Ъ': '}',
	'Ф': 'A', 'Ы': 'S', 'В': 'D', 'А': 'F', 'П': 'G', 'Р': 'H', 'О': 'J', 'Л': 'K', 'Д': 'L',
	'Ж': ':', 'Э': '"',
	'Я': 'Z', 'Ч': 'X', 'С': 'C', 'М': 'V', 'И': 'B', 'Т': 'N', 'Ь': 'M',
	'Б': '<', 'Ю': '>',
}

// normalizeKey maps a Cyrillic character to its Latin QWERTY physical equivalent.
// Non-Cyrillic strings (arrows, ctrl+c, enter, etc.) pass through unchanged.
func normalizeKey(s string) string {
	r := []rune(s)
	if len(r) == 1 {
		if lat, ok := cyrToLatin[r[0]]; ok {
			return string(lat)
		}
	}
	return s
}

type editorFinishedMsg struct{ err error }

type aiCommitMsg struct {
	msg string
	err error
}

// Update handles incoming events and updates the state
func (m *DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Normalize Cyrillic → Latin for hotkey matching (ЙЦУКЕН → QWERTY)
		// This ensures physical key positions work regardless of keyboard layout.
		// Text input components (SearchInput, TextInput) still receive the raw msg.
		keyStr := normalizeKey(msg.String())

		// ── Search Mode Intercept ──────────────────────────────────────────
		if m.SearchMode {
			switch msg.String() { // raw msg — user is typing text, not hotkeys
			case "esc":
				m.SearchMode = false
				m.SearchInput.Blur()
				return m, nil
			case "enter":
				m.SearchMode = false
				m.SearchInput.Blur()
				m.SearchQuery = m.SearchInput.Value()
				m.applySearchFilter()
				return m, nil
			case "ctrl+c":
				return m, tea.Quit
			default:
				m.SearchInput, cmd = m.SearchInput.Update(msg) // raw msg for text
				m.SearchQuery = m.SearchInput.Value()
				m.applySearchFilter()
				return m, cmd
			}
		}

		// ── ViewFileViewer: dedicated handler ───────────────────────────────
		if m.ActiveView == ViewFileViewer {
			switch keyStr {
			case "esc", "q", "backspace", "0":
				m.ActiveView = ViewBrowser
				return m, nil
			default:
				var cmd tea.Cmd
				m.FileViewport, cmd = m.FileViewport.Update(msg)
				return m, cmd
			}
		}

		// ── Rule Builder Intercept ──────────────────────────────────────────
		if m.RuleBuilderActive {
			switch msg.String() {
			case "esc":
				m.RuleBuilderActive = false
				m.RuleBuilderInput.Blur()
				return m, nil
			case "enter":
				m.RuleBuilderActive = false
				m.RuleBuilderInput.Blur()
				intent := m.RuleBuilderInput.Value()
				target := m.RuleBuilderTarget

				// Optional: switch to dashboard or scanning view to show generation
				m.RuleGenerating = true
				m.StatusMsg = "Generating rule for " + filepath.Base(target) + "..."
				m.StatusTTL = 60

				// Launch a tea.Cmd for rule generation
				return m, m.generateRuleCmd(target, intent)
			case "ctrl+c":
				return m, tea.Quit
			default:
				m.RuleBuilderInput, cmd = m.RuleBuilderInput.Update(msg)
				return m, cmd
			}
		}

		// ── ViewBrowser: dedicated handler ──────────────────────────────────
		if m.ActiveView == ViewBrowser {
			switch keyStr {
			case "ctrl+c", "q":
				return m, tea.Quit
			case "up", "k":
				if m.BrowserCursor > 0 {
					m.BrowserCursor--
				}
				return m, nil
			case "down", "j":
				if m.BrowserCursor < len(m.BrowserEntries)-1 {
					m.BrowserCursor++
				}
				return m, nil
			case "enter":
				if m.BrowserCursor < len(m.BrowserEntries) {
					entry := m.BrowserEntries[m.BrowserCursor]
					if entry.IsDir {
						// Navigate into directory
						m.loadBrowserDir(entry.Path)
					} else {
						// Load file into fullscreen viewer
						contentBytes, err := os.ReadFile(entry.Path)
						if err == nil {
							m.ActiveView = ViewFileViewer
							highlighted := highlightCode(entry.Name, string(contentBytes))
							m.FileViewport.SetContent(highlighted)
							m.FileViewport.GotoTop()
						}
					}
				}
				return m, nil
			case "backspace":
				// Go to parent directory
				parent := filepath.Dir(m.BrowserDir)
				if parent != m.BrowserDir {
					m.loadBrowserDir(parent)
				}
				return m, nil
			case "g", "G":
				// Git Add
				if m.BrowserCursor < len(m.BrowserEntries) {
					entry := m.BrowserEntries[m.BrowserCursor]
					if entry.Name != ".." {
						cmd := exec.Command("git", "add", entry.Path)
						cmd.Dir = m.BrowserDir
						_ = cmd.Run()
						m.loadBrowserDir(m.BrowserDir) // Refresh status
					}
				}
				return m, nil
			case "c", "C":
				// AI Commit
				cmd := exec.Command("git", "diff", "--cached")
				cmd.Dir = m.BrowserDir
				diffBytes, err := cmd.Output()
				if err != nil || len(bytes.TrimSpace(diffBytes)) == 0 {
					m.StatusMsg = "No files staged. Use [G] to stage files."
					m.StatusTTL = 30
					return m, nil
				}
				m.LoadingActive = true
				m.LoadingSteps = []LoadingStep{{Label: "Generating AI Commit...", Done: false}}
				m.LoadingStep = 0
				diffStr := string(diffBytes)
				return m, func() tea.Msg {
					if m.LLMClient == nil {
						return aiCommitMsg{err: fmt.Errorf("LLM client not initialized")}
					}
					ctx := context.Background()
					prompt := "Generate a concise, conventional commit message for the following changes:\n\n" + diffStr
					messages := []llm.Message{{Role: "user", Content: prompt}}
					msg, _, err := m.LLMClient.Chat(ctx, messages)
					return aiCommitMsg{msg: strings.TrimSpace(msg), err: err}
				}
			case "s", "S":
				// Scan selected directory (or current dir if file selected)
				scanPath := m.BrowserDir
				if m.BrowserCursor < len(m.BrowserEntries) {
					entry := m.BrowserEntries[m.BrowserCursor]
					if entry.IsDir && entry.Name != ".." {
						scanPath = entry.Path
					}
				}
				// Transition: browser → scanning overlay with animation
				m.BrowserDir = scanPath
				m.Report.ProjectPath = scanPath
				m.ActiveView = ViewDashboard
				m.ScanInProgress = true
				m.TickCount = 0 // Reset animation for Virtual Foundry overlay
				return m, m.asyncScanCmd()
			case "e", "E":
				if m.BrowserCursor < len(m.BrowserEntries) {
					entry := m.BrowserEntries[m.BrowserCursor]
					if !entry.IsDir {
						editor := os.Getenv("EDITOR")
						if editor == "" {
							editor = "vim"
						}
						c := exec.Command(editor, entry.Path)
						return m, tea.ExecProcess(c, func(err error) tea.Msg {
							return editorFinishedMsg{err}
						})
					}
				}
				return m, nil
			case "r", "R":
				if m.BrowserCursor < len(m.BrowserEntries) {
					entry := m.BrowserEntries[m.BrowserCursor]
					if !entry.IsDir {
						m.RuleBuilderActive = true
						m.RuleBuilderTarget = entry.Path
						m.RuleBuilderInput.Reset()
						m.RuleBuilderInput.Placeholder = "e.g., Detect hardcoded API keys in configuration objects"
						m.RuleBuilderInput.Focus()
					} else {
						m.StatusMsg = "Rule builder requires a specific file as target."
						m.StatusTTL = 30
					}
				}
				return m, nil
			case "home":
				m.BrowserCursor = 0
				return m, nil
			case "end":
				m.BrowserCursor = len(m.BrowserEntries) - 1
				if m.BrowserCursor < 0 {
					m.BrowserCursor = 0
				}
				return m, nil

			}
			return m, nil
		}

		switch keyStr {
		case "ctrl+c", "q":
			// Don't quit when typing in chat input
			if m.ActiveView == ViewChat && m.TextInput.Focused() && keyStr == "q" {
				break // let it fall through to TextInput.Update
			}
			return m, tea.Quit
		case "esc":
			if m.ActiveView == ViewChat {
				m.TextInput.Blur()
				m.ChatFocusMode = 0 // switch focus to viewport for scrolling
			}
		case "0":
			// Return to file browser from any tab (unless typing in chat)
			if !m.TextInput.Focused() || m.ActiveView != ViewChat {
				if m.BrowserDir == "" {
					m.BrowserDir = m.Report.ProjectPath
					if m.BrowserDir == "" {
						m.BrowserDir = "."
					}
				}
				m.loadBrowserDir(m.BrowserDir)
				m.ActiveView = ViewBrowser
				return m, nil
			}
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "c", "C", "l", "L":
			// Switch tabs if TextInput is not focused OR if we are not in Chat view
			if !m.TextInput.Focused() || m.ActiveView != ViewChat {
				switch keyStr {
				case "1":
					m.ActiveView = ViewDashboard
					// Auto-generate dashboard summary if empty and LLM available
					if m.DashboardSummary == "" && m.LLMClient != nil && !m.DashboardSummaryLoading {
						m.DashboardSummaryLoading = true
						m.DashboardSummary = "⠋ Generating executive summary..."
						return m, m.dashboardSummaryCmd()
					}
				case "2":
					m.ActiveView = ViewTriage
					m.Table.Focus()
					m.SASTTable.Blur()
				case "3":
					m.ActiveView = ViewSAST
					m.SASTTable.Focus()
					m.Table.Blur()
				case "4":
					m.ActiveView = ViewAudit
				case "5":
					m.ActiveView = ViewReports
				case "6":
					m.ActiveView = ViewChat
					return m, nil
				case "7":
					m.ActiveView = ViewDeps
				case "8":
					m.ActiveView = ViewGraph
				case "9":
					m.ActiveView = ViewInfra
				case "c", "C":
					m.ActiveView = ViewConfig
					m.initConfigInputs()
				case "l", "L":
					if !m.TextInput.Focused() || m.ActiveView != ViewChat {
						m.ActiveView = ViewLogs
					}
				}
			}
		case "/":
			if !m.TextInput.Focused() || m.ActiveView != ViewChat {
				m.SearchMode = true
				m.SearchInput.Focus()
				return m, nil
			}
		case "t", "T":
			// Embedded terminal drop
			if !m.TextInput.Focused() || m.ActiveView != ViewChat {
				shell := os.Getenv("SHELL")
				if shell == "" {
					shell = "bash"
				}
				c := exec.Command(shell)
				c.Dir = m.Report.ProjectPath
				if c.Dir == "" {
					c.Dir = m.BrowserDir
				}
				return m, tea.ExecProcess(c, func(err error) tea.Msg {
					return editorFinishedMsg{err}
				})
			}
		case "s", "S":
			// Launch async re-scan (not in chat mode, not if already scanning)
			if (m.ActiveView != ViewChat || !m.TextInput.Focused()) && !m.ScanInProgress {
				m.ScanInProgress = true
				m.AddLog(LogInfo, "SCAN", "Scan initiated from UI")
				return m, m.asyncScanCmd()
			}
		case "f", "F":
			// Autofix for selected finding (only on VULN tab)
			if m.ActiveView == ViewTriage && !m.ScanInProgress {
				row := m.Table.SelectedRow()
				if row != nil {
					id := row[0]
					for _, r := range m.Report.Results {
						if r.ID == id {
							m.RemediationViewport.SetContent(
								lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).
									Render("⚡ Running autofix dry-run for: " + r.Name + "..."),
							)
							return m, m.autofixCmd(r, false)
						}
					}
				}
			}
		case "a", "A":
			// Apply Fix (only on VULN tab)
			if m.ActiveView == ViewTriage && !m.ScanInProgress {
				row := m.Table.SelectedRow()
				if row != nil {
					id := row[0]
					for _, r := range m.Report.Results {
						if r.ID == id {
							m.RemediationViewport.SetContent(
								lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).
									Render("⚡ Applying fix for: " + r.Name + "..."),
							)
							return m, m.autofixCmd(r, true)
						}
					}
				}
			}
		case "i":
			// Toggle IGNORE status for selected finding (VULN tab)
			if m.ActiveView == ViewTriage && !m.ScanInProgress {
				row := m.Table.SelectedRow()
				if row != nil {
					id := row[0]
					for i, r := range m.Report.Results {
						if r.ID == id {
							newStatus := core.AuditStatusIgnored
							if r.AuditStatus == core.AuditStatusIgnored {
								newStatus = core.AuditStatusOpen
							}

							if m.AuditStore != nil {
								relPath := r.File
								if relPath != "" && filepath.IsAbs(relPath) {
									relPath, _ = filepath.Rel(m.Report.ProjectPath, relPath)
								}
								_ = m.AuditStore.SetStatus(r.ID, relPath, newStatus, "Toggled via TUI")
							}
							m.Report.Results[i].AuditStatus = newStatus
							m.updateTriageTable()
							if newStatus == core.AuditStatusIgnored {
								m.AddLog(LogSuccess, "TRIAGE", "Ignored: "+r.ID+" — "+r.Name)
							} else {
								m.AddLog(LogInfo, "TRIAGE", "Restored: "+r.ID+" — "+r.Name)
							}
							return m, nil
						}
					}
				}
			}
		case "I": // Shift+I — toggle visibility of ignored findings
			if m.ActiveView == ViewTriage {
				m.ShowIgnored = !m.ShowIgnored
				m.updateTriageTable()
				if m.ShowIgnored {
					m.AddLog(LogInfo, "TRIAGE", "Showing ignored findings")
				} else {
					m.AddLog(LogInfo, "TRIAGE", "Hiding ignored findings")
				}
				return m, nil
			}
		case "e", "E":
			// Export report (only on REPT tab)
			if m.ActiveView == ViewReports {
				return m, m.exportCmd()
			}
		case "w", "W":
			// Generate CI/CD workflow (only on REPT tab)
			if m.ActiveView == ViewReports {
				return m, m.generateCICDCmd()
			}
		case "h", "H":
			// Generate Pre-commit Hook (only on REPT tab)
			if m.ActiveView == ViewReports {
				return m, m.generateGitHookCmd()
			}
		// "c"/"C" is handled in tab navigation above (line 304) → ViewConfig
		case "x", "X":
			// Export context for AI agents (Reports tab)
			if m.ActiveView == ViewReports {
				return m, m.contextExportCmd()
			}
		case "enter":
			if m.ActiveView == ViewTriage {
				// Trigger in-TUI AI analysis for selected finding
				row := m.Table.SelectedRow()
				if row != nil {
					id := row[0]
					for _, r := range m.Report.Results {
						if r.ID == id {
							// Check cache first
							if cached, ok := m.TriageAnalysisCache[id]; ok {
								m.RemediationViewport.SetContent(cached)
								return m, nil
							}
							// Set analyzing state for animated spinner
							m.TriageAnalyzing = true
							m.TriageAnalyzingID = id
							return m, m.triageAnalyzeCmd(r)
						}
					}
				}
			} else if m.ActiveView == ViewSAST {
				// Trigger in-TUI AI analysis for SAST finding
				row := m.SASTTable.SelectedRow()
				if row != nil {
					source := row[0]
					ruleID := row[1]
					key := source + ":" + ruleID
					// Check cache first
					if cached, ok := m.SASTAnalysisCache[key]; ok {
						m.SASTViewport.SetContent(cached)
						return m, nil
					}
					// Set analyzing state for animated spinner
					m.SASTAnalyzing = true
					m.SASTAnalyzingKey = key
					return m, m.sastAnalyzeCmd(source, ruleID)
				}
			} else if m.ActiveView == ViewChat && m.ChatFocusMode == 0 {
				// Execute command from the Security Ops Center command panel
				if m.PromptCursor >= 0 && m.PromptCursor < len(m.QuickPrompts) {
					action := m.QuickPrompts[m.PromptCursor]

					// Rich, expert-level prompts per command — Mythos-grade depth
					var promptText string
					switch action.Command {
					case "FULL_BRIEFING":
						promptText = "Deliver a full executive security briefing. Structure: " +
							"1) RISK VERDICT with SecurityScore interpretation, " +
							"2) TOP 3 critical attack vectors with exploitability assessment (CVSS v3.1 base score estimate), " +
							"3) IMMEDIATE ACTIONS — prioritized by impact, with effort estimate (hours). " +
							"End with a one-line BOTTOM LINE statement."
					case "CRIT_PATH":
						promptText = "Map all exploitability chains in this codebase. For each chain: " +
							"ENTRY POINT (user input, API endpoint, file upload) → VULNERABILITY (the specific finding) → " +
							"LATERAL MOVEMENT (what an attacker gains) → IMPACT (data exfil, RCE, privilege escalation). " +
							"Assess which chains are remotely exploitable vs local-only. Rank by severity."
					case "TOP_CRIT":
						promptText = "Deep-dive the 3 most dangerous vulnerabilities. For each: " +
							"1) FINDING ID and exact file:line, " +
							"2) ROOT CAUSE — why this bug exists (design flaw vs implementation error), " +
							"3) EXPLOITABILITY — prerequisites, complexity, and whether it's automatable, " +
							"4) CVSS v3.1 vector string with breakdown, " +
							"5) FIX — exact code change with before/after snippet."
					case "THREAT_MODEL":
						promptText = "Perform a STRIDE threat model of this project's architecture. " +
							"For each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, " +
							"Denial of Service, Elevation of Privilege): identify which scan findings map to it, " +
							"assess current mitigations (present/absent), and rate residual risk (HIGH/MEDIUM/LOW). " +
							"Output as a structured threat matrix."
					case "FIX_PLAN":
						promptText = "Generate a prioritized remediation backlog. Group fixes into: " +
							"P0 (fix today — active exploit risk), P1 (fix this sprint — high severity), " +
							"P2 (fix this quarter — hardening). For each item: finding reference, " +
							"exact fix description with code example, estimated effort (S/M/L), " +
							"and what breaks if you don't fix it."
					case "SECRETS_FIX":
						promptText = "Identify ALL leaked credentials, secrets, API keys, and tokens in the scan findings. " +
							"For each: 1) exact file and line, 2) secret type (API key, JWT secret, DB password, etc.), " +
							"3) blast radius if compromised, 4) rotation procedure (step-by-step), " +
							"5) prevention — how to use env vars / vault / .gitignore to prevent recurrence."
					case "DEP_HARDEN":
						promptText = "Analyze all external dependencies for security posture. " +
							"1) Flag any with known CVEs or unmaintained status, " +
							"2) Identify unnecessary/unused dependencies that increase attack surface, " +
							"3) Check for lockfile presence and version pinning, " +
							"4) Recommend specific version upgrades with breaking change warnings, " +
							"5) Suggest dependency audit automation (Dependabot, Renovate, etc.)."
					case "NET_SURFACE":
						promptText = "Analyze the network attack surface from scan findings. Cover: " +
							"1) Exposed ports and services (with authentication status), " +
							"2) Unauthenticated API endpoints, " +
							"3) CORS configuration (overly permissive origins?), " +
							"4) Rate limiting gaps, " +
							"5) TLS/SSL configuration issues, " +
							"6) Network segmentation recommendations."
					case "OWASP_AUDIT":
						promptText = "Map every scan finding to OWASP Top 10 2021 categories " +
							"(A01:Broken Access Control through A10:SSRF). For each category: " +
							"list matching findings with severity, assess coverage gaps " +
							"(which OWASP categories have ZERO findings — are we blind or clean?), " +
							"and provide a compliance summary table."
					case "GEN_SPEC":
						promptText = "Generate a comprehensive CLAUDE.md project specification file. Include: " +
							"1) PROJECT OVERVIEW — language, framework, architecture pattern, " +
							"2) SECURITY POSTURE — current score, top risks, sensitive areas, " +
							"3) CONVENTIONS — coding standards, naming, file structure, " +
							"4) FORBIDDEN PATTERNS — based on findings (e.g., no hardcoded secrets, no eval()), " +
							"5) AI GUIDELINES — how an AI agent should approach changes to this codebase safely."
					case "SAST_COVERAGE":
						promptText = "Assess SAST coverage quality. " +
							"1) Which code paths/modules are well-covered by scan rules? " +
							"2) Which are BLIND SPOTS — areas with no findings that may simply lack rules? " +
							"3) Are there file types or patterns being skipped? " +
							"4) False positive rate assessment, " +
							"5) Recommendations for additional scanning tools or custom rules."
					case "NFR_CHECK":
						promptText = "Audit non-functional security requirements. Check for: " +
							"1) Authentication — is every sensitive endpoint protected? " +
							"2) Authorization — are there RBAC/ABAC gaps? " +
							"3) Rate limiting — which endpoints lack it? " +
							"4) Input validation — where is user input trusted without sanitization? " +
							"5) Error handling — are stack traces leaked to users? " +
							"6) Logging — are security events (login, access denied, data changes) logged?"
					default:
						promptText = action.Description
					}

					// Show shortened label in chat history, send full prompt to LLM
					m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "USER", Content: "▶ " + action.Label})
					if m.LLMClient != nil {
						m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "THINKING", Content: "THINKING: ⠋ Analyzing..."})
						m.ExecutingAgent = true
						m.ChatAnalyzing = true
						m.ChatFocusMode = 1 // Switch to chat history to see response
						m.updateChatViewport()
						return m, m.chatCmd(promptText)
					} else {
						m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "SYSTEM", Content: "⚠ No LLM configured. Set GEMINI_API_KEY or configure .aitriage.yaml"})
						m.updateChatViewport()
					}
				}
			} else if m.ActiveView == ViewChat && m.ChatFocusMode == 2 {
				if m.TextInput.Value() != "" && m.LLMClient != nil {
					val := m.TextInput.Value()
					m.TextInput.SetValue("")
					m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "USER", Content: val})
					m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "THINKING", Content: "THINKING: ⠋ AI Engine analyzing..."})
					m.ExecutingAgent = true
					m.ChatAnalyzing = true
					m.updateChatViewport()
					return m, m.chatCmd(val)
				} else if m.TextInput.Value() != "" && m.LLMClient == nil {
					val := m.TextInput.Value()
					m.TextInput.SetValue("")
					m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "USER", Content: val})
					m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "SYSTEM", Content: "No LLM provider configured. Set GEMINI_API_KEY to enable chat."})
					m.updateChatViewport()
				}
			}
		case "tab":
			// Toggle focus between table (left) and detail viewport (right)
			//nolint:staticcheck // The two-view toggle reads more clearly as an explicit branch.
			if m.ActiveView == ViewSAST {
				m.SASTFocusDetail = !m.SASTFocusDetail
			} else if m.ActiveView == ViewTriage {
				m.TriageFocusDetail = !m.TriageFocusDetail
			} else if m.ActiveView == ViewChat {
				// Cycle: 0 (Command Panel) → 1 (Chat History) → 2 (Text Input) → 0
				m.ChatFocusMode = (m.ChatFocusMode + 1) % 3
				if m.ChatFocusMode == 2 {
					m.TextInput.Focus()
				} else {
					m.TextInput.Blur()
				}
				return m, nil
			}
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.Ready = true
		m.handleResize(msg.Width, msg.Height)
		m.updateViewportContent()

	case ruleGeneratedMsg:
		m.RuleGenerating = false
		if msg.err != nil {
			m.StatusMsg = "Rule generation failed: " + msg.err.Error()
			m.StatusTTL = 60
			m.AddLog(LogError, "BUILDER", fmt.Sprintf("Failed to generate rule: %v", msg.err))
		} else {
			m.StatusMsg = "Rule generated to " + filepath.Base(msg.rulePath) + " — Hot-reloading engine..."
			m.StatusTTL = 60
			m.AddLog(LogSuccess, "BUILDER", "Saved custom rule to "+msg.rulePath)
			m.AddLog(LogInfo, "ENGINE", "Triggering background re-scan to apply new rules...")

			// Trigger engine hot-reload
			return m, m.asyncScanCmd()
		}

	case triageAnalysisMsg:
		m.TriageAnalyzing = false
		m.TriageAnalyzingID = ""
		if msg.err != nil {
			m.AddLog(LogError, "AI", fmt.Sprintf("Triage analysis failed: %v", msg.err))
			m.RemediationViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).
					Render("ERROR") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(fmt.Sprintf("%v", msg.err)),
			)
		} else {
			m.AddLog(LogSuccess, "AI", "Triage analysis completed")
			m.TokensUsed += msg.tokens
			// Render markdown and cache
			rendered := renderMarkdownToTerminal(msg.content, m.RemediationViewport.Width)
			m.RemediationViewport.SetContent(rendered)
			// Cache by current finding ID
			row := m.Table.SelectedRow()
			if row != nil {
				m.TriageAnalysisCache[row[0]] = rendered
			}
		}
		return m, nil

	case editorFinishedMsg:
		if msg.err != nil {
			m.AddLog(LogError, "SYSTEM", fmt.Sprintf("Editor exited with error: %v", msg.err))
		}
		// Refresh browser directory contents after editor closes
		m.loadBrowserDir(m.BrowserDir)
		return m, nil

	case aiCommitMsg:
		m.LoadingActive = false
		if msg.err != nil {
			m.StatusMsg = "Commit generation failed: " + msg.err.Error()
			m.StatusTTL = 50
			return m, nil
		}
		// Drop into editor for commit
		c := exec.Command("git", "commit", "-e", "-m", msg.msg)
		c.Dir = m.Report.ProjectPath
		if c.Dir == "" {
			c.Dir = m.BrowserDir
		}
		return m, tea.ExecProcess(c, func(err error) tea.Msg {
			return editorFinishedMsg{err}
		})

	case sastAnalysisMsg:
		m.SASTAnalyzing = false
		m.SASTAnalyzingKey = ""
		if msg.err != nil {
			m.AddLog(LogError, "AI", fmt.Sprintf("SAST analysis failed: %v", msg.err))
			m.SASTViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorError).Bold(true).
					Render("ERROR") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(fmt.Sprintf("%v", msg.err)),
			)
		} else {
			m.AddLog(LogSuccess, "AI", "SAST analysis completed")
			m.TokensUsed += msg.tokens
			// Render markdown and cache
			rendered := renderMarkdownToTerminal(msg.content, m.SASTViewport.Width)
			m.SASTViewport.SetContent(rendered)
			// Cache by source:ruleID
			row := m.SASTTable.SelectedRow()
			if row != nil {
				key := row[0] + ":" + row[1]
				m.SASTAnalysisCache[key] = rendered
			}
		}
		return m, nil

	case chatResponseMsg:
		m.ChatAnalyzing = false
		m.ExecutingAgent = false
		// Remove the THINKING placeholder
		for i := len(m.ChatHistory) - 1; i >= 0; i-- {
			if strings.HasPrefix(m.ChatHistory[i].Content, "THINKING:") {
				m.ChatHistory = append(m.ChatHistory[:i], m.ChatHistory[i+1:]...)
				break
			}
		}
		if msg.err != nil {
			m.AddLog(LogError, "AI", fmt.Sprintf("Chat response failed: %v", msg.err))
			m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "SYSTEM", Content: fmt.Sprintf("Error: %v", msg.err)})
		} else {
			m.AddLog(LogSuccess, "AI", "Chat response received")
			m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "AI", Content: msg.content})
			m.TokensUsed += msg.tokens
		}
		m.updateChatViewport()
		return m, nil

	case scanCompleteMsg:
		m.ScanInProgress = false
		if msg.err != nil {
			m.AddLog(LogError, "SCAN", fmt.Sprintf("Scan failed: %v", msg.err))
			m.RemediationViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorError).Bold(true).
					Render("SCAN ERROR") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(fmt.Sprintf("%v", msg.err)),
			)
		} else {
			m.Report = msg.report
			m.updateDashboardData()
			m.ExternalFindings = msg.external
			m.NFRFindings = msg.nfr
			m.DeployFindings = msg.deploy
			m.NetworkFindings = msg.network
			m.ScanStartTime = time.Now()

			m.AddLog(LogSuccess, "SCAN", fmt.Sprintf("Scan complete: %d findings, %s", len(msg.report.Results), msg.report.ScanDuration))
			if len(msg.external) > 0 {
				m.AddLog(LogInfo, "SAST", fmt.Sprintf("External SAST: %d findings", len(msg.external)))
			}
			if len(msg.nfr) > 0 {
				m.AddLog(LogInfo, "SAST", fmt.Sprintf("NFR check: %d findings", len(msg.nfr)))
			}
			if len(msg.deploy) > 0 {
				m.AddLog(LogInfo, "SAST", fmt.Sprintf("Deploy audit: %d findings", len(msg.deploy)))
			}
			if len(msg.network) > 0 {
				m.AddLog(LogInfo, "SAST", fmt.Sprintf("Network: %d findings", len(msg.network)))
			}

			// Lazy-initialize LLM client when coming from browser mode
			if m.LLMClient == nil && msg.report.Config != nil {
				m.LLMClient, _ = llm.NewClient(llm.Config{
					Provider:    msg.report.Config.LLM.Provider,
					Model:       msg.report.Config.LLM.Model,
					APIKey:      msg.report.Config.LLM.APIKey,
					BaseURL:     msg.report.Config.LLM.BaseURL,
					Timeout:     msg.report.Config.LLM.Timeout,
					Temperature: msg.report.Config.LLM.Temperature,
				})
				m.AddLog(LogInfo, "SYSTEM", fmt.Sprintf("LLM Engine initialized: %s/%s", msg.report.Config.LLM.Provider, msg.report.Config.LLM.Model))
			}
			// Ensure caches are initialized (browser mode starts without them)
			if m.SASTAnalysisCache == nil {
				m.SASTAnalysisCache = make(map[string]string)
			}
			if m.TriageAnalysisCache == nil {
				m.TriageAnalysisCache = make(map[string]string)
			}
			// Re-initialize AuditStore with the actual project path
			// (browser mode starts with empty path; scan provides the real one)
			if m.Report.ProjectPath != "" {
				m.AuditStore = core.NewAuditStore(m.Report.ProjectPath)
				// Apply persisted audit statuses to findings
				for i, r := range m.Report.Results {
					relPath := r.File
					if relPath != "" && filepath.IsAbs(relPath) {
						relPath, _ = filepath.Rel(m.Report.ProjectPath, relPath)
					}
					if status := m.AuditStore.GetStatus(r.ID, relPath); status != "" {
						m.Report.Results[i].AuditStatus = status
					}
				}
			}

			m.rebuildTableRows()
			m.rebuildSASTTableRows()
			m.rebuildInfraTableRows()
			m.rebuildDepsTableRows()
			m.rebuildGraphCache()
			m.handleResize(m.Width, m.Height) // Recalculate component sizes after scan
			m.updateViewportContent()

			// Ensure tables are focused for keyboard navigation
			m.Table.Focus()
			m.SASTTable.Focus()

			// Transition from browser to dashboard on first successful scan
			if m.ActiveView == ViewBrowser {
				m.ActiveView = ViewDashboard
			}

			// Record telemetry
			stacks := make([]string, len(msg.report.Stacks))
			for i, s := range msg.report.Stacks {
				stacks[i] = string(s)
			}
			critCount := 0
			for _, r := range msg.report.Results {
				if r.Severity == "CRITICAL" {
					critCount++
				}
			}
			telemetry.Record(telemetry.ScanMetric{
				Timestamp:     time.Now(),
				ProjectHash:   telemetry.HashProjectPath(msg.report.ProjectPath),
				Duration:      msg.report.ScanDuration.Milliseconds(),
				FilesScanned:  msg.report.TotalFiles,
				FindingsTotal: len(msg.report.Results),
				FindingsCrit:  critCount,
				SecurityScore: msg.report.SecurityScore,
				Stacks:        stacks,
				TokensUsed:    m.TokensUsed,
			})
		}
		return m, nil

	case autofixMsg:
		if msg.err != nil {
			m.AddLog(LogError, "FIX", fmt.Sprintf("Autofix failed: %v", msg.err))
			m.RemediationViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorError).Bold(true).
					Render("AUTOFIX ERROR") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(fmt.Sprintf("%v", msg.err)),
			)
		} else {
			if msg.logMsg != "" {
				m.AddLog(msg.logLevel, "FIX", msg.logMsg)
			}
			m.RemediationViewport.SetContent(msg.content)
		}
		return m, nil

	case exportMsg:
		if msg.err != nil {
			m.AddLog(LogError, "EXPORT", fmt.Sprintf("Export failed: %v", msg.err))
			m.RemediationViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorError).Bold(true).
					Render("EXPORT ERROR") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(fmt.Sprintf("%v", msg.err)),
			)
		} else {
			m.AddLog(LogInfo, "EXPORT", "JSON exported successfully")
			// Temporarily stash feedback in ChatHistory for visibility
			m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "SYSTEM", Content: msg.content})
			m.updateChatViewport()
		}
		return m, nil

	case dashboardSummaryMsg:
		m.DashboardSummaryLoading = false
		if msg.err != nil {
			m.DashboardSummary = "⚠ Summary error: " + msg.err.Error()
		} else {
			m.TokensUsed += msg.tokens
			m.DashboardSummary = msg.content
		}
		return m, nil

	case contextExportMsg:
		m.ExecutingAgent = false
		if msg.err != nil {
			m.AddLog(LogError, "EXPORT", fmt.Sprintf("Context export failed: %v", msg.err))
			m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "SYSTEM", Content: fmt.Sprintf("Export error: %v", msg.err)})
		} else {
			m.AddLog(LogInfo, "EXPORT", "Context exported successfully")
			m.ChatHistory = append(m.ChatHistory, ChatMessage{Sender: "SYSTEM", Content: msg.content})
		}
		m.updateChatViewport()
		return m, nil

	case tickMsg:
		m.TickCount++
		// Clear status toast after TTL
		if m.StatusTTL > 0 {
			m.StatusTTL--
			if m.StatusTTL == 0 {
				m.StatusMsg = ""
			}
		}
		// Animate AI loading spinners
		// Chat thinking animation
		if m.ChatAnalyzing {
			frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			frame := frames[m.TickCount%len(frames)]
			thinkPhrases := []string{
				"Analyzing security context",
				"Evaluating scan findings",
				"Cross-referencing vulnerabilities",
				"Building remediation plan",
				"Synthesizing response",
			}
			phrase := thinkPhrases[(m.TickCount/10)%len(thinkPhrases)]
			// Update the THINKING placeholder in ChatHistory
			for i := len(m.ChatHistory) - 1; i >= 0; i-- {
				if strings.HasPrefix(m.ChatHistory[i].Content, "THINKING:") {
					m.ChatHistory[i].Content = fmt.Sprintf("THINKING: %s %s...", frame, phrase)
					m.updateChatViewport()
					break
				}
			}
		}
		if m.TriageAnalyzing {
			frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			frame := frames[m.TickCount%len(frames)]
			thinkPhrases := []string{"Analyzing code patterns", "Evaluating severity", "Generating remediation", "Cross-referencing CVEs", "Building fix strategy"}
			phrase := thinkPhrases[(m.TickCount/8)%len(thinkPhrases)]
			m.RemediationViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorPrimaryDim).Bold(true).
					Render(frame+" AI ENGINE ACTIVE") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(phrase+"...") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorOutline).
						Render(strings.Repeat("█", (m.TickCount%20)+1)+strings.Repeat("░", 20-(m.TickCount%20)-1)),
			)
		}
		if m.SASTAnalyzing {
			frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			frame := frames[m.TickCount%len(frames)]
			thinkPhrases := []string{"Scanning dependencies", "Mapping attack surface", "Evaluating exploit path", "Building fix plan", "Validating remediation"}
			phrase := thinkPhrases[(m.TickCount/8)%len(thinkPhrases)]
			m.SASTViewport.SetContent(
				lipgloss.NewStyle().Foreground(colorPrimaryDim).Bold(true).
					Render(frame+" AI ENGINE ACTIVE") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorGray).
						Render(phrase+"...") + "\n\n" +
					lipgloss.NewStyle().Foreground(colorOutline).
						Render(strings.Repeat("█", (m.TickCount%20)+1)+strings.Repeat("░", 20-(m.TickCount%20)-1)),
			)
		}
		if m.DashboardSummaryLoading {
			frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			frame := frames[m.TickCount%len(frames)]
			m.DashboardSummary = frame + " Generating executive summary..."
		}
		return m, tick()
	}

	// Route events based on active view
	if m.ActiveView == ViewDashboard {
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case "tab":
				m.DashFocusPanel = (m.DashFocusPanel + 1) % 3
			case "up", "k":
				//nolint:staticcheck // This is a bounded two-panel navigation branch.
				if m.DashFocusPanel == 1 { // MAP
					if m.DashMapCursor > 0 {
						m.DashMapCursor--
					}
				} else if m.DashFocusPanel == 2 { // TOP FILES
					if m.DashFileCursor > 0 {
						m.DashFileCursor--
					}
				}
			case "down", "j":
				//nolint:staticcheck // This is a bounded two-panel navigation branch.
				if m.DashFocusPanel == 1 { // MAP
					if m.DashMapCursor < len(m.DashCats)-1 {
						m.DashMapCursor++
					}
				} else if m.DashFocusPanel == 2 { // TOP FILES
					if m.DashFileCursor < len(m.DashFiles)-1 {
						m.DashFileCursor++
					}
				}
			case "enter":
				//nolint:staticcheck // This is a bounded two-panel navigation branch.
				if m.DashFocusPanel == 1 { // MAP
					if m.DashMapCursor >= 0 && m.DashMapCursor < len(m.DashCats) {
						cat := m.DashCats[m.DashMapCursor]
						m.SearchQuery = cat.Name
						m.ActiveView = ViewTriage
						m.rebuildTableRows()
						m.Table.SetCursor(0)
					}
				} else if m.DashFocusPanel == 2 { // TOP FILES
					if m.DashFileCursor >= 0 && m.DashFileCursor < len(m.DashFiles) {
						file := m.DashFiles[m.DashFileCursor]
						m.SearchQuery = file.Path
						m.ActiveView = ViewTriage
						m.rebuildTableRows()
						m.Table.SetCursor(0)
					}
				}
			}
		}
	} else if m.ActiveView == ViewTriage {
		curCursor := m.Table.Cursor()
		cursorChanged := curCursor != m.TriageLastCursor
		if cursorChanged {
			m.TriageFocusDetail = false // Reset focus to table on row change
			m.TriageLastCursor = curCursor
		}

		if m.TriageFocusDetail {
			// Focus on detail: arrows scroll remediation viewport
			m.RemediationViewport, cmd = m.RemediationViewport.Update(msg)
			cmds = append(cmds, cmd)
		} else {
			// Focus on table: arrows move cursor
			m.Table, cmd = m.Table.Update(msg)
			cmds = append(cmds, cmd)

			newCursor := m.Table.Cursor()
			if newCursor != curCursor {
				m.TriageLastCursor = newCursor
				// Check cache for AI analysis
				row := m.Table.SelectedRow()
				if row != nil {
					if cached, ok := m.TriageAnalysisCache[row[0]]; ok {
						m.RemediationViewport.SetContent(cached)
					} else {
						m.updateViewportContent()
					}
				} else {
					m.updateViewportContent()
				}
			}
		}
	} else if m.ActiveView == ViewSAST {
		curCursor := m.SASTTable.Cursor()
		cursorChanged := curCursor != m.SASTLastCursor
		if cursorChanged {
			m.SASTFocusDetail = false // Reset focus to table on row change
			m.SASTLastCursor = curCursor
		}

		if m.SASTFocusDetail {
			// Focus on detail: arrows scroll SAST detail viewport
			m.SASTViewport, cmd = m.SASTViewport.Update(msg)
			cmds = append(cmds, cmd)
		} else {
			// Focus on table: arrows move cursor
			m.SASTTable, cmd = m.SASTTable.Update(msg)
			cmds = append(cmds, cmd)

			newCursor := m.SASTTable.Cursor()
			if newCursor != curCursor {
				m.SASTLastCursor = newCursor
				// Check cache for AI analysis
				row := m.SASTTable.SelectedRow()
				if row != nil {
					key := row[0] + ":" + row[1]
					if cached, ok := m.SASTAnalysisCache[key]; ok {
						m.SASTViewport.SetContent(cached)
					} else {
						m.updateSASTViewportContent()
					}
				} else {
					m.updateSASTViewportContent()
				}
			}
		}
	} else if m.ActiveView == ViewGraph {
		// Topology tab — interactive tree navigation
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case "up", "k":
				if m.TopologyCursor > 0 {
					m.TopologyCursor--
				}
			case "down", "j":
				if m.TopologyCursor < len(m.TopologyNodes)-1 {
					m.TopologyCursor++
				}
			case "enter", "right", "l":
				if m.TopologyCursor >= 0 && m.TopologyCursor < len(m.TopologyNodes) {
					node := m.TopologyNodes[m.TopologyCursor]
					if node.HasKids {
						m.TopologyExpanded[node.ID] = !m.TopologyExpanded[node.ID]
						m.rebuildTopologyNodes()
					}
				}
			case "left", "h":
				if m.TopologyCursor >= 0 && m.TopologyCursor < len(m.TopologyNodes) {
					node := m.TopologyNodes[m.TopologyCursor]
					if node.HasKids && m.TopologyExpanded[node.ID] {
						m.TopologyExpanded[node.ID] = false
						m.rebuildTopologyNodes()
					} else if node.Depth > 0 {
						for i := m.TopologyCursor - 1; i >= 0; i-- {
							if m.TopologyNodes[i].Depth < node.Depth {
								m.TopologyCursor = i
								break
							}
						}
					}
				}
			case "home":
				m.TopologyCursor = 0
			case "end":
				if len(m.TopologyNodes) > 0 {
					m.TopologyCursor = len(m.TopologyNodes) - 1
				}
			}
		}
	} else if m.ActiveView == ViewChat {
		//nolint:staticcheck // Explicit focus-mode cycling is easier to audit here.
		if m.ChatFocusMode == 2 {
			// Focus on input: route keyboard to TextInput
			m.TextInput, cmd = m.TextInput.Update(msg)
			cmds = append(cmds, cmd)
		} else if m.ChatFocusMode == 0 {
			// Focus on Command Panel (left pane): up/down navigation
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.String() {
				case "up", "k":
					if m.PromptCursor > 0 {
						m.PromptCursor--
					}
				case "down", "j":
					if m.PromptCursor < len(m.QuickPrompts)-1 {
						m.PromptCursor++
					}
				}
			}
		} else if m.ChatFocusMode == 1 {
			// Focus on Chat History (right pane): arrows scroll chat viewport
			m.ChatViewport, cmd = m.ChatViewport.Update(msg)
			cmds = append(cmds, cmd)
		}
	} else if m.ActiveView == ViewDeps {
		m.DepsTable, cmd = m.DepsTable.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.ActiveView == ViewInfra {
		m.InfraTable, cmd = m.InfraTable.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.ActiveView == ViewLogs {
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case "f", "F":
				m.LogFilter++
				if m.LogFilter > LogSuccess {
					m.LogFilter = -1 // Reset to ALL
				}
				m.LogAutoScroll = true
				m.formatLogViewport()
			case "g", "G":
				m.LogAutoScroll = true
				m.LogViewport.GotoBottom()
			case "up", "k", "down", "j", "pgup", "pgdown", "home":
				m.LogAutoScroll = false
				m.LogViewport, cmd = m.LogViewport.Update(msg)
				cmds = append(cmds, cmd)
			}
		} else {
			m.LogViewport, cmd = m.LogViewport.Update(msg)
			cmds = append(cmds, cmd)
		}
	} else if m.ActiveView == ViewConfig {
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case "tab", "down":
				if len(m.ConfigInputs) > 0 {
					m.ConfigInputs[m.ConfigFocusIndex].Blur()
					m.ConfigFocusIndex = (m.ConfigFocusIndex + 1) % len(m.ConfigInputs)
					m.ConfigInputs[m.ConfigFocusIndex].Focus()
				}
				return m, nil
			case "shift+tab", "up":
				if len(m.ConfigInputs) > 0 {
					m.ConfigInputs[m.ConfigFocusIndex].Blur()
					m.ConfigFocusIndex--
					if m.ConfigFocusIndex < 0 {
						m.ConfigFocusIndex = len(m.ConfigInputs) - 1
					}
					m.ConfigInputs[m.ConfigFocusIndex].Focus()
				}
				return m, nil
			case "enter", "ctrl+s":
				cmd := m.saveConfig()
				return m, cmd
			}
		}

		if len(m.ConfigInputs) > 0 {
			var cmd tea.Cmd
			m.ConfigInputs[m.ConfigFocusIndex], cmd = m.ConfigInputs[m.ConfigFocusIndex].Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

type triageAnalysisMsg struct {
	content string
	tokens  int
	err     error
}

// triageAnalyzeCmd runs AI analysis for a finding IN the TUI (no process suspension)
func (m *DashboardModel) triageAnalyzeCmd(res core.CheckResult) tea.Cmd {
	return func() tea.Msg {
		if m.LLMClient == nil {
			return triageAnalysisMsg{err: fmt.Errorf("no LLM client configured; set GEMINI_API_KEY")}
		}

		// Read source code context for grounding
		codeCtx := ""
		if res.File != "" {
			codeCtx = readCodeContext(res.File, res.Line, 15)
		}

		prompt := fmt.Sprintf(`Analyze this security finding and provide actionable remediation:

**Finding:** %s (ID: %s)
**Severity:** %s
**File:** %s (Line %d)
**Evidence:** %s
**Suggestion:** %s

%s

Provide:
1. Root cause analysis (2-3 sentences)
2. Step-by-step fix with code example
3. How to verify the fix

Be concise and technical. Respond in English.`,
			res.Name, res.ID, res.Severity, res.File, res.Line,
			res.Evidence, res.Suggestion,
			func() string {
				if codeCtx != "" {
					return "**Source Code Context:**\n```\n" + codeCtx + "\n```"
				}
				return ""
			}(),
		)

		messages := []llm.Message{
			{Role: "system", Content: `You are a senior security engineer. Analyze the finding and respond in EXACTLY this format:

CAUSE: [1-2 sentences explaining the root cause]

FIX:
1. [step]
2. [step]
3. [step]
(max 5 steps, include code snippets if needed)

VERIFY: [1 sentence on how to verify the fix]

Rules: Be extremely concise. Max 15 lines total. No filler phrases. Technical and actionable only.`},
			{Role: "user", Content: prompt},
		}

		resp, usage, err := m.LLMClient.Chat(context.Background(), messages)
		if err != nil {
			return triageAnalysisMsg{err: err}
		}

		// Format the response with styled header
		result := fmt.Sprintf("🔍 AI ANALYSIS: %s\n%s\n\n%s",
			res.Name,
			strings.Repeat("─", 40),
			resp,
		)

		return triageAnalysisMsg{content: result, tokens: usage.TotalTokens}
	}
}

type sastAnalysisMsg struct {
	content string
	tokens  int
	err     error
}

// sastAnalyzeCmd runs AI analysis for an external SAST finding
func (m *DashboardModel) sastAnalyzeCmd(source, ruleID string) tea.Cmd {
	return func() tea.Msg {
		if m.LLMClient == nil {
			return sastAnalysisMsg{err: fmt.Errorf("no LLM client configured; set GEMINI_API_KEY")}
		}

		// Build context from the finding
		var findingCtx string
		switch source {
		case "SEMGREP", "GITLEAKS", "TRIVY", "BANDIT":
			for _, f := range m.ExternalFindings {
				if strings.ToUpper(f.Source) == source && f.RuleID == ruleID {
					findingCtx = fmt.Sprintf("Source: %s\nRule: %s\nSeverity: %s\nFile: %s (Line %d)\nMessage: %s\nSuggestion: %s",
						f.Source, f.RuleID, f.Severity, f.File, f.Line, f.Message, f.Suggestion)
					if f.File != "" && f.Line > 0 {
						code := readCodeContext(f.File, f.Line, 10)
						if code != "" {
							findingCtx += "\n\nSource Code:\n```\n" + code + "\n```"
						}
					}
					break
				}
			}
		case "NFR":
			for _, f := range m.NFRFindings {
				if f.RuleID == ruleID {
					findingCtx = fmt.Sprintf("Source: NFR Checker\nRule: %s\nSeverity: %s\nName: %s\nMessage: %s\nAdvice: %s",
						f.RuleID, f.Severity, f.Name, f.Message, f.Advice)
					break
				}
			}
		case "DEPLOY":
			for _, f := range m.DeployFindings {
				if f.Issue == ruleID {
					findingCtx = fmt.Sprintf("Source: Deploy Audit\nRule: %s\nSeverity: %s\nFile: %s (Line %d)\nEvidence: %s\nAdvice: %s",
						f.Issue, f.Severity, f.File, f.Line, f.Evidence, f.Advice)
					break
				}
			}
		}

		if findingCtx == "" {
			return sastAnalysisMsg{err: fmt.Errorf("finding not found: %s / %s", source, ruleID)}
		}

		messages := []llm.Message{
			{Role: "system", Content: `You are a senior security engineer analyzing SAST findings. Respond in EXACTLY this format:

CAUSE: [1-2 sentences explaining the root cause]

FIX:
1. [step]
2. [step]
3. [step]
(max 5 steps, include code snippets if needed)

VERIFY: [1 sentence on how to verify the fix]

Rules: Be extremely concise. Max 15 lines total. No filler phrases. Technical and actionable only.`},
			{Role: "user", Content: "Analyze this external scanner finding and provide remediation:\n\n" + findingCtx},
		}

		resp, usage, err := m.LLMClient.Chat(context.Background(), messages)
		if err != nil {
			return sastAnalysisMsg{err: err}
		}

		result := fmt.Sprintf("🔍 AI ANALYSIS: %s / %s\n%s\n\n%s",
			source, ruleID,
			strings.Repeat("─", 40),
			resp,
		)

		return sastAnalysisMsg{content: result, tokens: usage.TotalTokens}
	}
}

type scanCompleteMsg struct {
	report   scanner.ScanReport
	external []external.UnifiedFinding
	nfr      []nfr.NFRFinding
	deploy   []deployaudit.DeployFinding
	network  []network.NetworkFinding
	err      error
}

// asyncScanCmd runs the full orchestrator in a goroutine and returns results via tea.Msg.
// This calls orchestrator.RunAllScanners() to include external SAST tools.
// Uses a 5-minute timeout to prevent the TUI from hanging indefinitely.
func (m *DashboardModel) asyncScanCmd() tea.Cmd {
	path := m.Report.ProjectPath
	if path == "" {
		path = m.BrowserDir // Use browser selection if no report path
	}
	if path == "" {
		path = "."
	}
	cfg := m.Report.Config // capture before goroutine
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Channel to receive result from goroutine
		type scanResult struct {
			rich llm.RichScanResult
		}
		ch := make(chan scanResult, 1)
		go func() {
			rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
				ProjectPath: path,
				RunExternal: true,
			})
			ch <- scanResult{rich: rich}
		}()

		select {
		case res := <-ch:
			// Carry config forward so LLM client stays valid
			res.rich.Report.Config = cfg
			return scanCompleteMsg{
				report:   res.rich.Report,
				external: res.rich.External,
				nfr:      res.rich.NFR,
				deploy:   res.rich.Deploy,
				network:  res.rich.Network,
			}
		case <-ctx.Done():
			return scanCompleteMsg{
				err: fmt.Errorf("scan timed out after 5 minutes — try scanning a smaller directory"),
			}
		}
	}
}

type autofixMsg struct {
	content  string
	logMsg   string
	logLevel LogLevel
	err      error
}

// autofixCmd runs deterministic autofix for a single finding.
func (m *DashboardModel) autofixCmd(res core.CheckResult, apply bool) tea.Cmd {
	return func() tea.Msg {
		// Create a minimal report with just this finding
		miniReport := scanner.ScanReport{
			ProjectPath: m.Report.ProjectPath,
			Results:     []core.CheckResult{res},
		}
		results := remedy.AutoFix(miniReport, apply)

		var b strings.Builder
		if apply {
			b.WriteString(lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).
				Render("⚡ AUTOFIX APPLIED: "+res.Name) + "\n")
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).
				Render("⚡ AUTOFIX DRY-RUN: "+res.Name) + "\n")
		}
		b.WriteString(strings.Repeat("─", 40) + "\n\n")

		var logMsg string
		var logLevel LogLevel

		if len(results) == 0 {
			b.WriteString(lipgloss.NewStyle().Foreground(colorGray).
				Render("No automatic fix available for rule " + res.ID + ".\n" +
					"Use ENTER to request AI-powered remediation advice."))
			logMsg = "No automatic fix available for " + res.ID
			logLevel = LogWarn
		} else {
			hasApplied := false
			hasError := false
			for _, fr := range results {
				if fr.Err != nil {
					hasError = true
					fmt.Fprintf(&b, "ERROR: %v\n", fr.Err)
				} else if fr.Applied {
					hasApplied = true
					b.WriteString(lipgloss.NewStyle().Foreground(colorSuccess).Render("✔ FIX APPLIED SUCCESSFULLY") + "\n\n")
					b.WriteString(highlightCode("diff", fr.Description) + "\n")
				} else {
					if apply {
						b.WriteString(lipgloss.NewStyle().Foreground(colorError).Render("❌ FIX FAILED") + "\n\n")
					} else {
						b.WriteString(lipgloss.NewStyle().Foreground(colorGray).Render("~ DRY RUN PREVIEW") + "\n\n")
					}
					// If the description is a diff, highlight it. Otherwise just print.
					if strings.HasPrefix(fr.Description, "---") || strings.HasPrefix(fr.Description, "Add ") || strings.HasPrefix(fr.Description, "Run:") {
						if strings.HasPrefix(fr.Description, "---") {
							b.WriteString(highlightCode("diff", fr.Description) + "\n")
						} else {
							b.WriteString(fr.Description + "\n")
						}
					} else {
						b.WriteString(fr.Description + "\n")
					}
				}
			}

			if apply {
				if hasApplied {
					logMsg = "Autofix applied successfully: " + res.ID
					logLevel = LogSuccess
				} else if hasError {
					logMsg = "Autofix failed to apply: " + res.ID
					logLevel = LogError
				} else {
					logMsg = "Autofix ran but made no changes: " + res.ID
					logLevel = LogWarn
				}
			} else {
				if hasError {
					logMsg = "Autofix dry-run encountered errors: " + res.ID
					logLevel = LogError
				} else {
					logMsg = "Autofix dry-run complete: " + res.ID
					logLevel = LogInfo
				}
			}
		}
		return autofixMsg{
			content:  b.String(),
			logMsg:   logMsg,
			logLevel: logLevel,
		}
	}
}

type exportMsg struct {
	content string
	err     error
}

// exportCmd exports the current report in SARIF format.
// Writes to the project root directory.
func (m *DashboardModel) exportCmd() tea.Cmd {
	return func() tea.Msg {
		data, err := m.Report.ToSARIF()
		if err != nil {
			return exportMsg{err: fmt.Errorf("failed to generate SARIF: %w", err)}
		}

		filename := filepath.Join(m.Report.ProjectPath, "aitriage-report.sarif")
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return exportMsg{err: fmt.Errorf("failed to write file: %w", err)}
		}
		return exportMsg{content: fmt.Sprintf("SARIF Report exported to: %s", filename)}
	}
}

// generateCICDCmd creates a default GitHub Actions workflow for AITriage.
func (m *DashboardModel) generateCICDCmd() tea.Cmd {
	return func() tea.Msg {
		workflowDir := filepath.Join(m.Report.ProjectPath, ".github", "workflows")
		if err := os.MkdirAll(workflowDir, 0755); err != nil {
			return exportMsg{err: fmt.Errorf("failed to create workflow dir: %w", err)}
		}

		workflowContent := `name: AITriage Security Scan

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Run AITriage Scanner
      run: |
        curl -sSfL https://raw.githubusercontent.com/dodobrands/aitriage/main/install.sh | sh
        ./aitriage scan . --export-sarif

    - name: Upload SARIF report
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: aitriage-report.sarif
`
		filename := filepath.Join(workflowDir, "aitriage.yaml")
		if err := os.WriteFile(filename, []byte(workflowContent), 0644); err != nil {
			return exportMsg{err: fmt.Errorf("failed to write workflow file: %w", err)}
		}

		return exportMsg{content: fmt.Sprintf("GitHub Actions workflow created at: %s", filename)}
	}
}

// generateGitHookCmd installs AITriage as a pre-commit hook.
func (m *DashboardModel) generateGitHookCmd() tea.Cmd {
	return func() tea.Msg {
		hooksDir := filepath.Join(m.Report.ProjectPath, ".git", "hooks")
		if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
			return exportMsg{err: fmt.Errorf("not a git repository (or .git/hooks missing)")}
		}

		hookContent := `#!/bin/sh
# AITriage Pre-commit Hook

echo "🛡️ Running AITriage Security Scan..."

# Run scan and fail if HIGH or CRITICAL issues are found
aitriage scan . --fail-on=HIGH

if [ $? -ne 0 ]; then
    echo "❌ AITriage found critical security issues. Commit blocked."
    echo "Run 'aitriage fix .' to auto-remediate."
    exit 1
fi

echo "✅ AITriage scan passed."
exit 0
`
		filename := filepath.Join(hooksDir, "pre-commit")
		if err := os.WriteFile(filename, []byte(hookContent), 0755); err != nil { // Executable permissions
			return exportMsg{err: fmt.Errorf("failed to write hook file: %w", err)}
		}

		return exportMsg{content: fmt.Sprintf("Pre-commit hook installed at: %s", filename)}
	}
}

type chatResponseMsg struct {
	content string
	tokens  int
	err     error
}

func (m DashboardModel) chatCmd(prompt string) tea.Cmd {
	return func() tea.Msg {
		if m.LLMClient == nil {
			return chatResponseMsg{err: fmt.Errorf("no LLM client")}
		}

		// ── Build deep scan context for grounded, expert-level answers ──
		var reportCtx strings.Builder
		if len(m.Report.Results) > 0 {
			sevCounts := map[string]int{}
			catCounts := map[string]int{}
			for _, r := range m.Report.Results {
				sevCounts[r.Severity]++
				catCounts[r.Framework]++
			}
			fmt.Fprintf(&reportCtx, "SCAN METRICS: SecurityScore=%d/100, Total=%d, CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d\n",
				m.Report.SecurityScore, len(m.Report.Results),
				sevCounts["CRITICAL"], sevCounts["HIGH"], sevCounts["MEDIUM"], sevCounts["LOW"])
			fmt.Fprintf(&reportCtx, "EXTERNAL: SAST=%d, NFR=%d, Deploy=%d, Network=%d\n",
				len(m.ExternalFindings), len(m.NFRFindings), len(m.DeployFindings), len(m.NetworkFindings))
			// Category breakdown
			reportCtx.WriteString("CATEGORIES: ")
			for cat, cnt := range catCounts {
				fmt.Fprintf(&reportCtx, "%s=%d ", cat, cnt)
			}
			reportCtx.WriteString("\n\n")
			// All findings (up to 30 for context window)
			reportCtx.WriteString("ALL FINDINGS:\n")
			for i, r := range m.Report.Results {
				if i >= 30 {
					fmt.Fprintf(&reportCtx, "... and %d more findings\n", len(m.Report.Results)-30)
					break
				}
				fmt.Fprintf(&reportCtx, "  [%s] %s | %s | %s:%d | Evidence: %s\n",
					r.Severity, r.ID, r.Name, r.File, r.Line, r.Evidence)
			}
			// NFR findings
			if len(m.NFRFindings) > 0 {
				reportCtx.WriteString("\nNFR FINDINGS:\n")
				for i, f := range m.NFRFindings {
					if i >= 10 {
						break
					}
					fmt.Fprintf(&reportCtx, "  [%s] %s: %s\n", f.Severity, f.Name, f.Message)
				}
			}
			// Deploy findings
			if len(m.DeployFindings) > 0 {
				reportCtx.WriteString("\nDEPLOY FINDINGS:\n")
				for i, f := range m.DeployFindings {
					if i >= 10 {
						break
					}
					fmt.Fprintf(&reportCtx, "  [%s] %s: %s (%s)\n", f.Severity, f.Issue, f.Evidence, f.File)
				}
			}
			// Network findings
			if len(m.NetworkFindings) > 0 {
				reportCtx.WriteString("\nNETWORK FINDINGS:\n")
				for i, f := range m.NetworkFindings {
					if i >= 10 {
						break
					}
					fmt.Fprintf(&reportCtx, "  [%s] %s:%d %s\n", f.Severity, f.Service, f.Port, f.Message)
				}
			}
		}

		// ── Mythos-grade system prompt ──
		systemPrompt := fmt.Sprintf(`You are a senior offensive security researcher and threat analyst embedded in the AITriage SAST platform. You operate at the level of a principal security engineer conducting a comprehensive security audit.

IDENTITY:
- You are NOT a chatbot. You are a security analyst embedded in a live scan context.
- You have complete access to all scan findings, architecture data, and vulnerability details.
- Your analysis should match the depth of a professional penetration test report.

RESPONSE RULES:
1. LANGUAGE: Match user's language exactly. Russian → Russian. English → English.
2. NO FILLER: Zero preamble. No "I'd be happy to", "Sure!", "Great question". Start with content.
3. FORMAT: Use markdown headers (##), **bold** for key terms, bullet lists, code blocks when showing fixes.
4. DEPTH: Provide thorough analysis. Use CVSS v3.1 scoring where applicable. Reference specific findings by ID.
5. NEVER repeat raw scan statistics — the user sees them in the dashboard.
6. NEVER say "based on the scan results" or restate the context prompt.
7. ACTIONABLE: Every response must end with concrete next steps the engineer can take.
8. EXPLOIT AWARENESS: When discussing vulnerabilities, assess real-world exploitability — not just theoretical risk.

ANALYSIS FRAMEWORKS (use when relevant):
- STRIDE for threat modeling
- CVSS v3.1 for severity scoring  
- OWASP Top 10 2021 for classification
- Kill Chain / ATT&CK for attack path analysis

%s`, reportCtx.String())

		// Build conversation with full history for context-aware responses
		messages := []llm.Message{
			{Role: "system", Content: systemPrompt},
		}
		for _, msg := range m.ChatHistory {
			switch msg.Sender {
			case "USER":
				messages = append(messages, llm.Message{Role: "user", Content: msg.Content})
			case "AI":
				messages = append(messages, llm.Message{Role: "assistant", Content: msg.Content})
			}
		}

		resp, usage, err := m.LLMClient.Chat(context.Background(), messages)
		if err != nil {
			return chatResponseMsg{err: err}
		}

		return chatResponseMsg{content: resp, tokens: usage.TotalTokens}
	}
}

type ruleGeneratedMsg struct {
	rulePath string
	err      error
}

func (m DashboardModel) generateRuleCmd(targetPath, intent string) tea.Cmd {
	return func() tea.Msg {
		if m.LLMClient == nil {
			return ruleGeneratedMsg{err: fmt.Errorf("no LLM client configured")}
		}

		contentBytes, err := os.ReadFile(targetPath)
		if err != nil {
			return ruleGeneratedMsg{err: fmt.Errorf("failed to read target file: %w", err)}
		}

		content := string(contentBytes)
		if len(content) > 16384 {
			content = content[:16384] // truncate for token limits
		}

		prompt := fmt.Sprintf(`You are a senior security engineer writing a custom SAST rule for AITriage.
The user wants to detect a specific pattern or vulnerability in the codebase.

TARGET FILE CONTENT (for context):
%s

USER INTENT:
%s

Generate a valid AITriage YAML custom rule. 
The rule MUST be a single YAML list item. It MUST start exactly with "- id:"
Like this:
- id: A unique, descriptive ID (e.g., custom-detect-hardcoded-token)
  name: Human readable name
  severity: CRITICAL, HIGH, MEDIUM, or LOW
  message: Explanation of what was found
  recommendation: How to fix it
  regex: The Go-compatible regular expression to find this pattern
  path: A Go-compatible regex to match file paths where this rule applies (e.g., "\.go$")

Return ONLY the raw YAML content, no markdown blocks or surrounding text.`, content, intent)

		messages := []llm.Message{
			{Role: "user", Content: prompt},
		}

		resp, _, err := m.LLMClient.Chat(context.Background(), messages)
		if err != nil {
			return ruleGeneratedMsg{err: err}
		}

		// Clean up the response
		resp = strings.TrimSpace(resp)
		resp = strings.TrimPrefix(resp, "```yaml")
		resp = strings.TrimPrefix(resp, "```")
		resp = strings.TrimSuffix(resp, "```")
		resp = strings.TrimSpace(resp)

		// Ensure the .aitriage directory exists
		aitriageDir := filepath.Join(m.Report.ProjectPath, ".aitriage")
		if err := os.MkdirAll(aitriageDir, 0755); err != nil {
			return ruleGeneratedMsg{err: fmt.Errorf("failed to create .aitriage dir: %w", err)}
		}

		rulePath := filepath.Join(aitriageDir, "custom_rules.yaml")

		// Read existing rules if any
		var existingRules string
		if existing, err := os.ReadFile(rulePath); err == nil {
			existingRules = string(existing) + "\n\n"
		}

		newRules := existingRules + resp + "\n"
		if err := os.WriteFile(rulePath, []byte(newRules), 0644); err != nil {
			return ruleGeneratedMsg{err: fmt.Errorf("failed to write rule to %s: %w", rulePath, err)}
		}

		return ruleGeneratedMsg{rulePath: rulePath}
	}
}

// handleResize recalculates box-model dimensions for all responsive sub-components
// based on the total available terminal width and height.
func (m *DashboardModel) handleResize(w, h int) {
	headerH := 3 // Line 1 + gap + Line 2 (tabs) — sync with view.go headerHeight
	footerH := 1 // Footer bar — sync with view.go footerHeight

	bodyHeight := h - headerH - footerH
	if bodyHeight < 0 {
		bodyHeight = 0
	}

	contentWidth := w
	if contentWidth < 0 {
		contentWidth = 0
	}

	// 1. File Viewer
	m.FileViewport.Width = contentWidth
	m.FileViewport.Height = bodyHeight

	// 2. Triage Table & Viewports
	tableWidth := (contentWidth * 6) / 10

	tableInnerHeight := bodyHeight
	if tableInnerHeight < 0 {
		tableInnerHeight = 0
	}

	m.Table.SetWidth(tableWidth)

	availableWidth := tableWidth - 5 // Account for Padding(0, 1, 0, 0) * 5 columns = 5 spaces
	if availableWidth < 20 {
		availableWidth = 20
	}

	idW := (availableWidth * 15) / 100
	if idW < 4 {
		idW = 4
	}
	sevW := (availableWidth * 10) / 100
	if sevW < 4 {
		sevW = 4
	}
	statusW := (availableWidth * 12) / 100
	if statusW < 6 {
		statusW = 6
	}
	issueW := (availableWidth * 35) / 100
	if issueW < 10 {
		issueW = 10
	}

	pathW := availableWidth - idW - sevW - statusW - issueW
	if pathW < 5 {
		pathW = 5
	}

	m.Table.SetColumns([]table.Column{
		{Title: "ID", Width: idW},
		{Title: "SEV", Width: sevW},
		{Title: "ISSUE", Width: issueW},
		{Title: "PATH", Width: pathW},
		{Title: "STATUS", Width: statusW},
	})

	m.Table.SetHeight(tableInnerHeight)

	rightWidth := contentWidth - tableWidth - 1
	if rightWidth < 0 {
		rightWidth = 0
	}

	codeBoxOuter := bodyHeight / 2
	remediationOuter := bodyHeight - codeBoxOuter

	codeBoxInner := codeBoxOuter - 1 // 1 for title
	if codeBoxInner < 0 {
		codeBoxInner = 0
	}
	m.Viewport.Width = rightWidth
	m.Viewport.Height = codeBoxInner

	remediationInner := remediationOuter - 1 // 1 for title
	if remediationInner < 0 {
		remediationInner = 0
	}
	m.RemediationViewport.Width = rightWidth
	m.RemediationViewport.Height = remediationInner

	// 2. SAST Table & Viewport — same split as Triage but using SASTTable
	m.SASTTable.SetWidth(tableWidth)

	sastAvailW := tableWidth - 5
	if sastAvailW < 20 {
		sastAvailW = 20
	}
	srcW := (sastAvailW * 12) / 100
	if srcW < 6 {
		srcW = 6
	}
	ruleW := (sastAvailW * 20) / 100
	if ruleW < 8 {
		ruleW = 8
	}
	sSevW := (sastAvailW * 10) / 100
	if sSevW < 4 {
		sSevW = 4
	}
	sMsgW := (sastAvailW * 35) / 100
	if sMsgW < 10 {
		sMsgW = 10
	}
	sFileW := sastAvailW - srcW - ruleW - sSevW - sMsgW
	if sFileW < 5 {
		sFileW = 5
	}

	m.SASTTable.SetColumns([]table.Column{
		{Title: "SOURCE", Width: srcW},
		{Title: "RULE", Width: ruleW},
		{Title: "SEV", Width: sSevW},
		{Title: "MESSAGE", Width: sMsgW},
		{Title: "FILE", Width: sFileW},
	})
	m.SASTTable.SetHeight(tableInnerHeight)

	// SAST Viewport = full right pane (no split like Triage)
	m.SASTViewport.Width = rightWidth
	m.SASTViewport.Height = bodyHeight - 1
	if m.SASTViewport.Height < 0 {
		m.SASTViewport.Height = 0
	}

	// 3. Chat Viewport & Input — split-pane layout
	// Left panel: 35% width, Right panel: 65% width, 1 char separator
	chatLeftW := contentWidth * 35 / 100
	if chatLeftW < 28 {
		chatLeftW = 28
	}
	if chatLeftW > 45 {
		chatLeftW = 45
	}
	chatRightW := contentWidth - chatLeftW - 1
	if chatRightW < 10 {
		chatRightW = 10
	}
	// renderChat: bodyH(h-1) → rightTitle(1) + chatBox(chatHeight) = bodyH-1
	chatHeight := bodyHeight - 2 // title + input
	if chatHeight < 0 {
		chatHeight = 0
	}

	m.ChatViewport.Width = chatRightW
	m.ChatViewport.Height = chatHeight

	m.TextInput.Width = contentWidth - 4 // Padding for prompt " ❯ "

	// 4. Graph Viewport
	m.GraphViewport.Width = contentWidth
	graphH := bodyHeight - 1 // 1 for title bar
	if graphH < 0 {
		graphH = 0
	}
	m.GraphViewport.Height = graphH
	// Re-set content with correct dimensions (only on resize, not every frame)
	if m.GraphTreeCache != "" {
		m.GraphViewport.SetContent(m.GraphTreeCache)
	}

	// 5. Deps Table — responsive columns + styles
	m.DepsTable.SetWidth(contentWidth)
	m.DepsTable.SetHeight(bodyHeight)

	// 6. Log Viewport
	m.LogViewport.Width = contentWidth
	logH := bodyHeight - 1
	if logH < 0 {
		logH = 0
	}
	m.LogViewport.Height = logH
	m.formatLogViewport()

	depsUsable := contentWidth - 4
	if depsUsable < 20 {
		depsUsable = 20
	}
	dColName := depsUsable * 40 / 100
	dColVer := depsUsable * 20 / 100
	dColType := depsUsable * 20 / 100
	dColEco := depsUsable - dColName - dColVer - dColType

	m.DepsTable.SetColumns([]table.Column{
		{Title: "NAME", Width: dColName},
		{Title: "VERSION", Width: dColVer},
		{Title: "TYPE", Width: dColType},
		{Title: "ECOSYSTEM", Width: dColEco},
	})

	depsStyles := table.DefaultStyles()
	depsStyles.Header = depsStyles.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorOutline).
		BorderBottom(true).
		Bold(false).
		Foreground(colorGray).
		Background(colorBG)
	depsStyles.Selected = depsStyles.Selected.
		Foreground(colorOnPrimary).
		Background(colorPrimaryCont).
		Bold(true)
	depsStyles.Cell = lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Padding(0, 1, 0, 0)
	m.DepsTable.SetStyles(depsStyles)

	// 6. Infra Table — responsive columns + styles
	m.InfraTable.SetWidth(contentWidth)
	m.InfraTable.SetHeight(bodyHeight)

	infraUsable := contentWidth - 4
	if infraUsable < 20 {
		infraUsable = 20
	}
	iColType := infraUsable * 10 / 100
	iColSev := infraUsable * 10 / 100
	iColFind := infraUsable * 45 / 100
	iColTarget := infraUsable - iColType - iColSev - iColFind
	if iColType < 6 {
		iColType = 6
	}
	if iColSev < 4 {
		iColSev = 4
	}
	if iColTarget < 10 {
		iColTarget = 10
	}

	m.InfraTable.SetColumns([]table.Column{
		{Title: "TYPE", Width: iColType},
		{Title: "SEV", Width: iColSev},
		{Title: "FINDING", Width: iColFind},
		{Title: "TARGET", Width: iColTarget},
	})

	infraStyles := table.DefaultStyles()
	infraStyles.Header = infraStyles.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorOutline).
		BorderBottom(true).
		Bold(false).
		Foreground(colorGray).
		Background(colorBG)
	infraStyles.Selected = infraStyles.Selected.
		Foreground(colorOnPrimary).
		Background(colorPrimaryCont).
		Bold(true)
	infraStyles.Cell = lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Padding(0, 1, 0, 0)
	m.InfraTable.SetStyles(infraStyles)
}

// --- Dashboard Summary ---

type dashboardSummaryMsg struct {
	content string
	tokens  int
	err     error
}

func (m *DashboardModel) dashboardSummaryCmd() tea.Cmd {
	return func() tea.Msg {
		if m.LLMClient == nil {
			return dashboardSummaryMsg{err: fmt.Errorf("no LLM client")}
		}

		// Build findings context
		sevCounts := map[string]int{}
		for _, r := range m.Report.Results {
			sevCounts[r.Severity]++
		}

		var findingsCtx strings.Builder
		fmt.Fprintf(&findingsCtx, "SecurityScore: %d/100\n", m.Report.SecurityScore)
		fmt.Fprintf(&findingsCtx, "Total: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW)\n",
			len(m.Report.Results), sevCounts["CRITICAL"], sevCounts["HIGH"], sevCounts["MEDIUM"], sevCounts["LOW"])
		fmt.Fprintf(&findingsCtx, "Files scanned: %d | Rules applied: %d\n", m.Report.TotalFiles, m.Report.RulesApplied)
		fmt.Fprintf(&findingsCtx, "External SAST: %d | NFR: %d | Deploy: %d\n",
			len(m.ExternalFindings), len(m.NFRFindings), len(m.DeployFindings))

		// Top 5 critical findings
		count := 0
		for _, r := range m.Report.Results {
			if count >= 5 {
				break
			}
			if r.Severity == "CRITICAL" || r.Severity == "HIGH" {
				fmt.Fprintf(&findingsCtx, "- [%s] %s: %s (%s:%d)\n", r.Severity, r.Name, r.Evidence, r.File, r.Line)
				count++
			}
		}

		messages := []llm.Message{
			{Role: "system", Content: `You are the AITriage executive summary engine. Generate a concise security brief in EXACTLY this format:

STATUS: [one of: CRITICAL RISK / HIGH RISK / MODERATE RISK / SECURE]

TOP THREATS:
1. [threat + file + one-line fix]
2. [threat + file + one-line fix]
3. [threat + file + one-line fix]

ACTION PLAN:
- [immediate action 1]
- [immediate action 2]
- [immediate action 3]

Rules: Max 12 lines. Be terse. No filler. Focus on what to fix NOW.`},
			{Role: "user", Content: "Generate executive security summary for this scan:\n\n" + findingsCtx.String()},
		}

		resp, usage, err := m.LLMClient.Chat(context.Background(), messages)
		if err != nil {
			return dashboardSummaryMsg{err: err}
		}
		return dashboardSummaryMsg{content: resp, tokens: usage.TotalTokens}
	}
}

// --- Context Export ---

type contextExportMsg struct {
	content string
	err     error
}

func (m *DashboardModel) contextExportCmd() tea.Cmd {
	return func() tea.Msg {
		// Write to /tmp/aitriage/context/ to avoid read-only filesystem in Docker
		baseDir := "/tmp/aitriage/context"
		if err := os.MkdirAll(baseDir, 0755); err != nil {
			return contextExportMsg{err: fmt.Errorf("mkdir failed: %w", err)}
		}

		// 1. findings.json
		findingsData, err := json.MarshalIndent(m.Report.Results, "", "  ")
		if err != nil {
			return contextExportMsg{err: err}
		}
		_ = os.WriteFile(filepath.Join(baseDir, "findings.json"), findingsData, 0644)

		// 2. severity_map.json
		sevMap := map[string]int{}
		for _, r := range m.Report.Results {
			sevMap[r.Severity]++
		}
		sevData, _ := json.MarshalIndent(map[string]interface{}{
			"security_score":      m.Report.SecurityScore,
			"total_findings":      len(m.Report.Results),
			"severity_breakdown":  sevMap,
			"external_sast_count": len(m.ExternalFindings),
			"nfr_count":           len(m.NFRFindings),
			"deploy_count":        len(m.DeployFindings),
		}, "", "  ")
		_ = os.WriteFile(filepath.Join(baseDir, "severity_map.json"), sevData, 0644)

		// 3. summary.md
		var summary strings.Builder
		summary.WriteString("# AITriage Security Summary\n\n")
		fmt.Fprintf(&summary, "**Project:** %s\n", m.Report.ProjectPath)
		fmt.Fprintf(&summary, "**Score:** %d/100\n", m.Report.SecurityScore)
		fmt.Fprintf(&summary, "**Scan Time:** %s\n\n", m.ScanStartTime.Format(time.RFC3339))
		summary.WriteString("## Critical & High Findings\n\n")
		for _, r := range m.Report.Results {
			if r.Severity == "CRITICAL" || r.Severity == "HIGH" {
				fmt.Fprintf(&summary, "### [%s] %s\n- **File:** %s:%d\n- **Evidence:** %s\n- **Fix:** %s\n\n",
					r.Severity, r.Name, r.File, r.Line, r.Evidence, r.Suggestion)
			}
		}
		if m.DashboardSummary != "" {
			summary.WriteString("## AI Executive Summary\n\n")
			summary.WriteString(m.DashboardSummary + "\n")
		}
		_ = os.WriteFile(filepath.Join(baseDir, "summary.md"), []byte(summary.String()), 0644)

		// 4. prompt.txt — ready for AI IDE
		var prompt strings.Builder
		prompt.WriteString("You are analyzing a software project with security vulnerabilities.\n\n")
		prompt.WriteString("Context: " + string(sevData) + "\n\n")
		prompt.WriteString("Findings:\n")
		for _, r := range m.Report.Results {
			fmt.Fprintf(&prompt, "- [%s] %s in %s:%d — %s\n", r.Severity, r.Name, r.File, r.Line, r.Evidence)
		}
		prompt.WriteString("\nProvide prioritized remediation with code fixes.\n")
		_ = os.WriteFile(filepath.Join(baseDir, "prompt.txt"), []byte(prompt.String()), 0644)

		return contextExportMsg{content: fmt.Sprintf(
			"Context exported to %s/ (4 files: findings.json, severity_map.json, summary.md, prompt.txt)",
			baseDir,
		)}
	}
}

func (m *DashboardModel) applySearchFilter() {
	query := strings.ToLower(m.SearchQuery)

	// Update Browser
	if m.ActiveView == ViewBrowser || m.ActiveView == ViewDashboard {
		// Just re-load the dir to apply the filter (need to update loadBrowserDir)
		m.loadBrowserDir(m.BrowserDir)
	}

	// Filter VULN Table
	var triageRows []table.Row
	for _, res := range m.Report.Results {
		if query == "" || strings.Contains(strings.ToLower(res.Name), query) || strings.Contains(strings.ToLower(res.File), query) || strings.Contains(strings.ToLower(res.ID), query) {
			triageRows = append(triageRows, table.Row{
				res.ID,
				res.Severity,
				res.Name,
				res.File,
				string(res.Status),
			})
		}
	}
	m.Table.SetRows(triageRows)

	// Filter SAST Table
	m.SASTTable.SetRows(buildSASTRowsFiltered(m.ExternalFindings, m.NFRFindings, query))

	// Filter DEPS Table
	m.DepsTable.SetRows(buildDepsRowsFiltered(m.Report.Dependencies, query))

	// Filter INFRA Table
	m.InfraTable.SetRows(buildInfraRowsFiltered(m.DeployFindings, m.NetworkFindings, query))

	// Topology search filter
	m.TopologyFilter = query
	m.TopologyNodes = BuildTopologyNodesFiltered(m.DepGraph, m.TopologyExpanded, m.TopologyFilter)
	m.TopologyCursor = 0
}

func (m *DashboardModel) initConfigInputs() {
	if len(m.ConfigInputs) == 0 {
		m.ConfigInputs = make([]textinput.Model, 4)
		for i := range m.ConfigInputs {
			m.ConfigInputs[i] = textinput.New()
			m.ConfigInputs[i].TextStyle = lipgloss.NewStyle().Foreground(colorText).Background(colorSurfaceHigh)
			m.ConfigInputs[i].PlaceholderStyle = lipgloss.NewStyle().Foreground(colorGray).Background(colorSurfaceHigh)
			m.ConfigInputs[i].Cursor.Style = lipgloss.NewStyle().Foreground(colorSecondary)
		}

		// Map inputs to config fields
		// 1. Strict Mode
		m.ConfigInputs[0].Placeholder = "true or false"
		m.ConfigInputs[0].SetValue("false") // Default, ideally read from actual config

		// 2. Fail Score
		m.ConfigInputs[1].Placeholder = "0-100"
		m.ConfigInputs[1].SetValue("0")

		// 3. LLM Provider
		m.ConfigInputs[2].Placeholder = "gemini, openai, anthropic"
		m.ConfigInputs[2].SetValue("gemini")

		// 4. LLM Model
		m.ConfigInputs[3].Placeholder = llm.DefaultGeminiModel
		m.ConfigInputs[3].SetValue(llm.DefaultGeminiModel)

		m.ConfigFocusIndex = 0
		m.ConfigInputs[0].Focus()
	}
}

func (m *DashboardModel) saveConfig() tea.Cmd {
	// Write configuration to .aitriage.yaml
	configPath := filepath.Join(m.Report.ProjectPath, ".aitriage.yaml")

	strictMode := m.ConfigInputs[0].Value() == "true"
	failScore := 0
	_, _ = fmt.Sscanf(m.ConfigInputs[1].Value(), "%d", &failScore)

	yamlContent := fmt.Sprintf(`strict_mode: %t
fail_score: %d
llm:
  provider: %s
  model: %s
`, strictMode, failScore, m.ConfigInputs[2].Value(), m.ConfigInputs[3].Value())

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		m.ConfigSavedMsg = "Error saving config: " + err.Error()
	} else {
		m.ConfigSavedMsg = "Configuration saved to .aitriage.yaml"
	}
	m.ConfigSavedTTL = 5
	return nil
}
