package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/dodobrands/aitriage/internal/telemetry"
)

// renderMarkdownToTerminal converts raw markdown (from LLM) into styled
// terminal text using glamour. Falls back to raw text on error.
func renderMarkdownToTerminal(raw string, width int) string {
	if width < 20 {
		width = 60
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle("dark"),
		glamour.WithWordWrap(width-4),
	)
	if err != nil {
		return raw // fallback: show as-is
	}
	rendered, err := r.Render(raw)
	if err != nil {
		return raw
	}
	// Trim trailing whitespace added by glamour
	return strings.TrimRight(rendered, "\n ")
}

var (
	// Silent Luxury Palette — STRICTLY from DESIGN.md
	colorBG             = lipgloss.Color("#0d1515") // surface / background
	colorSurfaceBright  = lipgloss.Color("#323b3b") // surface-bright
	colorSurfaceLowest  = lipgloss.Color("#081010") // surface-container-lowest
	colorSurface        = lipgloss.Color("#192121") // surface-container
	colorSurfaceHigh    = lipgloss.Color("#232b2c") // surface-container-high
	colorSurfaceHighest = lipgloss.Color("#2e3637") // surface-container-highest
	colorText           = lipgloss.Color("#dce4e4") // on-surface
	colorTextVariant    = lipgloss.Color("#b9caca") // on-surface-variant
	colorOutline        = lipgloss.Color("#3a494a") // outline-variant
	colorGray           = lipgloss.Color("#849495") // outline
	colorPrimary        = lipgloss.Color("#e9feff") // primary (off-white for text)
	colorOnPrimary      = lipgloss.Color("#003739") // on-primary (dark text on cyan)
	colorPrimaryCont    = lipgloss.Color("#00f5ff") // primary-container (CYAN — selection)
	colorOnPrimaryCont  = lipgloss.Color("#006c71") // on-primary-container
	colorPrimaryDim     = lipgloss.Color("#00dce5") // surface-tint
	colorSecondary      = lipgloss.Color("#b8c3ff") // secondary (cobalt)
	colorSecondaryBG    = lipgloss.Color("#0043eb") // secondary-container
	colorTertiary       = lipgloss.Color("#fff9f0") // tertiary
	colorTertiaryCont   = lipgloss.Color("#ffdb3f") // tertiary-container (amber)
	colorError          = lipgloss.Color("#ffb4ab") // error
	colorErrorContainer = lipgloss.Color("#93000a") // error-container
	colorSuccess        = lipgloss.Color("#00ffb2") // success (mint)
	colorAccent         = lipgloss.Color("#b8c3ff") // secondary (cobalt)

	_ = colorSurface // suppress unused
	_ = colorSurfaceLowest
	_ = colorSurfaceBright
	_ = colorSurfaceHighest
	_ = colorTextVariant
	_ = colorOnPrimary
	_ = colorOnPrimaryCont
	_ = colorSecondaryBG
	_ = colorTertiary
	_ = colorTertiaryCont
	_ = colorErrorContainer

	appStyle = lipgloss.NewStyle().
			Background(colorBG).
			Foreground(colorText)

	_ = appStyle

	headerStyle = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Background(colorBG)

	_ = headerStyle

	footerStyle = lipgloss.NewStyle().
			Foreground(colorGray).
			Background(colorBG)

	_ = footerStyle

	activeTabStyle = lipgloss.NewStyle().
			Foreground(colorBG).
			Background(colorPrimaryCont).
			Bold(true)

	// Background colorBG is mandatory, otherwise the terminal substitutes its own black
	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(colorGray).
				Background(colorBG)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorGray).
			Background(colorBG).
			Bold(true)

	// panelStyle — base block; background is mandatory
	panelStyle = lipgloss.NewStyle().
			Background(colorBG).
			Foreground(colorText)

	_ = panelStyle

	// Severity styles per DESIGN.md semantic palette:
	// CRITICAL = error (#ffb4ab), HIGH = tertiary-container/amber (#ffdb3f)
	// MEDIUM = secondary/cobalt (#b8c3ff), LOW = outline/gray (#849495)
	lowStyle      = lipgloss.NewStyle().Foreground(colorGray).Background(colorBG)
	mediumStyle   = lipgloss.NewStyle().Foreground(colorSecondary).Background(colorBG)
	highStyle     = lipgloss.NewStyle().Foreground(colorTertiaryCont).Background(colorBG)
	criticalStyle = lipgloss.NewStyle().Foreground(colorError).Background(colorBG).Bold(true)
)

const (
	headerHeight = 3
	footerHeight = 1
)

// bgANSI is the raw ANSI escape for our background color.
// selBgParam is the core SGR parameter (e.g. "48;2;0;245;255") for the selected
// row background. We use the raw SGR param instead of the full ANSI escape because
// lipgloss may combine Bold+FG+BG into a single \x1b[1;38;...;48;2;R;G;Bm sequence.
// Matching the param substring works regardless of how lipgloss formats the escape.
var bgANSI string
var bgANSIOnce sync.Once

func ensureBgANSI() {
	bgANSIOnce.Do(func() {
		// Render a single space with ONLY background — extract the ANSI prefix.
		rendered := lipgloss.NewStyle().Background(colorBG).Render(" ")
		idx := strings.Index(rendered, " ")
		if idx > 0 {
			bgANSI = rendered[:idx]
		}
		// Extract the core SGR param for selected bg.
		// colorPrimaryCont = #00f5ff = RGB(0,245,255) → SGR param "48;2;0;245;255"
		renderedSel := lipgloss.NewStyle().Background(colorPrimaryCont).Render(" ")
		// The full sequence is \x1b[48;2;0;245;255m — extract between \x1b[ and m
		if start := strings.Index(renderedSel, "\x1b["); start >= 0 {
			_ = renderedSel[start+2:]
		}
	})
}

// injectBG replaces every ANSI reset (\x1b[0m) with reset + our background color.
// This is the ROOT CAUSE fix: bubbles/table cells end with \x1b[0m which
// returns terminal to default bg. On light-theme terminals = white gaps.
func injectBG(s string) string {
	return injectBGColor(s, "")
}

// injectBGColor replaces every ANSI reset with reset + specified bg ANSI sequence.
// Handles both full SGR reset (\x1b[0m) and default-bg-only reset (\x1b[49m),
// which lipgloss uses interchangeably depending on style composition.
// If overrideBG is empty, uses the default bgANSI.
func injectBGColor(s string, overrideBG string) string {
	ensureBgANSI()
	bg := bgANSI
	if overrideBG != "" {
		bg = overrideBG
	}
	if bg == "" {
		return s
	}
	result := strings.ReplaceAll(s, "\x1b[0m", "\x1b[0m"+bg)
	result = strings.ReplaceAll(result, "\x1b[49m", "\x1b[49m"+bg)
	return result
}

// getBgANSI extracts the ANSI background escape sequence from a lipgloss.Color.
// Returns the FULL escape sequence (e.g. "\x1b[48;2;0;245;255m"), not just the param.
func getBgANSI(bg lipgloss.Color) string {
	rendered := lipgloss.NewStyle().Background(bg).Render(" ")
	if start := strings.Index(rendered, "\x1b["); start >= 0 {
		rest := rendered[start:]
		if end := strings.Index(rest[2:], "m"); end >= 0 {
			return rest[:end+3] // include \x1b[, params, and m
		}
	}
	return ""
}

// padBG renders N spaces with colorBG background.
func padBG(n int) string {
	if n <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Background(colorBG).Render(strings.Repeat(" ", n))
}

// padBGColor renders N spaces with a custom bg color.
func padBGColor(n int, bg lipgloss.Color) string {
	if n <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", n))
}

// bgFill ensures every character position in every line of content has colorBG.
// Two-phase approach:
//  1. injectBG — patches ANSI resets so inter-cell gaps inherit colorBG
//  2. padBG — explicit colored padding to reach target width w
func bgFill(content string, w int) string {
	return bgFillColor(content, w, "", colorBG)
}

// bgFillColor fills with a custom bg color and ANSI override.
func bgFillColor(content string, w int, ansiOverride string, padColor lipgloss.Color) string {
	if w <= 0 {
		return ""
	}
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		// Phase 1: patch ANSI resets to maintain background
		patched := injectBGColor(line, ansiOverride)
		// Phase 2: truncate if wider, pad if narrower
		vw := lipgloss.Width(patched)
		if vw > w {
			patched = ansi.Truncate(patched, w, "")
		} else if vw < w {
			patched = patched + padBGColor(w-vw, padColor)
		}
		result = append(result, patched)
	}
	return strings.Join(result, "\n")
}

// frameBuffer ensures the content fits EXACTLY into a w x h grid.
func frameBuffer(content string, w, h int) string {
	lines := strings.Split(content, "\n")
	emptyLine := padBG(w)
	var result []string

	for i := 0; i < h; i++ {
		if i < len(lines) {
			patched := injectBG(lines[i])
			vw := lipgloss.Width(patched)
			if vw > w {
				patched = ansi.Truncate(patched, w, "")
			} else if vw < w {
				patched = patched + padBG(w-vw)
			}
			result = append(result, patched)
		} else {
			result = append(result, emptyLine)
		}
	}

	return strings.Join(result, "\n")
}

// bgCell renders content with a custom foreground and colorBG background,
// padded to exactly w visual width. Uses injectBG for ANSI safety.
func bgCell(content string, w int, fg lipgloss.Color) string {
	if w <= 0 {
		return ""
	}
	styled := lipgloss.NewStyle().Background(colorBG).Foreground(fg).Render(content)
	patched := injectBG(styled)
	vw := lipgloss.Width(patched)
	if vw < w {
		return patched + padBG(w-vw)
	}
	return patched
}

func formatChip(key, value string, keyColor, valColor lipgloss.Color) string {
	k := lipgloss.NewStyle().Foreground(keyColor).Background(colorBG).Render(key)
	v := lipgloss.NewStyle().Foreground(valColor).Background(colorBG).Bold(true).Render(value)
	return k + lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).Render(":") + " " + v
}

// renderScanningOverlay renders the full-screen "Virtual Foundry" loading animation
// that shows while a scan is in progress, providing clear feedback about what's being scanned.
func (m DashboardModel) renderScanningOverlay(w, h int) string {
	ensureBgANSI()
	if w <= 0 || h <= 0 {
		return ""
	}

	var lines []string

	// Calculate vertical centering
	contentHeight := 18 // approximate content block height
	topPad := (h - contentHeight) / 3
	if topPad < 2 {
		topPad = 2
	}

	// Pad top
	emptyLine := bgFill("", w)
	for i := 0; i < topPad; i++ {
		lines = append(lines, emptyLine)
	}

	// ── Header Block ─────────────────────────────────────────────────────
	titleStyle := lipgloss.NewStyle().
		Foreground(colorPrimaryDim).
		Background(colorBG).
		Bold(true)

	subtitleStyle := lipgloss.NewStyle().
		Foreground(colorGray).
		Background(colorBG)

	pathStyle := lipgloss.NewStyle().
		Foreground(colorPrimaryCont).
		Background(colorBG).
		Bold(true)

	// Logo line
	logoLine := titleStyle.Render("  A I T R I A G E   //   V I R T U A L   F O U N D R Y")
	lines = append(lines, bgFill(logoLine, w))

	// Separator
	sepLine := subtitleStyle.Render("  " + strings.Repeat("─", min(w-4, 56)))
	lines = append(lines, bgFill(sepLine, w))

	// Empty line
	lines = append(lines, emptyLine)

	// Scan target
	scanPath := m.Report.ProjectPath
	if scanPath == "" {
		scanPath = m.BrowserDir
	}
	if scanPath == "" {
		scanPath = "."
	}
	// Truncate path if too long
	if len(scanPath) > w-20 && w > 30 {
		scanPath = "..." + scanPath[len(scanPath)-(w-23):]
	}
	targetLine := subtitleStyle.Render("  TARGET  ") + pathStyle.Render(scanPath)
	lines = append(lines, bgFill(targetLine, w))

	lines = append(lines, emptyLine)

	// ── Scan Phases ──────────────────────────────────────────────────────
	type scanPhase struct {
		label string
		delay int // tick delay before showing check
	}
	phases := []scanPhase{
		{"Initializing scan context", 3},
		{"Resolving upstream dependencies", 8},
		{"Initializing rule engine", 12},
		{"Detecting technology stacks", 18},
		{"Running security scanners", 25},
		{"Analyzing entropy patterns", 35},
		{"Scanning for hardcoded secrets", 42},
		{"Aggregating findings", 50},
	}

	spinFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	tick := m.TickCount

	checkStyle := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG)
	activeStyle := lipgloss.NewStyle().Foreground(colorPrimaryCont).Background(colorBG).Bold(true)
	pendingStyle := lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG)
	labelDoneStyle := lipgloss.NewStyle().Foreground(colorText).Background(colorBG)
	labelActiveStyle := lipgloss.NewStyle().Foreground(colorPrimaryCont).Background(colorBG)
	labelPendingStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG)

	for _, phase := range phases {
		var prefix, label string
		if tick >= phase.delay+5 {
			// Completed
			prefix = checkStyle.Render("  ✓")
			label = labelDoneStyle.Render("   " + phase.label)
		} else if tick >= phase.delay {
			// Active — spinning
			frame := spinFrames[tick%len(spinFrames)]
			prefix = activeStyle.Render("  " + frame)
			label = labelActiveStyle.Render("   " + phase.label)
		} else {
			// Pending
			prefix = pendingStyle.Render("  ·")
			label = labelPendingStyle.Render("   " + phase.label)
		}
		line := prefix + label
		lines = append(lines, bgFill(line, w))
	}

	lines = append(lines, emptyLine)

	// ── Progress indicator ───────────────────────────────────────────────
	progressWidth := min(w-8, 50)
	if progressWidth > 10 {
		filledPct := float64(tick) / 55.0
		if filledPct > 1.0 {
			filledPct = 1.0
		}
		filled := int(filledPct * float64(progressWidth))
		if filled > progressWidth {
			filled = progressWidth
		}
		bar := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).
			Render(strings.Repeat("█", filled))
		empty := lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).
			Render(strings.Repeat("░", progressWidth-filled))
		pctStr := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).
			Render(fmt.Sprintf(" %d%%", int(filledPct*100)))

		progressLine := subtitleStyle.Render("  ") + bar + empty + pctStr
		lines = append(lines, bgFill(progressLine, w))
	}

	lines = append(lines, emptyLine)

	// ── Hint ─────────────────────────────────────────────────────────────
	hintStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Italic(true)
	hintLine := hintStyle.Render("  Scanning in progress — please wait...")
	lines = append(lines, bgFill(hintLine, w))

	// Pad remaining lines
	for len(lines) < h {
		lines = append(lines, emptyLine)
	}
	if len(lines) > h {
		lines = lines[:h]
	}

	return strings.Join(lines, "\n")
}

// renderBrowser renders the full-screen file browser with split-pane layout.
func (m DashboardModel) renderBrowser(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	ensureBgANSI()

	bodyH := h
	if bodyH < 1 {
		bodyH = 1
	}

	// ── Split Pane: file list (60%) | preview (40%) ──────────────────────
	listWidth := w * 60 / 100
	if listWidth < 30 {
		listWidth = w // Full width on small terminals
	}
	sepW := 1
	previewWidth := w - listWidth - sepW
	if previewWidth < 10 {
		previewWidth = 0
		listWidth = w
		sepW = 0
	}

	// ── File List ────────────────────────────────────────────────────────
	entries := m.BrowserEntries
	cursor := m.BrowserCursor

	// Calculate widths for columns
	gitWidth := 3
	typeWidth := 10
	countWidth := 8
	sizeWidth := 10
	nameWidth := listWidth - gitWidth - typeWidth - countWidth - sizeWidth - 9 // 9 for spacing and selection
	if nameWidth < 10 {
		nameWidth = 10
	}

	// Headers
	headerStyle := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Bold(true)
	headerLine := "  " +
		headerStyle.Width(gitWidth).Render("ST") + " " +
		headerStyle.Width(nameWidth).Render("NAME") + " " +
		headerStyle.Width(typeWidth).Render("TYPE") + " " +
		headerStyle.Width(countWidth).Render("ITEMS") + " " +
		headerStyle.Width(sizeWidth).Render("SIZE")

	hw := lipgloss.Width(headerLine)
	if hw < listWidth {
		headerLine += lipgloss.NewStyle().Background(colorBG).Render(strings.Repeat(" ", listWidth-hw))
	} else if hw > listWidth {
		headerLine = ansi.Truncate(headerLine, listWidth, "")
	}

	// Calculate scroll window
	visibleRows := bodyH - 2 // -1 for header, -1 for header separator
	if visibleRows < 1 {
		visibleRows = 1
	}
	startRow := 0
	if cursor >= visibleRows {
		startRow = cursor - visibleRows + 1
	}
	endRow := startRow + visibleRows
	if endRow > len(entries) {
		endRow = len(entries)
		startRow = endRow - visibleRows
		if startRow < 0 {
			startRow = 0
		}
	}

	normalFG := colorText
	normalBG := colorBG
	selectedFG := colorBG
	selectedBG := colorPrimaryCont

	var listLines []string
	listLines = append(listLines, headerLine)

	headerSep := lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).
		Render(strings.Repeat("─", listWidth))
	listLines = append(listLines, headerSep)

	for ri := startRow; ri < endRow; ri++ {
		entry := entries[ri]
		isSelected := ri == cursor

		var fg lipgloss.Color
		var bg lipgloss.Color
		if isSelected {
			fg = selectedFG
			bg = selectedBG
		} else {
			fg = normalFG
			bg = normalBG
		}

		// Selection indicator (Left border block)
		selector := lipgloss.NewStyle().Background(bg).Render("  ")
		if isSelected {
			selector = lipgloss.NewStyle().Foreground(colorTertiaryCont).Background(bg).Bold(true).Render("▌ ")
		}

		// Name formatting
		name := entry.Name
		if entry.IsDir && entry.Name != ".." {
			name += "/"
		}
		if len(name) > nameWidth {
			name = name[:nameWidth-3] + "..."
		}

		// Git status
		gitStr := ""
		if entry.GitStatus != "" && entry.Name != ".." {
			gitFG := colorSecondary
			indicator := " "
			if strings.Contains(entry.GitStatus, "M") {
				gitFG = colorTertiaryCont
				indicator = "M"
			} else if strings.Contains(entry.GitStatus, "?") {
				gitFG = colorError
				indicator = "U"
			}
			if isSelected {
				gitFG = fg // override to keep readability on highlight
			}
			gitStr = lipgloss.NewStyle().Foreground(gitFG).Background(bg).
				Width(gitWidth).MaxWidth(gitWidth).Inline(true).
				Render(indicator)
		} else {
			gitStr = lipgloss.NewStyle().Background(bg).
				Width(gitWidth).MaxWidth(gitWidth).Inline(true).
				Render("")
		}

		// Project type badge
		typeStr := ""
		if entry.ProjectType != "" {
			typeFG := fg
			typeBg := bg
			if !isSelected {
				typeBg = colorSurfaceHigh
				switch entry.ProjectType {
				case "Go":
					typeFG = colorPrimaryDim
				case "Node.js":
					typeFG = colorTertiaryCont
				case "Python":
					typeFG = colorSecondary
				case "Rust":
					typeFG = colorError
				case "Docker":
					typeFG = colorPrimaryDim
				default:
					typeFG = colorTextVariant
				}
			}

			badgeText := " " + entry.ProjectType + " "
			// Try to fit badge
			if len(badgeText) > typeWidth {
				badgeText = entry.ProjectType
				if len(badgeText) > typeWidth {
					badgeText = badgeText[:typeWidth]
				}
			}

			typeStr = lipgloss.NewStyle().Foreground(typeFG).Background(typeBg).
				Width(typeWidth).MaxWidth(typeWidth).Align(lipgloss.Center).Inline(true).
				Render(badgeText)
		} else {
			typeStr = lipgloss.NewStyle().Foreground(colorGray).Background(bg).
				Width(typeWidth).MaxWidth(typeWidth).Inline(true).
				Render("—")
		}

		// File count (for dirs)
		countStr := ""
		if entry.IsDir && entry.Name != ".." {
			countStr = lipgloss.NewStyle().Foreground(fg).Background(bg).
				Width(countWidth).MaxWidth(countWidth).Inline(true).
				Render(fmt.Sprintf("%d", entry.Children))
		} else {
			countStr = lipgloss.NewStyle().Foreground(fg).Background(bg).
				Width(countWidth).MaxWidth(countWidth).Inline(true).
				Render("")
		}

		// Size
		sizeStr := ""
		if entry.Name != ".." && !entry.IsDir {
			sizeStr = lipgloss.NewStyle().Foreground(colorGray).Background(bg).
				Width(sizeWidth).MaxWidth(sizeWidth).Inline(true).
				Render(formatSize(entry.Size))
		} else {
			sizeStr = lipgloss.NewStyle().Background(bg).
				Width(sizeWidth).MaxWidth(sizeWidth).Inline(true).
				Render("")
		}

		// If selected, ensure gray stays readable or changes to selected fg
		if isSelected {
			if !entry.IsDir && entry.Name != ".." {
				sizeStr = lipgloss.NewStyle().Foreground(fg).Background(bg).
					Width(sizeWidth).MaxWidth(sizeWidth).Inline(true).
					Render(formatSize(entry.Size))
			} else {
				sizeStr = lipgloss.NewStyle().Foreground(fg).Background(bg).
					Width(sizeWidth).MaxWidth(sizeWidth).Inline(true).
					Render("")
			}
		}

		// Assemble the row
		nameStyle := lipgloss.NewStyle().Foreground(fg).Background(bg).
			Width(nameWidth).MaxWidth(nameWidth).Inline(true)

		if entry.IsDir && !isSelected && entry.Name != ".." {
			nameStyle = nameStyle.Foreground(colorPrimary).Bold(true)
		} else if !entry.IsDir && !isSelected {
			nameStyle = nameStyle.Foreground(colorTextVariant)
		}

		spacer := lipgloss.NewStyle().Background(bg).Render(" ")
		line := selector +
			gitStr + spacer +
			nameStyle.Render(name) + spacer +
			typeStr + spacer +
			countStr + spacer +
			sizeStr

		line = bgFillColor(line, listWidth, getBgANSI(bg), bg)
		listLines = append(listLines, line)
	}

	// Pad list to bodyH
	for len(listLines) < bodyH {
		listLines = append(listLines, bgFill("", listWidth))
	}

	// ── Preview Panel ────────────────────────────────────────────────────
	var previewLines []string
	if previewWidth > 0 {
		previewBG := colorSurface

		if m.RuleBuilderActive {
			// ── Rule Builder UI ──
			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			header := lipgloss.NewStyle().Foreground(colorPrimary).Background(previewBG).Bold(true).Padding(0, 2).Render("Rule Builder 🪄")
			previewLines = append(previewLines, header)

			sepStyle := lipgloss.NewStyle().Foreground(colorOutline).Background(previewBG).Padding(0, 2)
			previewLines = append(previewLines, sepStyle.Render(strings.Repeat("─", previewWidth-4)))

			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			targetStr := lipgloss.NewStyle().Foreground(colorGray).Background(previewBG).Padding(0, 2).Render("Target:") +
				lipgloss.NewStyle().Foreground(colorText).Background(previewBG).Bold(true).Render(filepath.Base(m.RuleBuilderTarget))
			previewLines = append(previewLines, targetStr)

			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			promptStr := lipgloss.NewStyle().Foreground(colorTextVariant).Background(previewBG).Padding(0, 2).Render("What should this rule detect?")
			previewLines = append(previewLines, promptStr)

			// Render text input
			inputStr := lipgloss.NewStyle().Background(previewBG).Padding(0, 2).Render(m.RuleBuilderInput.View())
			previewLines = append(previewLines, inputStr)

			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			hintStr := lipgloss.NewStyle().Foreground(colorGray).Background(previewBG).Padding(0, 2).Render("Press Enter to generate, Esc to cancel.")
			previewLines = append(previewLines, hintStr)
		} else if m.RuleGenerating {
			// ── Rule Generating UI ──
			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			header := lipgloss.NewStyle().Foreground(colorPrimary).Background(previewBG).Bold(true).Padding(0, 2).Render("Rule Builder 🪄")
			previewLines = append(previewLines, header)

			sepStyle := lipgloss.NewStyle().Foreground(colorOutline).Background(previewBG).Padding(0, 2)
			previewLines = append(previewLines, sepStyle.Render(strings.Repeat("─", previewWidth-4)))

			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			anim := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(previewBG).Bold(true).Padding(0, 2).Render("⠋ Analyzing source code and building rule...")
			previewLines = append(previewLines, anim)
		} else if cursor < len(entries) {
			entry := entries[cursor]

			// Top padding
			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			// Card Title
			titleText := entry.Name
			if entry.Name == ".." {
				titleText = "Parent Directory"
			} else if entry.IsDir {
				titleText += "/"
			}

			titleStyle := lipgloss.NewStyle().
				Foreground(colorPrimary).
				Background(previewBG).
				Bold(true).
				Padding(0, 2)

			previewLines = append(previewLines, titleStyle.Render(titleText))

			// Separator
			sepStyle := lipgloss.NewStyle().Foreground(colorOutline).Background(previewBG).Padding(0, 2)
			previewLines = append(previewLines, sepStyle.Render(strings.Repeat("─", previewWidth-4)))

			// Add blank line
			previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

			labelStyle := lipgloss.NewStyle().Foreground(colorGray).Background(previewBG).Width(12).Padding(0, 0, 0, 2)
			valueStyle := lipgloss.NewStyle().Foreground(colorText).Background(previewBG)

			if entry.Name == ".." {
				previewLines = append(previewLines,
					labelStyle.Render("Action:")+valueStyle.Render("Navigate up"))

				// Show scan instruction when no scan results yet
				if len(m.Report.Results) == 0 && !m.ScanInProgress {
					previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))
					previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

					instructionHeader := lipgloss.NewStyle().
						Foreground(colorPrimary).Background(previewBG).Bold(true).Padding(0, 2).
						Render("🔍 Getting Started")
					previewLines = append(previewLines, instructionHeader)

					previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

					steps := []string{
						"1. Navigate to a project directory",
						"2. Press [S] to start security scan",
						"3. Use tabs [1-9] to browse results",
					}
					for _, step := range steps {
						stepLine := lipgloss.NewStyle().Foreground(colorTextVariant).Background(previewBG).Padding(0, 2).Render(step)
						previewLines = append(previewLines, stepLine)
					}

					previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

					hint := lipgloss.NewStyle().Foreground(colorGray).Background(previewBG).Padding(0, 2).
						Render("Select any directory and press [S]")
					previewLines = append(previewLines, hint)
				}
			} else {
				// Type
				typeVal := entry.ProjectType
				if typeVal == "" {
					if entry.IsDir {
						typeVal = "Directory"
					} else {
						ext := filepath.Ext(entry.Name)
						if ext != "" {
							typeVal = strings.ToUpper(strings.TrimPrefix(ext, ".")) + " File"
						} else {
							typeVal = "File"
						}
					}
				}
				previewLines = append(previewLines, labelStyle.Render("Type:")+valueStyle.Render(typeVal))

				// Size/Items
				if entry.IsDir {
					previewLines = append(previewLines, labelStyle.Render("Items:")+valueStyle.Render(fmt.Sprintf("%d", entry.Children)))
				} else {
					previewLines = append(previewLines, labelStyle.Render("Size:")+valueStyle.Render(formatSize(entry.Size)))
				}

				// Modified
				modStr := "—"
				if !entry.ModTime.IsZero() {
					modStr = entry.ModTime.Format("Jan 02, 2006 at 15:04")
				}
				previewLines = append(previewLines, labelStyle.Render("Modified:")+valueStyle.Render(modStr))

				// Key Files
				if entry.IsDir {
					keyFiles := detectKeyFiles(entry.Path)
					if len(keyFiles) > 0 {
						previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

						header := lipgloss.NewStyle().Foreground(colorTextVariant).Background(previewBG).Bold(true).Padding(0, 2).Render("Key Files Detected")
						previewLines = append(previewLines, header)

						checkStyle := lipgloss.NewStyle().Foreground(colorSuccess).Background(previewBG).Padding(0, 0, 0, 2)
						fileStyle := lipgloss.NewStyle().Foreground(colorTextVariant).Background(previewBG)

						for _, kf := range keyFiles {
							if len(previewLines) >= bodyH-4 {
								break
							}
							previewLines = append(previewLines, checkStyle.Render("* ")+fileStyle.Render(kf))
						}
					}

					// Directory Contents (Recursive Tree)
					var walkLines []string
					totalItems := 0
					_ = filepath.WalkDir(entry.Path, func(p string, d os.DirEntry, err error) error {
						if err != nil || p == entry.Path {
							return nil
						}
						// Skip hidden files and directories
						if strings.HasPrefix(d.Name(), ".") {
							if d.IsDir() {
								return filepath.SkipDir
							}
							return nil
						}
						totalItems++

						// Render up to bodyH-6 lines
						if len(walkLines) < bodyH-6 {
							rel, _ := filepath.Rel(entry.Path, p)
							depth := strings.Count(rel, string(filepath.Separator))
							indent := strings.Repeat("  ", depth)

							if d.IsDir() {
								dirStyle := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(previewBG).Padding(0, 0, 0, 2)
								walkLines = append(walkLines, dirStyle.Render(indent+"▾ "+d.Name()+"/"))
							} else {
								fileStyle := lipgloss.NewStyle().Foreground(colorGray).Background(previewBG).Padding(0, 0, 0, 2)
								walkLines = append(walkLines, fileStyle.Render(indent+"- "+d.Name()))
							}
						}
						return nil
					})

					if totalItems > 0 {
						previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))
						header := lipgloss.NewStyle().Foreground(colorTextVariant).Background(previewBG).Bold(true).Padding(0, 2).Render("Directory Contents")
						previewLines = append(previewLines, header)

						previewLines = append(previewLines, walkLines...)

						if totalItems > len(walkLines) {
							previewLines = append(previewLines,
								lipgloss.NewStyle().Foreground(colorGray).Background(previewBG).Padding(0, 0, 0, 4).
									Render(fmt.Sprintf("... +%d more", totalItems-len(walkLines))))
						}
					}

					// Scan action hint at the bottom
					for len(previewLines) < bodyH-2 {
						previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))
					}

					scanBtn := lipgloss.NewStyle().
						Foreground(colorBG).
						Background(colorPrimaryDim).
						Bold(true).
						Padding(0, 2).
						Render(" [S] SCAN PROJECT ")

					scanLine := lipgloss.NewStyle().Background(previewBG).Padding(0, 2).Render(scanBtn)
					previewLines = append(previewLines, scanLine)
				} else {
					// File Preview
					contentBytes, err := os.ReadFile(entry.Path)
					if err == nil {
						previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))

						header := lipgloss.NewStyle().Foreground(colorTextVariant).Background(previewBG).Bold(true).Padding(0, 2).Render("File Preview")
						previewLines = append(previewLines, header)

						contentStr := string(contentBytes)
						if len(contentStr) > 16384 {
							contentStr = contentStr[:16384] + "\n... (truncated)"
						}

						lines := strings.Split(contentStr, "\n")
						if len(lines) > 200 {
							lines = append(lines[:200], "... (truncated)")
							contentStr = strings.Join(lines, "\n")
						}

						highlighted := highlightCode(entry.Name, contentStr)
						hlLines := strings.Split(highlighted, "\n")

						availHeight := bodyH - len(previewLines) - 2 // reserve for bottom hint

						hlStyle := lipgloss.NewStyle().Background(previewBG).Padding(0, 0, 0, 2)
						for i, line := range hlLines {
							if i >= availHeight {
								break
							}
							previewLines = append(previewLines, hlStyle.Render(line))
						}
					}

					// Editor action hint
					for len(previewLines) < bodyH-2 {
						previewLines = append(previewLines, lipgloss.NewStyle().Background(previewBG).Width(previewWidth).Render(""))
					}

					editBtn := lipgloss.NewStyle().
						Foreground(colorBG).
						Background(colorPrimaryDim).
						Bold(true).
						Padding(0, 2).
						Render(" [E] EDIT FILE ")

					editLine := lipgloss.NewStyle().Background(previewBG).Padding(0, 2).Render(editBtn)
					previewLines = append(previewLines, editLine)
				}
			}
		}

		// Pad preview to bodyH
		for len(previewLines) < bodyH {
			previewLines = append(previewLines,
				lipgloss.NewStyle().Background(previewBG).
					Width(previewWidth).MaxWidth(previewWidth).
					Render(""))
		}
		if len(previewLines) > bodyH {
			previewLines = previewLines[:bodyH]
		}

		// Ensure all lines are strictly previewWidth wide
		for i, line := range previewLines {
			pw := lipgloss.Width(line)
			if pw < previewWidth {
				previewLines[i] = line + lipgloss.NewStyle().Background(previewBG).Render(strings.Repeat(" ", previewWidth-pw))
			} else if pw > previewWidth {
				previewLines[i] = ansi.Truncate(line, previewWidth, "")
			}
		}
	}

	// ── Assemble Rows ────────────────────────────────────────────────────
	colSep := ""
	if sepW > 0 {
		colSep = bgCell("│", sepW, colorOutline)
	}

	var bodyRows []string
	for i := 0; i < bodyH; i++ {
		row := listLines[i]
		if previewWidth > 0 && i < len(previewLines) {
			row += colSep + previewLines[i]
		}
		bodyRows = append(bodyRows, row)
	}

	// ── Assembly ─────────────────────────────────────────────────────────
	var rows []string
	rows = append(rows, bodyRows...)

	// Pad to exact height
	for len(rows) < h {
		rows = append(rows, bgFill("", w))
	}
	if len(rows) > h {
		rows = rows[:h]
	}

	return strings.Join(rows, "\n")
}

func (m DashboardModel) renderHeader(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}

	bg := lipgloss.NewStyle().Background(colorBG)

	// LINE 1: Logo, Context, Health
	logoText := " AITRIAGE "
	logo := lipgloss.NewStyle().Foreground(colorBG).Background(colorPrimaryDim).Bold(true).Render(logoText)

	projStr := m.Report.ProjectPath
	if projStr == "" {
		projStr = m.BrowserDir
	}
	if len(projStr) > 40 && w > 60 {
		projStr = "..." + projStr[len(projStr)-37:]
	} else if len(projStr) > 20 {
		projStr = "..." + projStr[len(projStr)-17:]
	}
	if projStr == "" {
		projStr = "Select Project"
	}
	project := lipgloss.NewStyle().Foreground(colorText).Background(colorSurfaceHighest).Render(" " + projStr + " ")

	healthStr := "NOMINAL"
	healthColor := colorPrimaryDim
	healthIcon := "■"
	if m.Report.HasCriticalFailures {
		healthStr = "DEGRADED"
		healthColor = colorError
		healthIcon = "▲"
	}
	if m.ScanInProgress {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		healthIcon = frames[m.TickCount%len(frames)]
		healthStr = "SCANNING"
		healthColor = colorPrimaryDim
	}
	healthVal := healthIcon + " " + healthStr
	healthChip := formatChip("SYS", healthVal, colorGray, healthColor)

	uptime := time.Since(m.ScanStartTime).Round(time.Second)
	uptimeChip := formatChip("UPTIME", uptime.String(), colorGray, colorPrimaryDim)

	tokensStr := fmt.Sprintf("%d", m.TokensUsed)
	if m.TokensUsed > 1000 {
		tokensStr = fmt.Sprintf("%.1fK", float64(m.TokensUsed)/1000.0)
	}
	tokensChip := formatChip("TOKENS", tokensStr, colorGray, colorPrimaryDim)
	durationChip := formatChip("TIME", fmt.Sprintf("%dms", m.Report.ScanDuration.Milliseconds()), colorGray, colorText)
	filesChip := formatChip("FILES", fmt.Sprintf("%d", m.Report.TotalFiles), colorGray, colorText)

	// Active engines summary
	enginesActive := "SAST"
	if len(m.DeployFindings) > 0 || len(m.NetworkFindings) > 0 {
		enginesActive += " | INFRA"
	}
	enginesChip := formatChip("ENGINES", enginesActive, colorGray, colorSecondary)

	line1Content := logo + bg.Render("  ") + project + bg.Render("  ") + healthChip + bg.Render("  ") + enginesChip
	line1Right := uptimeChip + bg.Render("    ") + tokensChip + bg.Render("    ") + durationChip + bg.Render("    ") + filesChip + bg.Render(" ")

	gap1 := w - lipgloss.Width(line1Content) - lipgloss.Width(line1Right)
	if gap1 < 0 {
		gap1 = 0
	}
	line1 := line1Content + bg.Render(strings.Repeat(" ", gap1)) + line1Right

	// LINE 2: Tabs + Stats
	// TAB MAPPING: [0]BROWSER, [1]DASH, [2]VULN, [3]SAST, [4]AUDIT, [5]REPT, [6]CHAT, [7]DEPS, [8]GRAPH, [9]INFRA
	tabs := []struct {
		key   int
		label string
	}{
		{0, "BROWSER"},
		{1, "DASH"},
		{2, "VULN"},
		{3, "SAST"},
		{4, "AUDIT"},
		{5, "REPT"},
		{6, "CHAT"},
		{7, "DEPS"},
		{8, "TOPO"},
		{9, "INFRA"},
	}
	var tabStrings []string
	for _, t := range tabs {
		// ViewBrowser is -1, so map key 0 → ViewBrowser, others → key-1
		var isActive bool
		if t.key == 0 {
			isActive = m.ActiveView == ViewBrowser
		} else {
			isActive = int(m.ActiveView) == t.key-1
		}
		if isActive {
			tabStrings = append(tabStrings, activeTabStyle.Render(fmt.Sprintf(" [%d] %s ", t.key, t.label)))
		} else {
			tabStrings = append(tabStrings, inactiveTabStyle.Render(fmt.Sprintf(" [%d] %s ", t.key, t.label)))
		}
	}

	if m.ActiveView == ViewLogs {
		tabStrings = append(tabStrings, activeTabStyle.Render(" [L] LOGS "))
	} else {
		tabStrings = append(tabStrings, inactiveTabStyle.Render(" [L] LOGS "))
	}

	if m.ActiveView == ViewConfig {
		tabStrings = append(tabStrings, activeTabStyle.Render(" [C] CONF "))
	} else {
		tabStrings = append(tabStrings, inactiveTabStyle.Render(" [C] CONF "))
	}

	nav := lipgloss.JoinHorizontal(lipgloss.Top, tabStrings...)

	critCount := 0
	for _, res := range m.Report.Results {
		if res.Severity == "CRITICAL" {
			critCount++
		}
	}
	extCount := len(m.ExternalFindings) + len(m.NFRFindings) + len(m.DeployFindings) + len(m.NetworkFindings)

	scoreColor := colorPrimary
	gradeVal := m.Report.SecurityGrade
	scoreVal := fmt.Sprintf("%d", m.Report.SecurityScore)

	if m.Report.SecurityScore == 0 && m.Report.SecurityGrade == "" {
		scoreColor = colorGray
		gradeVal = "-"
		scoreVal = "-"
	} else if m.Report.SecurityScore < 70 {
		scoreColor = colorError
	} else if m.Report.SecurityScore < 90 {
		scoreColor = colorTertiaryCont
	}

	gradeChip := formatChip("GRADE", gradeVal, colorGray, scoreColor)
	scoreChip := formatChip("SCORE", scoreVal, colorGray, scoreColor)
	critChip := formatChip("CRIT", fmt.Sprintf("%d", critCount), colorGray, colorError)
	extChip := formatChip("EXT", fmt.Sprintf("%d", extCount), colorGray, colorText)

	stats := gradeChip + bg.Render("    ") + scoreChip + bg.Render("    ") + extChip + bg.Render("    ") + critChip + bg.Render(" ")

	statsW := lipgloss.Width(stats)
	navW := lipgloss.Width(nav)
	// If nav + stats exceed width, truncate nav to leave room for stats
	if navW+statsW > w {
		maxNav := w - statsW - 1
		if maxNav > 0 {
			nav = ansi.Truncate(nav, maxNav, "")
			navW = lipgloss.Width(nav)
		}
	}

	gap2 := w - navW - statsW
	if gap2 < 0 {
		gap2 = 0
	}
	line2 := nav + bg.Render(strings.Repeat(" ", gap2)) + stats

	// STRICT ASSEMBLY: Ensure every line is exactly w wide
	l1 := bgFill(line1, w)
	l1_5 := bgFill(bg.Render(strings.Repeat(" ", w)), w) // Gap between logo and tabs
	l2 := bgFill(line2, w)

	// Returning 3 lines to match headerHeight = 3
	return strings.Join([]string{l1, l1_5, l2}, "\n")
}

func (m DashboardModel) renderDashboard(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}

	crit, high, med, low := 0, 0, 0, 0
	for _, res := range m.Report.Results {
		switch res.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		case "LOW":
			low++
		}
	}
	total := len(m.Report.Results)

	// ── CHIP ROW ──────────────────────────────────────────────────────────────
	chipHeight := 4
	chipWidth := (w - 5) / 6
	if chipWidth < 1 {
		chipWidth = 1
	}

	subStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG)
	chipStyle := lipgloss.NewStyle().Background(colorBG).Foreground(colorText).
		Width(chipWidth).MaxWidth(chipWidth).
		Height(chipHeight).MaxHeight(chipHeight)

	// Chip 1: SECURITY SCORE
	scoreValColor := colorPrimaryDim
	if m.Report.SecurityScore < 70 {
		scoreValColor = colorTertiaryCont
	}
	if m.Report.SecurityScore < 50 {
		scoreValColor = colorError
	}
	scoreVal := lipgloss.NewStyle().Foreground(scoreValColor).Background(colorBG).Bold(true).
		Render(fmt.Sprintf("%d/100", m.Report.SecurityScore))
	scoreChip := chipStyle.Render(labelStyle.Render("SCORE") + "\n" + scoreVal + "\n" + subStyle.Render("Grade: "+m.Report.SecurityGrade))

	// Chip 2: CRITICAL THREATS
	critHighTotal := crit + high
	critHighColor := colorPrimaryDim
	if critHighTotal > 0 {
		critHighColor = colorError
	}
	critHighVal := lipgloss.NewStyle().Foreground(critHighColor).Background(colorBG).Bold(true).
		Render(fmt.Sprintf("⚠ %d", critHighTotal))
	subCrit := subStyle.Render(fmt.Sprintf("%d Critical, %d High", crit, high))
	critHighChip := chipStyle.Render(labelStyle.Render("CRIT/HIGH") + "\n" + critHighVal + "\n" + subCrit)

	// Chip 3: SAST & NFR
	sastTotal := len(m.ExternalFindings) + len(m.NFRFindings)
	sastColor := colorPrimaryDim
	if sastTotal > 0 {
		sastColor = colorTertiaryCont
	}
	sastVal := lipgloss.NewStyle().Foreground(sastColor).Background(colorBG).Bold(true).
		Render(fmt.Sprintf("%d", sastTotal))
	subSast := subStyle.Render(fmt.Sprintf("%d SAST, %d NFR", len(m.ExternalFindings), len(m.NFRFindings)))
	sastChip := chipStyle.Render(labelStyle.Render("CODE/SAST") + "\n" + sastVal + "\n" + subSast)

	// Chip 4: INFRASTRUCTURE
	infraTotal := len(m.DeployFindings) + len(m.NetworkFindings)
	infraColor := colorPrimaryDim
	if infraTotal > 0 {
		infraColor = colorSecondary
	}
	infraVal := lipgloss.NewStyle().Foreground(infraColor).Background(colorBG).Bold(true).
		Render(fmt.Sprintf("%d", infraTotal))
	subInfra := subStyle.Render(fmt.Sprintf("%d IaC, %d Net", len(m.DeployFindings), len(m.NetworkFindings)))
	infraChip := chipStyle.Render(labelStyle.Render("INFRA/NET") + "\n" + infraVal + "\n" + subInfra)

	// Chip 5: AI TOKENS
	tokensStr := fmt.Sprintf("%d", m.TokensUsed)
	if m.TokensUsed > 1000 {
		tokensStr = fmt.Sprintf("%.1fK", float64(m.TokensUsed)/1000.0)
	}
	tokensVal := lipgloss.NewStyle().Foreground(colorAccent).Background(colorBG).Bold(true).
		Render(tokensStr)
	subTokens := subStyle.Render("Tokens Consumed")
	tokensChip := chipStyle.Render(labelStyle.Render("AI USAGE") + "\n" + tokensVal + "\n" + subTokens)

	// Chip 6: TELEMETRY
	telStore := telemetry.Summary()
	trend := telemetry.ScoreTrend(telStore)
	trendStr := fmt.Sprintf("%d", trend)
	trendColor := colorGray
	if trend > 0 {
		trendStr = fmt.Sprintf("↑+%d", trend)
		trendColor = colorPrimaryDim
	} else if trend < 0 {
		trendColor = colorError
	} else {
		trendStr = "—"
	}

	telVal := lipgloss.NewStyle().Foreground(colorSecondary).Background(colorBG).Bold(true).
		Render(fmt.Sprintf("%d SCANS", telStore.TotalScans))
	subTel := lipgloss.NewStyle().Foreground(trendColor).Background(colorBG).Render(fmt.Sprintf("Trend: %s", trendStr))
	if !telemetry.IsEnabled() {
		telVal = lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Bold(true).Render("DISABLED")
		subTel = subStyle.Render("Opted out")
	}
	telChip := chipStyle.Render(labelStyle.Render("TELEMETRY") + "\n" + telVal + "\n" + subTel)

	chip1Lines := strings.Split(scoreChip, "\n")
	chip2Lines := strings.Split(critHighChip, "\n")
	chip3Lines := strings.Split(sastChip, "\n")
	chip4Lines := strings.Split(infraChip, "\n")
	chip5Lines := strings.Split(tokensChip, "\n")
	chip6Lines := strings.Split(telChip, "\n")

	for len(chip1Lines) < chipHeight {
		chip1Lines = append(chip1Lines, "")
	}
	for len(chip2Lines) < chipHeight {
		chip2Lines = append(chip2Lines, "")
	}
	for len(chip3Lines) < chipHeight {
		chip3Lines = append(chip3Lines, "")
	}
	for len(chip4Lines) < chipHeight {
		chip4Lines = append(chip4Lines, "")
	}
	for len(chip5Lines) < chipHeight {
		chip5Lines = append(chip5Lines, "")
	}
	for len(chip6Lines) < chipHeight {
		chip6Lines = append(chip6Lines, "")
	}

	chipSepStr := bgCell("│", 1, colorOutline)
	tailW := w - chipWidth*6 - 5
	if tailW < 0 {
		tailW = 0
	}

	var chipRows []string
	for i := 0; i < chipHeight; i++ {
		c1 := bgFill(chip1Lines[i], chipWidth)
		c2 := bgFill(chip2Lines[i], chipWidth)
		c3 := bgFill(chip3Lines[i], chipWidth)
		c4 := bgFill(chip4Lines[i], chipWidth)
		c5 := bgFill(chip5Lines[i], chipWidth)
		c6 := bgFill(chip6Lines[i], chipWidth)
		tail := bgFill("", tailW)
		chipRows = append(chipRows, c1+chipSepStr+c2+chipSepStr+c3+chipSepStr+c4+chipSepStr+c5+chipSepStr+c6+tail)
	}
	chips := strings.Join(chipRows, "\n")
	chipSepLine := bgCell(strings.Repeat("─", w), w, colorOutline)

	// ── BODY: 3-COLUMN LAYOUT ────────────────────────────────────────────
	panelHeight := h - chipHeight - 1
	if panelHeight < 1 {
		panelHeight = 1
	}

	sepW := 1
	leftColWidth := w * 25 / 100
	if leftColWidth < 28 {
		leftColWidth = 28
	}
	centerColWidth := w * 35 / 100
	if centerColWidth < 28 {
		centerColWidth = 28
	}
	rightColWidth := w - leftColWidth - centerColWidth - sepW*2
	if rightColWidth < 16 {
		rightColWidth = 16
	}

	valSt := lipgloss.NewStyle().Foreground(colorText).Background(colorBG)
	bullet := lipgloss.NewStyle().Foreground(colorOutline).Render("•")

	// ── LEFT: Health + Severity + Attack Surface ──
	var leftContent strings.Builder
	scoreColor := colorPrimary
	healthStatus := " NOMINAL "
	statusStyle := lipgloss.NewStyle().Background(colorSurfaceHigh).Foreground(colorPrimaryDim)
	heartbeat := lipgloss.NewStyle().Foreground(colorPrimaryDim).Render("●")
	if m.Report.SecurityScore < 70 {
		scoreColor = colorTertiaryCont
	}
	if m.Report.SecurityScore < 50 {
		scoreColor = colorError
	}
	if m.Report.HasCriticalFailures {
		healthStatus = " DEGRADED "
		statusStyle = lipgloss.NewStyle().Background(colorError).Foreground(colorBG).Bold(true)
		heartbeat = lipgloss.NewStyle().Foreground(colorError).Render("●")
	} else if crit+high > 0 {
		healthStatus = " AT RISK "
		statusStyle = lipgloss.NewStyle().Background(colorTertiaryCont).Foreground(colorBG).Bold(true)
		heartbeat = lipgloss.NewStyle().Foreground(colorTertiaryCont).Render("●")
	}

	leftContent.WriteString(labelStyle.Render("[ SYS.HEALTH ]") + "\n")
	bigScore := lipgloss.NewStyle().Foreground(scoreColor).Background(colorBG).Bold(true).Render(fmt.Sprintf("%d", m.Report.SecurityScore))
	gradeBox := lipgloss.NewStyle().Foreground(colorBG).Background(scoreColor).Bold(true).Padding(0, 1).Render(m.Report.SecurityGrade)
	leftContent.WriteString(heartbeat + " " + bigScore + lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render("/100") + " " + gradeBox + " " + statusStyle.Render(healthStatus) + "\n\n")

	leftContent.WriteString(labelStyle.Render(fmt.Sprintf("[ SEVERITY ] %d TOTAL", total)) + "\n")
	leftContent.WriteString(m.renderSevBar("CRIT", crit, total, colorError, leftColWidth) + "\n")
	leftContent.WriteString(m.renderSevBar("HIGH", high, total, colorTertiaryCont, leftColWidth) + "\n")
	leftContent.WriteString(m.renderSevBar("MED ", med, total, colorSecondary, leftColWidth) + "\n")
	leftContent.WriteString(m.renderSevBar("LOW ", low, total, colorGray, leftColWidth) + "\n\n")

	leftContent.WriteString(labelStyle.Render("[ ATTACK.SURFACE ]") + "\n")
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Files", valSt.Render(fmt.Sprintf("%d", m.Report.TotalFiles)))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Dependencies", valSt.Render(fmt.Sprintf("%d", len(m.Report.Dependencies))))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "IaC Resources", valSt.Render(fmt.Sprintf("%d", len(m.DeployFindings))))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Network", valSt.Render(fmt.Sprintf("%d", len(m.NetworkFindings))))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Vulns", valSt.Render(fmt.Sprintf("%d", total)))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Rules", valSt.Render(fmt.Sprintf("%d", m.Report.RulesApplied)))
	leftContent.WriteString("\n" + labelStyle.Render("[ INFRA.SUMMARY ]") + "\n")
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Deploy Audit", valSt.Render(fmt.Sprintf("%d", len(m.DeployFindings))))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "NFR Checks", valSt.Render(fmt.Sprintf("%d", len(m.NFRFindings))))
	fmt.Fprintf(&leftContent, "%s %-14s %s\n", bullet, "Net Surface", valSt.Render(fmt.Sprintf("%d", len(m.NetworkFindings))))

	leftPanel := lipgloss.NewStyle().Background(colorBG).Width(leftColWidth).MaxWidth(leftColWidth).Height(panelHeight).MaxHeight(panelHeight).Render(leftContent.String())

	// ── CENTER: Scan Meta + Tech Stack + Findings Heatmap + Top Files ──
	var centerContent strings.Builder
	centerContent.WriteString(labelStyle.Render("[ SCAN.META ]") + "\n")
	scanDur := m.Report.ScanDuration.String()
	if m.Report.ScanDuration > time.Second {
		scanDur = fmt.Sprintf("%.1fs", m.Report.ScanDuration.Seconds())
	} else if m.Report.ScanDuration > time.Millisecond {
		scanDur = fmt.Sprintf("%dms", m.Report.ScanDuration.Milliseconds())
	}
	pPath := m.Report.ProjectPath
	maxPP := centerColWidth - 14
	if maxPP < 8 {
		maxPP = 8
	}
	if len(pPath) > maxPP {
		pPath = "..." + pPath[len(pPath)-maxPP+3:]
	}
	fmt.Fprintf(&centerContent, "%s %-10s %s\n", bullet, "Project", valSt.Render(pPath))
	fmt.Fprintf(&centerContent, "%s %-10s %s\n", bullet, "Duration", valSt.Render(scanDur))
	fmt.Fprintf(&centerContent, "%s %-10s %s\n", bullet, "Time", valSt.Render(m.ScanStartTime.Format("15:04:05")))

	centerContent.WriteString("\n" + labelStyle.Render("[ TECH.STACK ]") + "\n")
	if len(m.Report.Stacks) > 0 {
		for _, st := range m.Report.Stacks {
			s := string(st)
			icon := "◆"
			switch s {
			case "go":
				icon = "▸"
			case "node":
				icon = "◇"
			case "java":
				icon = "◈"
			}
			centerContent.WriteString(lipgloss.NewStyle().Foreground(colorAccent).Background(colorBG).Render("  "+icon+" ") + valSt.Render(s) + "\n")
		}
	} else {
		centerContent.WriteString(subStyle.Render("  No stacks detected") + "\n")
	}

	mapTitle := "[ FINDINGS.MAP ]"
	if m.DashFocusPanel == 1 {
		mapTitle = lipgloss.NewStyle().Foreground(colorBG).Background(colorSecondary).Bold(true).Render(mapTitle)
	} else {
		mapTitle = labelStyle.Render(mapTitle)
	}
	centerContent.WriteString("\n" + mapTitle + "\n")

	for i := 0; i < len(m.DashCats) && i < 6; i++ {
		c := m.DashCats[i]
		sc := colorGray
		switch c.Severity {
		case "CRITICAL":
			sc = colorError
		case "HIGH":
			sc = colorTertiaryCont
		case "MEDIUM":
			sc = colorSecondary
		}

		prefix := "  "
		if m.DashFocusPanel == 1 && m.DashMapCursor == i {
			prefix = lipgloss.NewStyle().Foreground(colorSecondary).Render("▸ ")
		}

		bW := centerColWidth - 16
		if bW < 4 {
			bW = 4
		}
		fl := 0
		if total > 0 {
			fl = c.Count * bW / total
		}
		if fl < 1 && c.Count > 0 {
			fl = 1
		}
		bar := lipgloss.NewStyle().Foreground(sc).Background(colorBG).Render(strings.Repeat("█", fl)) + lipgloss.NewStyle().Foreground(colorSurfaceHigh).Background(colorBG).Render(strings.Repeat("░", bW-fl))

		line := lipgloss.NewStyle().Foreground(sc).Background(colorBG).Width(6).Render(c.Name) + fmt.Sprintf(" %2d ", c.Count) + bar
		if m.DashFocusPanel == 1 && m.DashMapCursor == i {
			line = lipgloss.NewStyle().Background(colorSurface).Render(line)
		}
		centerContent.WriteString(prefix + line + "\n")
	}

	filesTitle := "[ TOP.FILES ]"
	if m.DashFocusPanel == 2 {
		filesTitle = lipgloss.NewStyle().Foreground(colorBG).Background(colorTertiaryCont).Bold(true).Render(filesTitle)
	} else {
		filesTitle = labelStyle.Render(filesTitle)
	}
	centerContent.WriteString("\n" + filesTitle + "\n")

	for i := 0; i < len(m.DashFiles) && i < 5; i++ {
		fn := m.DashFiles[i].Path
		ml := centerColWidth - 8
		if len(fn) > ml {
			fn = "..." + fn[len(fn)-ml+3:]
		}
		cc := colorGray
		if m.DashFiles[i].Count >= 5 {
			cc = colorError
		} else if m.DashFiles[i].Count >= 3 {
			cc = colorTertiaryCont
		}

		prefix := "  "
		if m.DashFocusPanel == 2 && m.DashFileCursor == i {
			prefix = lipgloss.NewStyle().Foreground(colorTertiaryCont).Render("▸ ")
		}

		countStr := lipgloss.NewStyle().Foreground(cc).Background(colorBG).Bold(true).Render(fmt.Sprintf("%2d", m.DashFiles[i].Count))
		fileStr := valSt.Render(fn)

		line := countStr + " " + fileStr
		if m.DashFocusPanel == 2 && m.DashFileCursor == i {
			line = lipgloss.NewStyle().Background(colorSurface).Render(line)
		}
		centerContent.WriteString(prefix + line + "\n")
	}

	centerPanel := lipgloss.NewStyle().Background(colorBG).Width(centerColWidth).MaxWidth(centerColWidth).Height(panelHeight).MaxHeight(panelHeight).Render(centerContent.String())

	// ── RIGHT: Top Threats + OWASP + AI Summary + Commands ──
	var rightContent strings.Builder
	rightContent.WriteString(lipgloss.NewStyle().Foreground(colorPrimaryCont).Background(colorBG).Bold(true).Render("[ TOP_THREATS ]") + "\n")
	tc := 0
	for _, r := range m.Report.Results {
		if tc >= 5 {
			break
		}
		if r.Severity == "CRITICAL" || r.Severity == "HIGH" {
			sc := lipgloss.NewStyle().Foreground(colorTertiaryCont).Background(colorBG).Bold(true)
			if r.Severity == "CRITICAL" {
				sc = lipgloss.NewStyle().Foreground(colorError).Background(colorBG).Bold(true)
			}
			nm := r.Name
			if len(nm) > rightColWidth-10 {
				nm = nm[:rightColWidth-13] + "..."
			}
			rightContent.WriteString(sc.Render(fmt.Sprintf("%-8s", r.Severity)) + " " + valSt.Render(nm) + "\n")
			tc++
		}
	}
	if tc == 0 {
		rightContent.WriteString(lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Render("✓ No critical threats") + "\n")
	}

	// OWASP hits
	if len(m.DashOWASP) > 0 {
		rightContent.WriteString("\n" + lipgloss.NewStyle().Foreground(colorSecondary).Background(colorBG).Bold(true).Render("[ OWASP.MAP ]") + "\n")
		for i := 0; i < len(m.DashOWASP) && i < 4; i++ {
			o := m.DashOWASP[i]
			lb := o.Name
			if len(lb) > rightColWidth-6 {
				lb = lb[:rightColWidth-9] + "..."
			}
			rightContent.WriteString("  " + valSt.Render(fmt.Sprintf("%-3d", o.Count)) + subStyle.Render(lb) + "\n")
		}
	}

	rightContent.WriteString("\n" + lipgloss.NewStyle().Foreground(colorAccent).Background(colorBG).Bold(true).Render("[ AI_SUMMARY ]") + "\n")
	sumText := m.DashboardSummary
	if sumText == "" && m.Report.AISummary != "" {
		sumText = m.Report.AISummary
	}
	if sumText != "" {
		rendered := renderMarkdownToTerminal(sumText, rightColWidth)
		rLines := strings.Split(rendered, "\n")
		remH := panelHeight - tc - 14
		if remH < 3 {
			remH = 3
		}
		for i, line := range rLines {
			if i >= remH {
				rightContent.WriteString(subStyle.Render("... [5] for full report") + "\n")
				break
			}
			rightContent.WriteString(bgFill(line, rightColWidth) + "\n")
		}
	} else if m.LLMClient != nil {
		rightContent.WriteString(subStyle.Render("Press [1] for AI assessment") + "\n")
	} else {
		rightContent.WriteString(subStyle.Render("Set GEMINI_API_KEY for AI") + "\n")
	}

	rightContent.WriteString("\n" + lipgloss.NewStyle().Foreground(colorTertiaryCont).Background(colorBG).Bold(true).Render("[ COMMANDS ]") + "\n")
	kh := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Bold(true)
	hs := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG)
	rightContent.WriteString(kh.Render(" TAB ") + hs.Render("NAV ") + kh.Render(" ENT ") + hs.Render("DRILL ") + kh.Render(" 6 ") + hs.Render("CHAT") + "\n")
	rightContent.WriteString(kh.Render(" 2 ") + hs.Render("VULN ") + kh.Render(" 3 ") + hs.Render("SAST  ") + kh.Render(" S ") + hs.Render("SCAN") + "\n")

	rightPanel := lipgloss.NewStyle().Background(colorBG).Width(rightColWidth).MaxWidth(rightColWidth).Height(panelHeight).MaxHeight(panelHeight).Render(rightContent.String())

	// ── Assemble 3 columns ──
	leftLines := strings.Split(leftPanel, "\n")
	centerLines := strings.Split(centerPanel, "\n")
	rightLines := strings.Split(rightPanel, "\n")
	colSep := bgCell("│", sepW, colorOutline)
	var bodyRows []string
	for i := 0; i < panelHeight; i++ {
		var lS, cS, rS string
		if i < len(leftLines) {
			lS = leftLines[i]
		}
		if i < len(centerLines) {
			cS = centerLines[i]
		}
		if i < len(rightLines) {
			rS = rightLines[i]
		}
		bodyRows = append(bodyRows, bgFill(lS, leftColWidth)+colSep+bgFill(cS, centerColWidth)+colSep+bgFill(rS, rightColWidth))
	}
	body := strings.Join(bodyRows, "\n")

	return chips + "\n" + chipSepLine + "\n" + body
}

func (m DashboardModel) renderSevBar(label string, count int, total int, c lipgloss.Color, maxW int) string {
	barWidth := 24
	if barWidth > maxW-18 {
		barWidth = maxW - 18
	}
	if barWidth < 1 {
		barWidth = 1
	}

	filled, percent := 0, 0
	if total > 0 {
		filled = int(float64(barWidth) * float64(count) / float64(total))
		percent = int(float64(count) * 100 / float64(total))
	}

	// Double bar for luxury look
	fullBlock := "█"
	emptyBlock := "░"
	bar := lipgloss.NewStyle().Foreground(c).Background(colorBG).Render(strings.Repeat(fullBlock, filled))
	empty := lipgloss.NewStyle().Foreground(colorSurfaceHigh).Background(colorBG).Render(strings.Repeat(emptyBlock, barWidth-filled))

	labelStr := lipgloss.NewStyle().Foreground(c).Background(colorBG).Width(8).Render(label)
	countStr := lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Render(fmt.Sprintf("%3d", count))
	pctStr := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(fmt.Sprintf("%3d%%", percent))

	return fmt.Sprintf("%s %s %s [%s%s]", labelStr, countStr, pctStr, bar, empty)
}

func (m DashboardModel) renderTriage(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	ensureBgANSI()
	tableWidth := (w * 6) / 10
	if tableWidth < 1 {
		tableWidth = 1
	}

	// Dynamic column widths: fit to tableWidth.
	// Each column has Padding(0,1,0,0) = +1 char per cell.
	// 5 columns = 5 padding chars total. Distribute remaining proportionally.
	usable := tableWidth - 5 // 5 columns × 1 padding
	if usable < 20 {
		usable = 20
	}
	colID := usable * 15 / 100
	colSev := usable * 8 / 100
	colIssue := usable * 35 / 100
	colPath := usable * 32 / 100
	colStat := usable - colID - colSev - colIssue - colPath // remainder
	if colID < 5 {
		colID = 5
	}
	if colSev < 4 {
		colSev = 4
	}
	if colStat < 6 {
		colStat = 6
	}

	// === MANUAL TABLE RENDER ===
	// We bypass m.Table.View() entirely because bubbles/table's Selected style
	// cannot override the per-Cell background (inner escapes take priority).
	// Instead we render rows ourselves using Rows()/Cursor().

	cols := []table.Column{
		{Title: "ID", Width: colID},
		{Title: "SEV", Width: colSev},
		{Title: "ISSUE", Width: colIssue},
		{Title: "PATH", Width: colPath},
		{Title: "STATUS", Width: colStat},
	}
	m.Table.SetColumns(cols)
	// Still set styles so keyboard navigation (cursor) works via bubbles/table internally
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorOutline).
		BorderBottom(true).
		Foreground(colorGray).
		Background(colorBG).
		Bold(false).
		Padding(0, 1, 0, 0)
	s.Selected = s.Selected.
		Foreground(colorOnPrimary).
		Background(colorPrimaryCont).
		Bold(true)
	s.Cell = lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Padding(0, 1, 0, 0)
	m.Table.SetStyles(s)

	// Render header manually
	headerCells := make([]string, len(cols))
	for ci, col := range cols {
		cellStyle := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true)
		title := cellStyle.Render(col.Title)
		headerCells[ci] = lipgloss.NewStyle().
			Foreground(colorGray).Background(colorBG).Padding(0, 1, 0, 0).
			Render(title)
	}
	headerLine := bgFill(lipgloss.JoinHorizontal(lipgloss.Left, headerCells...), tableWidth)
	// Header separator (thin line)
	sepLine := bgFill(lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).
		Render(strings.Repeat("─", tableWidth)), tableWidth)

	var coloredTableLines []string
	coloredTableLines = append(coloredTableLines, headerLine, sepLine)

	// Determine visible rows (simple windowing)
	allRows := m.Table.Rows()
	cursor := m.Table.Cursor()
	visibleRowCount := h - 2 // minus header + separator
	if visibleRowCount < 1 {
		visibleRowCount = 1
	}

	// Calculate scroll window: keep cursor in view
	startRow := 0
	if cursor >= visibleRowCount {
		startRow = cursor - visibleRowCount + 1
	}
	endRow := startRow + visibleRowCount
	if endRow > len(allRows) {
		endRow = len(allRows)
		startRow = endRow - visibleRowCount
		if startRow < 0 {
			startRow = 0
		}
	}

	// Normal row style
	normalFG := colorText
	normalBG := colorBG
	// Selected row style: CYAN bg, dark text
	selectedFG := colorOnPrimary   // #003739 — dark text
	selectedBG := colorPrimaryCont // #00f5ff — CYAN

	for ri := startRow; ri < endRow; ri++ {
		row := allRows[ri]
		isSelected := ri == cursor

		var fg lipgloss.Color
		var bg lipgloss.Color
		if isSelected {
			fg = selectedFG
			bg = selectedBG
		} else {
			fg = normalFG
			bg = normalBG
		}

		cells := make([]string, len(cols))
		for ci, col := range cols {
			val := ""
			if ci < len(row) {
				val = row[ci]
			}
			// Per-cell foreground: severity column (index 1) gets DESIGN.md semantic color
			cellFG := fg
			if !isSelected && ci == 1 { // SEV column
				switch strings.TrimSpace(val) {
				case "CRITICAL":
					cellFG = colorError
				case "HIGH":
					cellFG = colorTertiaryCont
				case "MEDIUM":
					cellFG = colorSecondary
				case "LOW":
					cellFG = colorGray
				}
			}
			cellInner := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true).Render(val)
			cellStyle := lipgloss.NewStyle().Foreground(cellFG).Background(bg).Padding(0, 1, 0, 0)
			if !isSelected && ci == 1 && (strings.TrimSpace(val) == "CRITICAL") {
				cellStyle = cellStyle.Bold(true)
			}
			cells[ci] = cellStyle.Render(cellInner)
		}
		line := lipgloss.JoinHorizontal(lipgloss.Left, cells...)
		// Fill to full tableWidth
		vw := lipgloss.Width(line)
		if vw < tableWidth {
			line += lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", tableWidth-vw))
		} else if vw > tableWidth {
			line = ansi.Truncate(line, tableWidth, "")
		}
		coloredTableLines = append(coloredTableLines, line)
	}

	// Pad/trim to exactly h lines
	for len(coloredTableLines) < h {
		coloredTableLines = append(coloredTableLines, bgFill("", tableWidth))
	}
	if len(coloredTableLines) > h {
		coloredTableLines = coloredTableLines[:h]
	}

	sepW := 1
	rightWidth := w - tableWidth - sepW
	if rightWidth < 1 {
		rightWidth = 1
	}

	codeBoxOuter := h / 2
	remediationOuter := h - codeBoxOuter

	// Post-process viewport outputs: paint every line
	srcTitle := bgCell(" SRC_PREVIEW ", rightWidth, colorText)
	vpRaw := m.Viewport.View()
	vpLines := strings.Split(vpRaw, "\n")
	var codeLines []string
	codeLines = append(codeLines, srcTitle)
	for _, line := range vpLines {
		codeLines = append(codeLines, bgFill(line, rightWidth))
	}
	for len(codeLines) < codeBoxOuter {
		codeLines = append(codeLines, bgFill("", rightWidth))
	}
	if len(codeLines) > codeBoxOuter {
		codeLines = codeLines[:codeBoxOuter]
	}

	var aiTitle string
	if m.TriageFocusDetail {
		aiTitle = lipgloss.NewStyle().Background(colorSurface).Foreground(colorPrimary).Bold(true).
			Width(rightWidth).MaxWidth(rightWidth).ColorWhitespace(true).
			Render(" ▶ AI ADVICE [Tab: switch] ")
	} else {
		aiTitle = lipgloss.NewStyle().Background(colorSurface).Foreground(colorGray).
			Width(rightWidth).MaxWidth(rightWidth).ColorWhitespace(true).
			Render(" AI ADVICE [Tab: focus] ")
	}
	remRaw := m.RemediationViewport.View()
	remLines := strings.Split(remRaw, "\n")
	var remColoredLines []string
	remColoredLines = append(remColoredLines, aiTitle)
	for _, line := range remLines {
		remColoredLines = append(remColoredLines, bgFill(line, rightWidth))
	}
	for len(remColoredLines) < remediationOuter {
		remColoredLines = append(remColoredLines, bgFill("", rightWidth))
	}
	if len(remColoredLines) > remediationOuter {
		remColoredLines = remColoredLines[:remediationOuter]
	}

	// Combine right pane
	rightLines := append(codeLines, remColoredLines...)

	// Assemble rows: table | sep | right
	colSep := bgCell("│", sepW, colorOutline)
	var rows []string
	for i := 0; i < h; i++ {
		var lStr, rStr string
		if i < len(coloredTableLines) {
			lStr = coloredTableLines[i]
		}
		if i < len(rightLines) {
			rStr = rightLines[i]
		}
		rows = append(rows, lStr+colSep+rStr)
	}

	return strings.Join(rows, "\n")
}

func (m DashboardModel) renderSAST(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	ensureBgANSI()
	tableWidth := (w * 6) / 10
	if tableWidth < 1 {
		tableWidth = 1
	}

	usable := tableWidth - 5
	if usable < 20 {
		usable = 20
	}
	colSrc := usable * 12 / 100
	colRule := usable * 20 / 100
	colSev := usable * 8 / 100
	colMsg := usable * 35 / 100
	colFile := usable - colSrc - colRule - colSev - colMsg
	if colSrc < 6 {
		colSrc = 6
	}
	if colRule < 8 {
		colRule = 8
	}
	if colSev < 4 {
		colSev = 4
	}
	if colFile < 5 {
		colFile = 5
	}

	cols := []table.Column{
		{Title: "SOURCE", Width: colSrc},
		{Title: "RULE", Width: colRule},
		{Title: "SEV", Width: colSev},
		{Title: "MESSAGE", Width: colMsg},
		{Title: "FILE", Width: colFile},
	}
	m.SASTTable.SetColumns(cols)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colorOutline).
		BorderBottom(true).
		Foreground(colorGray).
		Background(colorBG).
		Bold(false).
		Padding(0, 1, 0, 0)
	s.Selected = s.Selected.
		Foreground(colorOnPrimary).
		Background(colorPrimaryCont).
		Bold(true)
	s.Cell = lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Padding(0, 1, 0, 0)
	m.SASTTable.SetStyles(s)

	// Header
	headerCells := make([]string, len(cols))
	for ci, col := range cols {
		cellStyle := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true)
		title := cellStyle.Render(col.Title)
		headerCells[ci] = lipgloss.NewStyle().
			Foreground(colorGray).Background(colorBG).Padding(0, 1, 0, 0).
			Render(title)
	}
	headerLine := bgFill(lipgloss.JoinHorizontal(lipgloss.Left, headerCells...), tableWidth)
	sepLine := bgFill(lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).
		Render(strings.Repeat("─", tableWidth)), tableWidth)

	var coloredTableLines []string
	coloredTableLines = append(coloredTableLines, headerLine, sepLine)

	allRows := m.SASTTable.Rows()
	cursor := m.SASTTable.Cursor()
	visibleRowCount := h - 2
	if visibleRowCount < 1 {
		visibleRowCount = 1
	}

	startRow := 0
	if cursor >= visibleRowCount {
		startRow = cursor - visibleRowCount + 1
	}
	endRow := startRow + visibleRowCount
	if endRow > len(allRows) {
		endRow = len(allRows)
		startRow = endRow - visibleRowCount
		if startRow < 0 {
			startRow = 0
		}
	}

	normalFG := colorText
	normalBG := colorBG
	selectedFG := colorOnPrimary
	selectedBG := colorPrimaryCont

	for ri := startRow; ri < endRow; ri++ {
		row := allRows[ri]
		isSelected := ri == cursor

		var fg lipgloss.Color
		var bg lipgloss.Color
		if isSelected {
			fg = selectedFG
			bg = selectedBG
		} else {
			fg = normalFG
			bg = normalBG
		}

		cells := make([]string, len(cols))
		for ci, col := range cols {
			val := ""
			if ci < len(row) {
				val = row[ci]
			}
			// Per-cell foreground: severity column (index 2) gets DESIGN.md semantic color
			cellFG := fg
			if !isSelected && ci == 2 { // SEV column
				switch strings.TrimSpace(val) {
				case "CRITICAL":
					cellFG = colorError // #ffb4ab
				case "HIGH":
					cellFG = colorTertiaryCont // #ffdb3f (amber)
				case "MEDIUM":
					cellFG = colorSecondary // #b8c3ff (cobalt)
				case "LOW":
					cellFG = colorGray // #849495
				}
			}
			cellInner := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true).Render(val)
			cellStyle := lipgloss.NewStyle().Foreground(cellFG).Background(bg).Padding(0, 1, 0, 0)
			if !isSelected && ci == 2 && (strings.TrimSpace(val) == "CRITICAL") {
				cellStyle = cellStyle.Bold(true)
			}
			cells[ci] = cellStyle.Render(cellInner)
		}
		line := lipgloss.JoinHorizontal(lipgloss.Left, cells...)
		vw := lipgloss.Width(line)
		if vw < tableWidth {
			line += lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", tableWidth-vw))
		} else if vw > tableWidth {
			line = ansi.Truncate(line, tableWidth, "")
		}
		coloredTableLines = append(coloredTableLines, line)
	}

	// Handle empty state
	if len(allRows) == 0 {
		emptyMsg := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).
			Render("  No external scanner findings. Install semgrep/trivy/gitleaks/bandit for SAST coverage.")
		coloredTableLines = append(coloredTableLines, bgFill(emptyMsg, tableWidth))
	}

	for len(coloredTableLines) < h {
		coloredTableLines = append(coloredTableLines, bgFill("", tableWidth))
	}
	if len(coloredTableLines) > h {
		coloredTableLines = coloredTableLines[:h]
	}

	sepW := 1
	rightWidth := w - tableWidth - sepW
	if rightWidth < 1 {
		rightWidth = 1
	}

	// Right pane: SAST detail viewport (full height)
	var detailTitle string
	if m.SASTFocusDetail {
		detailTitle = lipgloss.NewStyle().
			Foreground(colorPrimary).Background(colorBG).Bold(true).
			Width(rightWidth).MaxWidth(rightWidth).Inline(true).
			Render(" ▶ AI ADVICE [Tab: switch] ")
	} else {
		detailTitle = bgCell(" AI ADVICE [Tab: focus] ", rightWidth, colorGray)
	}
	vpRaw := m.SASTViewport.View()
	vpLines := strings.Split(vpRaw, "\n")
	var rightLines []string
	rightLines = append(rightLines, detailTitle)
	for _, line := range vpLines {
		rightLines = append(rightLines, bgFill(line, rightWidth))
	}
	for len(rightLines) < h {
		rightLines = append(rightLines, bgFill("", rightWidth))
	}
	if len(rightLines) > h {
		rightLines = rightLines[:h]
	}

	colSepStr := bgCell("│", sepW, colorOutline)
	var rows []string
	for i := 0; i < h; i++ {
		var lStr, rStr string
		if i < len(coloredTableLines) {
			lStr = coloredTableLines[i]
		}
		if i < len(rightLines) {
			rStr = rightLines[i]
		}
		rows = append(rows, lStr+colSepStr+rStr)
	}

	return strings.Join(rows, "\n")
}

func (m DashboardModel) renderGraph(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	ensureBgANSI()

	// ── KPI Title Bar ────────────────────────────────────────────────────
	nodeCount := len(m.DepGraph.Nodes)
	edgeCount := 0
	for _, children := range m.DepGraph.Edges {
		edgeCount += len(children)
	}
	isChildMap := make(map[string]bool)
	for _, children := range m.DepGraph.Edges {
		for _, child := range children {
			isChildMap[child] = true
		}
	}
	rootCount := 0
	for _, node := range m.DepGraph.Nodes {
		if !isChildMap[node.ID()] {
			rootCount++
		}
	}

	titleStyle := lipgloss.NewStyle().
		Foreground(colorBG).Background(colorPrimaryCont).Bold(true).Padding(0, 1)
	metricStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorSurfaceHigh)
	mValStyle := lipgloss.NewStyle().Foreground(colorText).Background(colorSurfaceHigh).Bold(true)

	var titleText string
	if m.ScanInProgress {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		titleText = titleStyle.Render(" " + frames[m.TickCount%len(frames)] + " SCANNING... ")
	} else {
		titleText = titleStyle.Render(" ◆ TOPOLOGY ")
	}

	met := metricStyle.Render(" NODES: ") + mValStyle.Render(fmt.Sprintf("%d", nodeCount)) +
		metricStyle.Render(" │ EDGES: ") + mValStyle.Render(fmt.Sprintf("%d", edgeCount)) +
		metricStyle.Render(" │ ROOTS: ") + mValStyle.Render(fmt.Sprintf("%d", rootCount))
	headerLine := titleText + met
	hw := lipgloss.Width(headerLine)
	if hw < w {
		headerLine += lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", w-hw))
	}

	if nodeCount == 0 {
		var rows []string
		rows = append(rows, headerLine)
		emptyLines := []string{
			"", "",
			"      ╭──────────────────────────────────╮",
			"      │                                    │",
			"      │   No dependency graph detected.    │",
			"      │                                    │",
			"      │   Scan a project containing:       │",
			"      │     • package.json  (npm)           │",
			"      │     • go.mod        (Go)            │",
			"      │     • requirements.txt (Python)     │",
			"      │                                    │",
			"      │   Press [S] to scan.               │",
			"      │                                    │",
			"      ╰──────────────────────────────────╯",
		}
		emptyStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG)
		for _, el := range emptyLines {
			rows = append(rows, bgFill(emptyStyle.Render(el), w))
		}
		for len(rows) < h {
			rows = append(rows, bgFill("", w))
		}
		if len(rows) > h {
			rows = rows[:h]
		}
		return strings.Join(rows, "\n")
	}

	// ── Split Layout: Tree (60%) │ Detail (40%) ─────────────────────────
	sepW := 1
	leftWidth := w * 60 / 100
	rightWidth := w - leftWidth - sepW
	if rightWidth < 20 {
		rightWidth = 20
		leftWidth = w - rightWidth - sepW
	}
	bodyH := h - 2 // header + footer

	// ── Left: Interactive Tree ──────────────────────────────────────────
	nodes := m.TopologyNodes
	cursor := m.TopologyCursor
	if cursor >= len(nodes) {
		cursor = len(nodes) - 1
	}
	if cursor < 0 {
		cursor = 0
	}

	startRow := 0
	if cursor >= bodyH {
		startRow = cursor - bodyH + 1
	}
	endRow := startRow + bodyH
	if endRow > len(nodes) {
		endRow = len(nodes)
		startRow = endRow - bodyH
		if startRow < 0 {
			startRow = 0
		}
	}

	var leftLines []string
	for i := startRow; i < endRow; i++ {
		node := nodes[i]
		isSel := i == cursor
		indent := strings.Repeat("  ", node.Depth)

		var arrow string
		if node.HasKids {
			if m.TopologyExpanded[node.ID] {
				arrow = "▼ "
			} else {
				arrow = "▶ "
			}
		} else {
			arrow = "  "
		}

		var line string
		if isSel {
			st := lipgloss.NewStyle().Foreground(colorOnPrimary).Background(colorPrimaryCont).Bold(true)
			line = st.Render(indent + arrow + node.Name)
			if node.Version != "" {
				line += lipgloss.NewStyle().Foreground(colorOnPrimary).Background(colorPrimaryCont).Render(" @" + node.Version)
			}
		} else if node.IsRoot {
			st := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Bold(true)
			line = lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(indent) +
				lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorBG).Render(arrow) + st.Render(node.Name)
			if node.Version != "" {
				line += lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(" @" + node.Version)
			}
		} else {
			line = lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(indent+arrow) +
				lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Render(node.Name)
			if node.Version != "" {
				line += lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(" @" + node.Version)
			}
		}

		vw := lipgloss.Width(line)
		padBG := colorBG
		if isSel {
			padBG = colorPrimaryCont
		}
		if vw < leftWidth {
			line += lipgloss.NewStyle().Background(padBG).Render(strings.Repeat(" ", leftWidth-vw))
		} else if vw > leftWidth {
			line = ansi.Truncate(line, leftWidth, "")
		}
		leftLines = append(leftLines, line)
	}
	for len(leftLines) < bodyH {
		leftLines = append(leftLines, bgFill("", leftWidth))
	}

	// ── Right: Detail Panel ─────────────────────────────────────────────
	var rightLines []string
	dBG := colorSurfaceHigh
	dStyle := func(fg lipgloss.Color) lipgloss.Style {
		return lipgloss.NewStyle().Foreground(fg).Background(dBG)
	}
	padRight := func(s string) string {
		vw := lipgloss.Width(s)
		if vw < rightWidth {
			return s + lipgloss.NewStyle().Background(dBG).Render(strings.Repeat(" ", rightWidth-vw))
		}
		if vw > rightWidth {
			return ansi.Truncate(s, rightWidth, "")
		}
		return s
	}

	if cursor >= 0 && cursor < len(nodes) {
		sel := nodes[cursor]
		rightLines = append(rightLines, padRight(dStyle(colorPrimaryCont).Bold(true).Render(" "+sel.Name)))
		if sel.Version != "" {
			rightLines = append(rightLines, padRight(dStyle(colorGray).Render(" version: "+sel.Version)))
		}
		if sel.IsRoot {
			badge := lipgloss.NewStyle().Foreground(colorBG).Background(colorSecondary).Bold(true).Padding(0, 1).Render("ROOT MODULE")
			rightLines = append(rightLines, padRight(" "+badge))
		}
		rightLines = append(rightLines, padRight(dStyle(colorOutline).Render(" "+strings.Repeat("─", rightWidth-2))))

		children := m.DepGraph.Edges[sel.ID]
		if len(children) > 0 {
			rightLines = append(rightLines, padRight(dStyle(colorText).Bold(true).Render(fmt.Sprintf(" Dependencies (%d):", len(children)))))
			for i, child := range children {
				if i >= bodyH-10 {
					rightLines = append(rightLines, padRight(dStyle(colorGray).Render(fmt.Sprintf("   ... +%d more", len(children)-i))))
					break
				}
				rightLines = append(rightLines, padRight(dStyle(colorTextVariant).Render("   → "+child)))
			}
		} else {
			rightLines = append(rightLines, padRight(dStyle(colorGray).Render(" Leaf node (no dependencies)")))
		}

		rightLines = append(rightLines, padRight(""))
		var reverseDeps []string
		for parent, kids := range m.DepGraph.Edges {
			for _, kid := range kids {
				if kid == sel.ID {
					reverseDeps = append(reverseDeps, parent)
				}
			}
		}
		if len(reverseDeps) > 0 {
			rightLines = append(rightLines, padRight(dStyle(colorText).Bold(true).Render(fmt.Sprintf(" Required by (%d):", len(reverseDeps)))))
			for i, rd := range reverseDeps {
				if i >= 8 {
					rightLines = append(rightLines, padRight(dStyle(colorGray).Render(fmt.Sprintf("   ... +%d more", len(reverseDeps)-i))))
					break
				}
				rightLines = append(rightLines, padRight(dStyle(colorTextVariant).Render("   ← "+rd)))
			}
		}
	}

	for len(rightLines) < bodyH {
		rightLines = append(rightLines, lipgloss.NewStyle().Background(dBG).Render(strings.Repeat(" ", rightWidth)))
	}
	if len(rightLines) > bodyH {
		rightLines = rightLines[:bodyH]
	}

	// ── Assembly ─────────────────────────────────────────────────────────
	colSepStr := bgCell("│", sepW, colorOutline)
	var bodyRows []string
	for i := 0; i < bodyH; i++ {
		var lStr, rStr string
		if i < len(leftLines) {
			lStr = leftLines[i]
		}
		if i < len(rightLines) {
			rStr = rightLines[i]
		}
		bodyRows = append(bodyRows, lStr+colSepStr+rStr)
	}

	posStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorSurfaceHigh)
	posValSt := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorSurfaceHigh).Bold(true)
	pos := posValSt.Render(fmt.Sprintf(" %d", cursor+1)) +
		posStyle.Render(fmt.Sprintf("/%d ", len(nodes))) +
		posStyle.Render("│ ↑↓ nav  Enter expand  ← collapse ")
	sepStr := lipgloss.NewStyle().Foreground(colorOutline).Background(colorSurfaceHigh).Render("─── ")
	footerLine := sepStr + pos + sepStr
	fw := lipgloss.Width(footerLine)
	if fw < w {
		footerLine += lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", w-fw))
	}

	var allRows []string
	allRows = append(allRows, headerLine)
	allRows = append(allRows, bodyRows...)
	allRows = append(allRows, footerLine)
	for len(allRows) < h {
		allRows = append(allRows, bgFill("", w))
	}
	if len(allRows) > h {
		allRows = allRows[:h]
	}

	return strings.Join(allRows, "\n")
}

func (m DashboardModel) renderDeps(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	ensureBgANSI()
	tableWidth := w

	// ── KPI Title Bar ────────────────────────────────────────────────────
	allRows := m.DepsTable.Rows()
	totalDeps := len(allRows)

	// Count by type from raw dependencies
	prodCount, devCount, indirectCount, rootCount := 0, 0, 0, 0
	for _, d := range m.Report.Dependencies {
		switch d.Type {
		case "root":
			rootCount++
		case "dev":
			devCount++
		case "indirect":
			indirectCount++
		default:
			prodCount++
		}
	}

	titleStyle := lipgloss.NewStyle().
		Foreground(colorBG).
		Background(colorPrimaryCont).
		Bold(true).
		Padding(0, 1)

	metricStyle := lipgloss.NewStyle().
		Foreground(colorGray).
		Background(colorSurfaceHigh)

	metricValStyle := lipgloss.NewStyle().
		Foreground(colorText).
		Background(colorSurfaceHigh).
		Bold(true)

	var titleText string
	if m.ScanInProgress {
		titleText = titleStyle.Render(" ⟳ SCANNING DEPENDENCIES... ")
	} else {
		titleText = titleStyle.Render(" DEPENDENCY AUDIT ")
	}

	metrics := metricStyle.Render(" TOTAL: ") + metricValStyle.Render(fmt.Sprintf("%d", totalDeps)) +
		metricStyle.Render(" │ PROD: ") + metricValStyle.Render(fmt.Sprintf("%d", prodCount)) +
		metricStyle.Render(" │ DEV: ") + metricValStyle.Render(fmt.Sprintf("%d", devCount)) +
		metricStyle.Render(" │ INDIRECT: ") + metricValStyle.Render(fmt.Sprintf("%d", indirectCount))
	if rootCount > 0 {
		metrics += metricStyle.Render(" │ ROOT: ") + metricValStyle.Render(fmt.Sprintf("%d", rootCount))
	}

	titleLine := titleText + metrics
	tw := lipgloss.Width(titleLine)
	if tw < tableWidth {
		titleLine += lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", tableWidth-tw))
	}

	// ── Column Widths ────────────────────────────────────────────────────
	usable := tableWidth - 4
	if usable < 20 {
		usable = 20
	}
	cols := []table.Column{
		{Title: "NAME", Width: usable * 40 / 100},
		{Title: "VERSION", Width: usable * 20 / 100},
		{Title: "TYPE", Width: usable * 20 / 100},
		{Title: "ECOSYSTEM", Width: usable - usable*40/100 - usable*20/100 - usable*20/100},
	}

	// ── Column Header ────────────────────────────────────────────────────
	headerCells := make([]string, len(cols))
	for ci, col := range cols {
		cellStyle := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true)
		title := cellStyle.Render(col.Title)
		headerCells[ci] = lipgloss.NewStyle().
			Foreground(colorGray).Background(colorBG).Padding(0, 1, 0, 0).
			Render(title)
	}
	headerLine := bgFill(lipgloss.JoinHorizontal(lipgloss.Left, headerCells...), tableWidth)
	sepLine := bgFill(lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).
		Render(strings.Repeat("─", tableWidth)), tableWidth)

	var coloredTableLines []string
	coloredTableLines = append(coloredTableLines, titleLine, headerLine, sepLine)

	// ── Row Rendering ────────────────────────────────────────────────────
	cursor := m.DepsTable.Cursor()
	// Reserve: title(1) + header(1) + sep(1) + footer(1) = 4 chrome lines
	visibleRowCount := h - 4
	if visibleRowCount < 1 {
		visibleRowCount = 1
	}

	startRow := 0
	if cursor >= visibleRowCount {
		startRow = cursor - visibleRowCount + 1
	}
	endRow := startRow + visibleRowCount
	if endRow > len(allRows) {
		endRow = len(allRows)
		startRow = endRow - visibleRowCount
		if startRow < 0 {
			startRow = 0
		}
	}

	normalFG := colorText
	normalBG := colorBG
	selectedFG := colorOnPrimary
	selectedBG := colorPrimaryCont

	for ri := startRow; ri < endRow; ri++ {
		row := allRows[ri]
		isSelected := ri == cursor

		var fg lipgloss.Color
		var bg lipgloss.Color
		if isSelected {
			fg = selectedFG
			bg = selectedBG
		} else {
			fg = normalFG
			bg = normalBG
		}

		cells := make([]string, len(cols))
		for ci, col := range cols {
			val := ""
			if ci < len(row) {
				val = row[ci]
			}

			cellFG := fg

			// TYPE column (index 2) — semantic coloring
			if !isSelected && ci == 2 {
				switch strings.TrimSpace(val) {
				case "root":
					cellFG = colorPrimaryCont
				case "dev":
					cellFG = colorSecondary
				case "indirect":
					cellFG = colorGray
				}
			}

			// ECOSYSTEM column (index 3) — badge coloring
			if !isSelected && ci == 3 {
				switch strings.TrimSpace(val) {
				case "go":
					cellFG = colorPrimaryDim
				case "npm":
					cellFG = colorTertiaryCont
				case "pypi":
					cellFG = colorSecondary
				case "rust":
					cellFG = colorError
				case "ruby":
					cellFG = colorError
				case "php":
					cellFG = colorSecondary
				}
			}

			cellInner := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true).Render(val)
			cellStyle := lipgloss.NewStyle().Foreground(cellFG).Background(bg).Padding(0, 1, 0, 0)

			// Bold root type
			if !isSelected && ci == 2 && strings.TrimSpace(val) == "root" {
				cellStyle = cellStyle.Bold(true)
			}

			cells[ci] = cellStyle.Render(cellInner)
		}
		line := lipgloss.JoinHorizontal(lipgloss.Left, cells...)
		vw := lipgloss.Width(line)
		if vw < tableWidth {
			line += lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", tableWidth-vw))
		} else if vw > tableWidth {
			line = ansi.Truncate(line, tableWidth, "")
		}
		coloredTableLines = append(coloredTableLines, line)
	}

	// ── Empty State ──────────────────────────────────────────────────────
	if len(allRows) == 0 {
		emptyLines := []string{
			"",
			"      No dependencies detected in project.",
			"",
			"      Scan a project containing:",
			"        • package.json  (npm)",
			"        • go.mod        (Go)",
			"        • requirements.txt (Python)",
			"        • Cargo.toml    (Rust)",
			"        • composer.json (PHP)",
			"        • Gemfile       (Ruby)",
		}
		emptyStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG)
		for _, el := range emptyLines {
			coloredTableLines = append(coloredTableLines, bgFill(emptyStyle.Render(el), tableWidth))
		}
	}

	// ── Scroll Position Indicator ────────────────────────────────────────
	var footerLine string
	if len(allRows) > 0 {
		posStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorSurfaceHigh)
		posValStyle := lipgloss.NewStyle().Foreground(colorPrimaryDim).Background(colorSurfaceHigh).Bold(true)
		pos := posValStyle.Render(fmt.Sprintf(" %d", cursor+1)) +
			posStyle.Render(fmt.Sprintf("/%d ", totalDeps)) +
			posStyle.Render("dependencies ")
		sepStr := lipgloss.NewStyle().Foreground(colorOutline).Background(colorSurfaceHigh).
			Render("─── ")
		footerLine = sepStr + pos + sepStr
		fw := lipgloss.Width(footerLine)
		if fw < tableWidth {
			footerLine += lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", tableWidth-fw))
		}
	} else {
		footerLine = bgFill("", tableWidth)
	}

	// ── Assembly ─────────────────────────────────────────────────────────
	// Pad body to exact height minus footer
	bodyH := h - 1 // 1 for footer
	for len(coloredTableLines) < bodyH {
		coloredTableLines = append(coloredTableLines, bgFill("", tableWidth))
	}
	if len(coloredTableLines) > bodyH {
		coloredTableLines = coloredTableLines[:bodyH]
	}
	coloredTableLines = append(coloredTableLines, footerLine)

	return strings.Join(coloredTableLines, "\n")
}

func (m DashboardModel) renderInfra(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	ensureBgANSI()
	tableWidth := w

	// Column widths for custom header rendering (mirrors handleResize calc).
	// Actual table columns/styles are set in handleResize (pointer receiver).
	usable := tableWidth - 4
	if usable < 20 {
		usable = 20
	}
	iColType := usable * 10 / 100
	iColSev := usable * 10 / 100
	iColFind := usable * 45 / 100
	iColTarget := usable - iColType - iColSev - iColFind
	if iColType < 6 {
		iColType = 6
	}
	if iColSev < 4 {
		iColSev = 4
	}
	if iColTarget < 10 {
		iColTarget = 10
	}
	cols := []table.Column{
		{Title: "TYPE", Width: iColType},
		{Title: "SEV", Width: iColSev},
		{Title: "FINDING", Width: iColFind},
		{Title: "TARGET", Width: iColTarget},
	}

	// Header
	headerCells := make([]string, len(cols))
	for ci, col := range cols {
		cellStyle := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true)
		title := cellStyle.Render(col.Title)
		headerCells[ci] = lipgloss.NewStyle().
			Foreground(colorGray).Background(colorBG).Padding(0, 1, 0, 0).
			Render(title)
	}
	headerLine := bgFill(lipgloss.JoinHorizontal(lipgloss.Left, headerCells...), tableWidth)
	sepLine := bgFill(lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).
		Render(strings.Repeat("─", tableWidth)), tableWidth)

	var coloredTableLines []string
	coloredTableLines = append(coloredTableLines, headerLine, sepLine)

	allRows := m.InfraTable.Rows()
	cursor := m.InfraTable.Cursor()
	visibleRowCount := h - 2
	if visibleRowCount < 1 {
		visibleRowCount = 1
	}

	startRow := 0
	if cursor >= visibleRowCount {
		startRow = cursor - visibleRowCount + 1
	}
	endRow := startRow + visibleRowCount
	if endRow > len(allRows) {
		endRow = len(allRows)
		startRow = endRow - visibleRowCount
		if startRow < 0 {
			startRow = 0
		}
	}

	normalFG := colorText
	normalBG := colorBG
	selectedFG := colorOnPrimary
	selectedBG := colorPrimaryCont

	for ri := startRow; ri < endRow; ri++ {
		row := allRows[ri]
		isSelected := ri == cursor

		var fg lipgloss.Color
		var bg lipgloss.Color
		if isSelected {
			fg = selectedFG
			bg = selectedBG
		} else {
			fg = normalFG
			bg = normalBG
		}

		cells := make([]string, len(cols))
		for ci, col := range cols {
			val := ""
			if ci < len(row) {
				val = row[ci]
			}

			cellFG := fg
			if !isSelected && ci == 1 { // SEV column
				switch strings.TrimSpace(val) {
				case "CRITICAL":
					cellFG = colorError
				case "HIGH":
					cellFG = colorTertiaryCont
				case "MEDIUM":
					cellFG = colorSecondary
				case "LOW":
					cellFG = colorGray
				}
			}
			cellInner := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true).Render(val)
			cellStyle := lipgloss.NewStyle().Foreground(cellFG).Background(bg).Padding(0, 1, 0, 0)
			if !isSelected && ci == 1 && (strings.TrimSpace(val) == "CRITICAL") {
				cellStyle = cellStyle.Bold(true)
			}
			cells[ci] = cellStyle.Render(cellInner)
		}
		line := lipgloss.JoinHorizontal(lipgloss.Left, cells...)
		vw := lipgloss.Width(line)
		if vw < tableWidth {
			line += lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", tableWidth-vw))
		} else if vw > tableWidth {
			line = ansi.Truncate(line, tableWidth, "")
		}
		coloredTableLines = append(coloredTableLines, line)
	}

	// Handle empty state
	if len(allRows) == 0 {
		emptyMsg := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).
			Render("  No infrastructure findings detected.")
		coloredTableLines = append(coloredTableLines, bgFill(emptyMsg, tableWidth))
	}

	for len(coloredTableLines) < h {
		coloredTableLines = append(coloredTableLines, bgFill("", tableWidth))
	}
	if len(coloredTableLines) > h {
		coloredTableLines = coloredTableLines[:h]
	}

	return strings.Join(coloredTableLines, "\n")
}

func (m DashboardModel) renderAudit(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}

	// Column widths
	colTime := 20
	colAction := 14
	colTarget := w - colTime - colAction - 4 // 4 for separators and spacing
	if colTarget < 10 {
		colTarget = 10
	}

	// Header row — styled per DESIGN.md
	tsH := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Width(colTime).Render("TIMESTAMP")
	actH := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Width(colAction).Render("ACTION")
	tgtH := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Width(colTarget).Render("TARGET")
	sep := bgCell("│", 1, colorOutline)
	headerStr := tsH + sep + " " + actH + sep + " " + tgtH

	dividerStr := lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).Render(strings.Repeat("─", w))

	// Build audit entries from real scan data
	type auditEntry struct {
		ts     string
		action string
		target string
		color  lipgloss.Color
	}

	entries := []auditEntry{
		{m.ScanStartTime.Add(-4 * time.Minute).Format("2006-01-02 15:04"), "SCAN_INIT", m.Report.ProjectPath, colorGray},
	}

	// Add real entries from scan results
	critCount, highCount, medCount := 0, 0, 0
	for _, res := range m.Report.Results {
		switch res.Severity {
		case "CRITICAL":
			critCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			medCount++
		}
	}

	if m.Report.TotalFiles > 0 {
		entries = append(entries, auditEntry{
			m.ScanStartTime.Add(-3 * time.Minute).Format("2006-01-02 15:04"),
			"FILE_SCAN", fmt.Sprintf("%d files analyzed", m.Report.TotalFiles),
			colorSecondary,
		})
	}

	if m.Report.RulesApplied > 0 {
		entries = append(entries, auditEntry{
			m.ScanStartTime.Add(-3 * time.Minute).Format("2006-01-02 15:04"),
			"RULE_EXEC", fmt.Sprintf("%d rules applied across %d stacks", m.Report.RulesApplied, len(m.Report.Stacks)),
			colorSecondary,
		})
	}

	if critCount > 0 {
		entries = append(entries, auditEntry{
			m.ScanStartTime.Add(-2 * time.Minute).Format("2006-01-02 15:04"),
			"CRIT_ALERT", fmt.Sprintf("%d critical findings detected", critCount),
			colorError,
		})
	}

	if highCount > 0 {
		entries = append(entries, auditEntry{
			m.ScanStartTime.Add(-2 * time.Minute).Format("2006-01-02 15:04"),
			"ENT_DETC", fmt.Sprintf("%d high severity issues", highCount),
			colorTertiaryCont,
		})
	}

	if medCount > 0 {
		entries = append(entries, auditEntry{
			m.ScanStartTime.Add(-1 * time.Minute).Format("2006-01-02 15:04"),
			"MED_CHECK", fmt.Sprintf("%d medium severity issues", medCount),
			colorSecondary,
		})
	}

	entries = append(entries, auditEntry{
		m.ScanStartTime.Format("2006-01-02 15:04"),
		"SEC_SCR", fmt.Sprintf("SecurityScore generated: %d", m.Report.SecurityScore),
		colorPrimaryDim,
	})

	var rows []string
	rows = append(rows, bgFill(headerStr, w))
	rows = append(rows, bgFill(dividerStr, w))

	for _, e := range entries {
		target := e.target
		if len(target) > colTarget {
			target = target[:colTarget-3] + "..."
		}
		tsCell := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Width(colTime).Render(e.ts)
		actCell := lipgloss.NewStyle().Foreground(e.color).Background(colorBG).Width(colAction).Render(e.action)
		tgtCell := lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Width(colTarget).Render(target)
		rows = append(rows, bgFill(tsCell+sep+" "+actCell+sep+" "+tgtCell, w))
	}

	for len(rows) < h {
		rows = append(rows, bgFill("", w))
	}
	if len(rows) > h {
		rows = rows[:h]
	}

	return strings.Join(rows, "\n")
}

func (m DashboardModel) renderReports(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	title := labelStyle.Render("[ EXECUTIVE_SUMMARY ]")

	stats := []string{
		m.renderMetric("Project Path", m.Report.ProjectPath, w),
		m.renderMetric("Total Findings", fmt.Sprintf("%d", len(m.Report.Results)), w),
		m.renderMetric("Security Score", fmt.Sprintf("%d/100", m.Report.SecurityScore), w),
		m.renderMetric("Engine Version", fmt.Sprintf("AITriage %s", m.Version), w),
		m.renderMetric("Scan Time", m.ScanStartTime.Format("2006-01-02 15:04:05"), w),
		m.renderMetric("Scan Duration", m.Report.ScanDuration.Truncate(time.Millisecond).String(), w),
	}

	// Dynamic recommendation based on actual scan data
	crit, high := 0, 0
	for _, res := range m.Report.Results {
		switch res.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		}
	}
	var recText string
	switch {
	case crit > 0:
		recText = fmt.Sprintf("%d CRITICAL findings require immediate remediation. Rotate all exposed secrets and address authentication bypasses before next deployment.", crit)
	case high > 0:
		recText = fmt.Sprintf("%d HIGH severity findings detected. Prioritize input validation and access control hardening. Run 'autofix' for deterministic fixes.", high)
	case len(m.Report.Results) > 0:
		recText = fmt.Sprintf("%d findings detected at medium/low severity. Good security posture. Consider hardening with CSP headers and dependency lockfiles.", len(m.Report.Results))
	default:
		recText = "No findings detected. Excellent security posture. Continue monitoring with scheduled scans."
	}

	recStyle := lipgloss.NewStyle().Background(colorSurface).Foreground(colorAccent).Padding(1, 2).Width(w).MaxWidth(w)
	recHeader := labelStyle.Foreground(colorAccent).Render("AI_RECOMMENDATION:")
	recommendation := recStyle.Render(recHeader + "\n\n" + recText)
	recLines := strings.Split(recommendation, "\n")

	var rows []string
	rows = append(rows, bgFill(title, w))
	rows = append(rows, bgFill("", w))
	for _, s := range stats {
		rows = append(rows, bgFill(s, w))
	}
	rows = append(rows, bgFill("", w))
	for _, rl := range recLines {
		rows = append(rows, bgFill(rl, w))
	}

	for len(rows) < h {
		rows = append(rows, bgFill("", w))
	}
	if len(rows) > h {
		rows = rows[:h]
	}

	return strings.Join(rows, "\n")
}

func (m DashboardModel) renderMetric(k, v string, maxW int) string {
	str := fmt.Sprintf("%-20s: %s", k, v)
	if len(str) > maxW && maxW > 3 {
		str = str[:maxW-3] + "..."
	}
	parts := strings.SplitN(str, ": ", 2)
	if len(parts) == 2 {
		key := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(parts[0])
		sep := lipgloss.NewStyle().Foreground(colorGray).Background(colorBG).Render(": ")
		val := lipgloss.NewStyle().Foreground(colorText).Bold(true).Background(colorBG).Render(parts[1])
		return key + sep + val
	}
	return lipgloss.NewStyle().Foreground(colorText).Background(colorBG).Render(str)
}

func (m DashboardModel) renderChat(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}

	// ── Layout calculations ──
	leftW := w * 35 / 100
	if leftW < 28 {
		leftW = 28
	}
	if leftW > 45 {
		leftW = 45
	}
	sepW := 1 // vertical separator
	rightW := w - leftW - sepW
	if rightW < 10 {
		rightW = 10
	}
	// Safety: if the sum exceeds w, shrink the left panel
	if leftW+sepW+rightW > w {
		leftW = w - sepW - rightW
		if leftW < 10 {
			leftW = 10
		}
	}

	bodyH := h - 1 // reserve 1 line for input bar at bottom (spans full width)
	if bodyH < 1 {
		bodyH = 1
	}

	// ── LEFT PANEL: Command Center ──
	leftFocused := m.ChatFocusMode == 0
	var leftLines []string

	// Panel title
	panelTitleBg := colorSurface
	panelTitleFg := colorGray
	if leftFocused {
		panelTitleBg = colorTertiaryCont
		panelTitleFg = colorBG
	}
	panelTitle := lipgloss.NewStyle().
		Foreground(panelTitleFg).
		Background(panelTitleBg).
		Bold(true).
		Width(leftW).
		Render(" ◆ OPS CENTER ")
	leftLines = append(leftLines, panelTitle)

	// Category definitions for visual grouping
	type cmdCategory struct {
		name  string
		start int
		end   int
	}
	categories := []cmdCategory{
		{"── ANALYSIS ──", 0, 4},
		{"── REMEDIATION ──", 4, 8},
		{"── COMPLIANCE ──", 8, 12},
	}

	// Render commands with category headers
	for _, cat := range categories {
		if cat.start >= len(m.QuickPrompts) {
			break
		}

		// Category header
		catHeader := lipgloss.NewStyle().
			Foreground(colorGray).
			Background(colorBG).
			Width(leftW).
			Render(" " + cat.name)
		leftLines = append(leftLines, catHeader)

		end := cat.end
		if end > len(m.QuickPrompts) {
			end = len(m.QuickPrompts)
		}

		for i := cat.start; i < end; i++ {
			p := m.QuickPrompts[i]

			if i == m.PromptCursor && leftFocused {
				// Active selection
				line := lipgloss.NewStyle().
					Foreground(colorOnPrimary).
					Background(colorTertiaryCont).
					Bold(true).
					Width(leftW).
					Render(" ❯ " + p.Label)
				leftLines = append(leftLines, line)
			} else if i == m.PromptCursor {
				// Cursor but unfocused panel
				line := lipgloss.NewStyle().
					Foreground(colorText).
					Background(colorSurface).
					Width(leftW).
					Render(" › " + p.Label)
				leftLines = append(leftLines, line)
			} else {
				// Normal item
				line := lipgloss.NewStyle().
					Foreground(colorTextVariant).
					Background(colorBG).
					Width(leftW).
					Render("   " + p.Label)
				leftLines = append(leftLines, line)
			}
		}
	}

	// Token counter at bottom of left panel
	tokenLine := lipgloss.NewStyle().
		Foreground(colorGray).
		Background(colorBG).
		Width(leftW).
		Render(fmt.Sprintf(" ◆ %d tokens", m.TokensUsed))

	// Pad left panel to bodyH
	for len(leftLines) < bodyH-1 {
		leftLines = append(leftLines, lipgloss.NewStyle().
			Background(colorBG).
			Width(leftW).
			Render(""))
	}
	// Last line = token counter
	if len(leftLines) >= bodyH {
		leftLines = leftLines[:bodyH-1]
	}
	leftLines = append(leftLines, tokenLine)
	if len(leftLines) > bodyH {
		leftLines = leftLines[:bodyH]
	}

	// ── SEPARATOR ──
	sepStyle := lipgloss.NewStyle().
		Foreground(colorOutline).
		Background(colorBG)

	// ── RIGHT PANEL: Chat History ──
	rightFocused := m.ChatFocusMode == 1

	// Right panel title
	rightTitleBg := colorBG
	rightTitleFg := colorGray
	statusText := ""
	if rightFocused {
		rightTitleFg = colorAccent
		statusText = " HISTORY"
	} else if m.ChatFocusMode == 2 {
		rightTitleFg = colorPrimaryCont
		statusText = " INPUT"
	} else {
		statusText = " HISTORY"
	}

	// AI status indicator
	aiStatus := ""
	if m.ChatAnalyzing {
		aiStatus = lipgloss.NewStyle().
			Foreground(colorPrimaryDim).
			Background(rightTitleBg).
			Bold(true).
			Render(" ⠋ ANALYZING ")
	}

	rightTitle := lipgloss.NewStyle().
		Foreground(rightTitleFg).
		Background(rightTitleBg).
		Bold(true).
		Render(" ["+statusText+" ]") + aiStatus
	// Pad right title
	rtw := lipgloss.Width(rightTitle)
	if rtw < rightW {
		rightTitle = rightTitle + lipgloss.NewStyle().Background(rightTitleBg).Render(strings.Repeat(" ", rightW-rtw))
	}

	chatHeight := bodyH - 1 // minus title
	if chatHeight < 1 {
		chatHeight = 1
	}
	m.ChatViewport.Width = rightW
	m.ChatViewport.Height = chatHeight
	chatBox := m.ChatViewport.View()
	chatLines := strings.Split(chatBox, "\n")
	for len(chatLines) < chatHeight {
		chatLines = append(chatLines, "")
	}
	if len(chatLines) > chatHeight {
		chatLines = chatLines[:chatHeight]
	}

	// Pad each chat line to rightW
	for i, cl := range chatLines {
		clw := lipgloss.Width(cl)
		if clw < rightW {
			chatLines[i] = cl + lipgloss.NewStyle().Background(colorBG).Render(strings.Repeat(" ", rightW-clw))
		}
	}

	// Build right panel lines: title + chat lines
	var rightLines []string
	rightLines = append(rightLines, rightTitle)
	rightLines = append(rightLines, chatLines...)
	for len(rightLines) < bodyH {
		rightLines = append(rightLines, lipgloss.NewStyle().Background(colorBG).Width(rightW).Render(""))
	}
	if len(rightLines) > bodyH {
		rightLines = rightLines[:bodyH]
	}

	// ── MERGE LEFT + SEP + RIGHT line by line ──
	var rows []string
	for i := 0; i < bodyH; i++ {
		left := ""
		if i < len(leftLines) {
			left = leftLines[i]
		}
		right := ""
		if i < len(rightLines) {
			right = rightLines[i]
		}
		sep := sepStyle.Render("│")
		rows = append(rows, left+sep+right)
	}

	// ── INPUT BAR (full width, bottom) ──
	var inputLine string
	if m.ChatFocusMode == 2 {
		promptSt := lipgloss.NewStyle().Foreground(colorBG).Background(colorPrimaryCont).Bold(true).Render(" ❯ ")
		inputView := m.TextInput.View()
		inputBg := lipgloss.NewStyle().Background(colorSurfaceHigh).Foreground(colorText).Render(inputView)
		inputPad := w - lipgloss.Width(promptSt) - lipgloss.Width(inputBg)
		if inputPad < 0 {
			inputPad = 0
		}
		inputLine = promptSt + inputBg + lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", inputPad))
	} else {
		promptSt := lipgloss.NewStyle().Foreground(colorGray).Background(colorSurface).Render(" ❯ ")
		inputView := m.TextInput.View()
		inputBg := lipgloss.NewStyle().Background(colorSurface).Foreground(colorGray).Render(inputView)
		inputPad := w - lipgloss.Width(promptSt) - lipgloss.Width(inputBg)
		if inputPad < 0 {
			inputPad = 0
		}
		inputLine = promptSt + inputBg + lipgloss.NewStyle().Background(colorSurface).Render(strings.Repeat(" ", inputPad))
	}
	rows = append(rows, inputLine)

	if len(rows) > h {
		rows = rows[:h]
	}
	for len(rows) < h {
		rows = append(rows, bgFill("", w))
	}

	return strings.Join(rows, "\n")
}

func (m DashboardModel) renderLogs(w, h int) string {
	if h <= 0 || w <= 0 {
		return ""
	}

	filterName := "ALL"
	switch m.LogFilter {
	case LogDebug:
		filterName = "DEBUG"
	case LogInfo:
		filterName = "INFO"
	case LogWarn:
		filterName = "WARN"
	case LogError:
		filterName = "ERROR"
	case LogSuccess:
		filterName = "SUCCESS"
	}

	title := lipgloss.NewStyle().Foreground(colorBG).Background(colorGray).Bold(true).Render(" L ") +
		lipgloss.NewStyle().Foreground(colorText).Background(colorSurface).Bold(true).Render(" OPERATIONAL LOGS ") +
		lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).Render(fmt.Sprintf("── [F] FILTER: %s ── [G] BOTTOM ", filterName))

	tw := lipgloss.Width(title)
	if tw < w {
		title = title + lipgloss.NewStyle().Foreground(colorOutline).Render(strings.Repeat("─", w-tw))
	} else if tw > w {
		title = title[:w]
	}

	vpStr := m.LogViewport.View()
	content := title + "\n" + vpStr

	return frameBuffer(content, w, h)
}

func (m DashboardModel) renderConfig(w, h int) string {
	if h <= 0 || w <= 0 {
		return ""
	}

	title := lipgloss.NewStyle().Foreground(colorBG).Background(colorGray).Bold(true).Render(" C ") +
		lipgloss.NewStyle().Foreground(colorText).Background(colorSurface).Bold(true).Render(" CONFIGURATION ") +
		lipgloss.NewStyle().Foreground(colorOutline).Background(colorBG).Render("── .aitriage.yaml ")

	tw := lipgloss.Width(title)
	if tw < w {
		title = title + lipgloss.NewStyle().Foreground(colorOutline).Render(strings.Repeat("─", w-tw))
	} else if tw > w {
		title = title[:w]
	}

	var formContent strings.Builder
	formContent.WriteString("\n")

	if m.ConfigSavedMsg != "" {
		formContent.WriteString(lipgloss.NewStyle().Foreground(colorSuccess).Render("✓ "+m.ConfigSavedMsg) + "\n\n")
	}

	formContent.WriteString("Settings are saved to .aitriage.yaml in the project root.\n\n")

	labels := []string{
		"Strict Mode (fail on any finding):",
		"Fail Score Threshold (0-100):",
		"LLM Provider (gemini/openai/anthropic):",
		"LLM Model (empty: provider default):",
	}

	for i, label := range labels {
		if i < len(m.ConfigInputs) {
			labelStyle := lipgloss.NewStyle().Foreground(colorGray).Width(40)
			if i == m.ConfigFocusIndex {
				labelStyle = labelStyle.Foreground(colorSecondary).Bold(true)
			}
			formContent.WriteString(labelStyle.Render(label) + " " + m.ConfigInputs[i].View() + "\n\n")
		}
	}

	paddedContent := lipgloss.NewStyle().Padding(1, 4).Render(formContent.String())
	content := title + "\n" + paddedContent

	return frameBuffer(content, w, h)
}

func (m DashboardModel) renderFooter(w int) string {
	if w <= 0 {
		return ""
	}
	keyStyle := lipgloss.NewStyle().Foreground(colorPrimaryCont).Background(colorSurfaceHigh).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(colorGray).Background(colorSurfaceHigh)
	sepStyle := lipgloss.NewStyle().Foreground(colorOutline).Background(colorSurfaceHigh)

	if m.SearchMode {
		v := " " + m.SearchInput.View() + " "
		vw := lipgloss.Width(v)
		if vw < w {
			v = v + lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", w-vw))
		}
		return v
	}

	// Context-sensitive footer hints per active tab
	var items []string
	switch m.ActiveView {
	case ViewBrowser:
		items = []string{
			keyStyle.Render(" ENTER ") + descStyle.Render(" OPEN "),
			keyStyle.Render(" S ") + descStyle.Render(" SCAN ") + sepStyle.Render("│") + keyStyle.Render(" BKSP ") + descStyle.Render(" BACK "),
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" NAV "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewDashboard:
		items = []string{
			keyStyle.Render(" C ") + descStyle.Render(" COPY PROMPT "),
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" 0 ") + descStyle.Render(" BROWSER "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewTriage:
		focusLabel := "TABLE"
		if m.TriageFocusDetail {
			focusLabel = "DETAIL"
		}
		items = []string{
			keyStyle.Render(" ENTER ") + descStyle.Render(" AI ANALYZE "),
			keyStyle.Render(" TAB ") + descStyle.Render(" "+focusLabel+" "),
			keyStyle.Render(" F ") + descStyle.Render(" AUTOFIX ") + sepStyle.Render("│") + keyStyle.Render(" A ") + descStyle.Render(" APPLY FIX "),
			keyStyle.Render(" I ") + descStyle.Render(" IGNORE ") + sepStyle.Render("│") + keyStyle.Render(" SHIFT+I ") + descStyle.Render(" TOGGLE VISIBILITY "),
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" NAV "),
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" L ") + descStyle.Render(" LOGS ") + sepStyle.Render("│") + keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewSAST:
		focusLabel := "TABLE"
		if m.SASTFocusDetail {
			focusLabel = "DETAIL"
		}
		items = []string{
			keyStyle.Render(" ENTER ") + descStyle.Render(" AI ANALYZE "),
			keyStyle.Render(" TAB ") + descStyle.Render(" "+focusLabel+" "),
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" NAV "),
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" L ") + descStyle.Render(" LOGS ") + sepStyle.Render("│") + keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewAudit:
		items = []string{
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewGraph:
		items = []string{
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" SCROLL "),
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewReports:
		items = []string{
			keyStyle.Render(" E ") + descStyle.Render(" EXPORT SARIF "),
			keyStyle.Render(" X ") + descStyle.Render(" EXPORT CONTEXT "),
			keyStyle.Render(" W ") + descStyle.Render(" CI/CD WORKFLOW ") + sepStyle.Render("│") + keyStyle.Render(" H ") + descStyle.Render(" GIT HOOK "),
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewConfig:
		items = []string{
			keyStyle.Render(" TAB/↑↓ ") + descStyle.Render(" NAVIGATE FIELDS "),
			keyStyle.Render(" ENTER/CTRL+S ") + descStyle.Render(" SAVE CONFIG "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewChat:
		focusLabel := "COMMANDS"
		//nolint:staticcheck // Explicit two-pane focus styling is clearer as a branch.
		if m.ChatFocusMode == 1 {
			focusLabel = "HISTORY"
		} else if m.ChatFocusMode == 2 {
			focusLabel = "INPUT"
		}
		items = []string{
			keyStyle.Render(" TAB ") + descStyle.Render(" "+focusLabel+" "),
			keyStyle.Render(" ENTER ") + descStyle.Render(" EXECUTE "),
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" NAV "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
		}
	case ViewDeps, ViewInfra:
		items = []string{
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" NAV "),
			keyStyle.Render(" / ") + descStyle.Render(" SEARCH ") + sepStyle.Render("│") + keyStyle.Render(" S ") + descStyle.Render(" SCAN "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	case ViewLogs:
		items = []string{
			keyStyle.Render(" ↑↓ ") + descStyle.Render(" SCROLL "),
			keyStyle.Render(" F ") + descStyle.Render(" FILTER ") + sepStyle.Render("│") + keyStyle.Render(" G ") + descStyle.Render(" BOTTOM "),
			keyStyle.Render(" 1-9 ") + descStyle.Render(" TABS ") + sepStyle.Render("│") + keyStyle.Render(" L ") + descStyle.Render(" LOGS "),
			keyStyle.Render(" Q ") + descStyle.Render(" QUIT "),
		}
	}

	if m.ScanInProgress {
		// Override first item with scan status
		scanIndicator := lipgloss.NewStyle().Foreground(colorBG).Background(colorPrimaryDim).Bold(true).Render(" ⟳ SCANNING... ")
		items = append([]string{scanIndicator}, items...)
	}

	// Toast notification overlay
	if m.StatusMsg != "" {
		toastStyle := lipgloss.NewStyle().
			Foreground(colorBG).
			Background(colorPrimaryDim).
			Bold(true)
		toast := toastStyle.Render(" ✓ " + m.StatusMsg + " ")
		tw := lipgloss.Width(toast)
		if tw < w {
			toast = toast + lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", w-tw))
		}
		return toast
	}

	content := sepStyle.Render("│") + strings.Join(items, sepStyle.Render("│")) + sepStyle.Render("│")

	vw := lipgloss.Width(content)
	if vw < w {
		content = content + lipgloss.NewStyle().Background(colorSurfaceHigh).Render(strings.Repeat(" ", w-vw))
	}
	return content
}

func (m DashboardModel) View() string {
	if !m.Ready || m.Width == 0 || m.Height == 0 {
		return "\n  Initializing Dashboard..."
	}

	// ── Full-screen scanning overlay ─────────────────────────────────────
	// When scan is in progress and we're coming from browser or just started,
	// show a premium Virtual Foundry loading screen instead of blank dashboard
	if m.ScanInProgress && len(m.Report.Results) == 0 {
		content := m.renderScanningOverlay(m.Width, m.Height)
		framed := frameBuffer(content, m.Width, m.Height)
		return lipgloss.Place(
			m.Width, m.Height,
			lipgloss.Left, lipgloss.Top,
			framed,
			lipgloss.WithWhitespaceBackground(colorBG),
		)
	}

	bodyHeight := m.Height - headerHeight - footerHeight
	if bodyHeight < 0 {
		bodyHeight = 0
	}

	header := m.renderHeader(m.Width, headerHeight)

	var body string
	switch m.ActiveView {
	case ViewFileViewer:
		body = bgFill(m.FileViewport.View(), m.Width)
	case ViewBrowser:
		body = m.renderBrowser(m.Width, bodyHeight)
	case ViewDashboard:
		body = m.renderDashboard(m.Width, bodyHeight)
	case ViewTriage:
		body = m.renderTriage(m.Width, bodyHeight)
	case ViewSAST:
		body = m.renderSAST(m.Width, bodyHeight)
	case ViewAudit:
		body = m.renderAudit(m.Width, bodyHeight)
	case ViewReports:
		body = m.renderReports(m.Width, bodyHeight)
	case ViewChat:
		body = m.renderChat(m.Width, bodyHeight)
	case ViewDeps:
		body = m.renderDeps(m.Width, bodyHeight)
	case ViewGraph:
		body = m.renderGraph(m.Width, bodyHeight)
	case ViewInfra:
		body = m.renderInfra(m.Width, bodyHeight)
	case ViewLogs:
		body = m.renderLogs(m.Width, bodyHeight)
	case ViewConfig:
		body = m.renderConfig(m.Width, bodyHeight)
	}

	// Footer bar with hotkey hints
	footer := m.renderFooter(m.Width)

	// Final assembly: ensures EXACTLY m.Height lines and m.Width columns.
	// First pass: frameBuffer pads/trims to exact grid dimensions.
	fullContent := header + "\n" + body + "\n" + footer
	framed := frameBuffer(fullContent, m.Width, m.Height)

	// Second pass: lipgloss.Place — the nuclear option.
	// Fills ALL remaining whitespace (right margin, bottom margin, rounding gaps)
	// with colorBG. This is how K9s achieves zero-leak via tcell cell-painting.
	return lipgloss.Place(
		m.Width, m.Height,
		lipgloss.Left, lipgloss.Top,
		framed,
		lipgloss.WithWhitespaceBackground(colorBG),
	)
}
