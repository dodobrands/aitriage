package remedy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
)

var goSecretRegex = regexp.MustCompile(`(\w+)\s*:?=\s*"[^"]{8,}"`)
var pySecretRegex = regexp.MustCompile(`(\w+)\s*=\s*["'][^"']{8,}["']`)
var jsSecretRegex = regexp.MustCompile(`(const|let|var)\s+(\w+)\s*=\s*["'][^"']{8,}["']`)
var pyDebugRegex = regexp.MustCompile(`(?i)(DEBUG\s*=\s*)True`)
var flaskDebugRegex = regexp.MustCompile(`(?i)(app\.run\([^)]*debug\s*=\s*)True`)

// FixResult describes a single auto-fix applied to a file.
type FixResult struct {
	RuleID      string
	File        string
	Line        int
	Description string
	Applied     bool
	Err         error
}

// AutoFix runs deterministic fixers over all scan results.
// If apply=false, prints unified diffs but does not write to disk.
// If apply=true, writes changes to disk and reports what changed.
func AutoFix(report scanner.ScanReport, apply bool) []FixResult {
	var results []FixResult

	for _, r := range report.Results {
		if r.Status != core.Absent || r.File == "" {
			continue
		}

		var fr FixResult
		switch r.ID {
		case "ENTR-17", "ENTROPY-SECRET":
			fr = fixHardcodedSecret(r, apply)
		case "ENTR-18":
			fr = fixDebugMode(r, apply)
		case "FAST-SSTI":
			fr = suggestManual(r, "Use Jinja2 template variables: Template(\"Hello {{ name }}!\").render(name=username)")
		case "FAST-CORS", "FLASK-CORS":
			fr = fixMissingCORS(r, apply)
		case "ENTR-02":
			fr = fixMissingLockfile(r, apply)
		default:
			continue
		}

		results = append(results, fr)
	}

	return results
}

// fixHardcodedSecret replaces a hardcoded secret with an os.Getenv() call.
func fixHardcodedSecret(r core.CheckResult, apply bool) FixResult {
	content, err := os.ReadFile(r.File)
	if err != nil {
		return FixResult{RuleID: r.ID, File: r.File, Err: err}
	}

	lines := strings.Split(string(content), "\n")
	if r.Line < 1 || r.Line > len(lines) {
		return FixResult{RuleID: r.ID, File: r.File, Err: fmt.Errorf("line %d out of range", r.Line)}
	}

	original := lines[r.Line-1]

	// Detect language and apply appropriate env var pattern
	var fixed string
	var varName string
	switch {
	case strings.HasSuffix(r.File, ".go"):
		// Find the assignment target: `secretKey = "abc123"` → `secretKey = os.Getenv("SECRET_KEY")`
		re := goSecretRegex
		m := re.FindStringSubmatch(original)
		if m == nil {
			return suggestManual(r, "Move secret to environment variable via os.Getenv()")
		}
		varName = strings.ToUpper(m[1])
		fixed = re.ReplaceAllString(original, fmt.Sprintf(`$1 = os.Getenv("%s")`, varName))
	case strings.HasSuffix(r.File, ".py"):
		re := pySecretRegex
		m := re.FindStringSubmatch(original)
		if m == nil {
			return suggestManual(r, "Move secret to environment variable via os.environ.get()")
		}
		varName = strings.ToUpper(m[1])
		fixed = re.ReplaceAllString(original, fmt.Sprintf(`$1 = os.environ.get("%s", "")`, varName))
	case strings.HasSuffix(r.File, ".ts"), strings.HasSuffix(r.File, ".js"):
		re := jsSecretRegex
		m := re.FindStringSubmatch(original)
		if m == nil {
			return suggestManual(r, "Move secret to environment variable via process.env")
		}
		varName = strings.ToUpper(m[2])
		fixed = re.ReplaceAllString(original, fmt.Sprintf(`$1 $2 = process.env.%s`, varName))
	default:
		return suggestManual(r, "Move secret to environment variable")
	}

	diff := buildLineDiff(r.File, r.Line, original, fixed)

	if apply {
		lines[r.Line-1] = fixed
		err = os.WriteFile(r.File, []byte(strings.Join(lines, "\n")), 0644)
		if err != nil {
			return FixResult{RuleID: r.ID, File: r.File, Line: r.Line, Err: err}
		}
		// Append to .env.example
		appendEnvExample(r.File, varName)
		fmt.Printf("  ✔ Fixed %s:%d — moved %s to env\n%s\n", r.File, r.Line, varName, diff)
		return FixResult{RuleID: r.ID, File: r.File, Line: r.Line, Applied: true, Description: fmt.Sprintf("Moved %s to $%s env var", varName, varName)}
	}

	fmt.Printf("  ~ [DRY RUN] Would fix %s:%d:\n%s\n", r.File, r.Line, diff)
	return FixResult{RuleID: r.ID, File: r.File, Line: r.Line, Applied: false, Description: diff}
}

// fixDebugMode replaces debug=True with an env var pattern.
func fixDebugMode(r core.CheckResult, apply bool) FixResult {
	content, err := os.ReadFile(r.File)
	if err != nil {
		return FixResult{RuleID: r.ID, File: r.File, Err: err}
	}

	original := string(content)
	var fixed string

	switch {
	case strings.HasSuffix(r.File, ".py"):
		// Django/Flask: DEBUG = True → DEBUG = os.environ.get("DEBUG", "False") == "True"
		re := pyDebugRegex
		if !re.MatchString(original) {
			// Check app.run(debug=True)
			re2 := flaskDebugRegex
			if !re2.MatchString(original) {
				return suggestManual(r, "Replace debug=True with environment variable check")
			}
			fixed = re2.ReplaceAllString(original, `${1}os.environ.get("DEBUG", "False") == "True"`)
		} else {
			fixed = re.ReplaceAllString(original, `${1}os.environ.get("DEBUG", "False") == "True"`)
		}
	default:
		return suggestManual(r, "Replace debug mode with environment variable check")
	}

	diff := buildFileDiff(r.File, original, fixed)

	if apply {
		if err := os.WriteFile(r.File, []byte(fixed), 0644); err != nil {
			return FixResult{RuleID: r.ID, File: r.File, Err: err}
		}
		fmt.Printf("  ✔ Fixed DEBUG=True in %s\n%s\n", r.File, diff)
		return FixResult{RuleID: r.ID, File: r.File, Applied: true, Description: "Replaced DEBUG=True with env var"}
	}

	fmt.Printf("  ~ [DRY RUN] Would fix DEBUG mode in %s:\n%s\n", r.File, diff)
	return FixResult{RuleID: r.ID, File: r.File, Applied: false, Description: diff}
}

// fixMissingCORS generates a CORS middleware snippet suggestion.
func fixMissingCORS(r core.CheckResult, apply bool) FixResult {
	desc := ""
	switch {
	case strings.HasSuffix(r.File, ".py"):
		desc = "Add to main.py:\n  from fastapi.middleware.cors import CORSMiddleware\n  app.add_middleware(CORSMiddleware, allow_origins=[os.environ.get('CORS_ORIGINS','*')], allow_methods=['*'], allow_headers=['*'])"
	default:
		desc = "Add CORS middleware appropriate for your framework"
	}
	fmt.Printf("  ℹ [MANUAL] %s:%d — %s\n", r.File, r.Line, desc)
	return FixResult{RuleID: r.ID, File: r.File, Applied: false, Description: desc}
}

// fixMissingLockfile generates a lockfile creation command.
func fixMissingLockfile(r core.CheckResult, apply bool) FixResult {
	dir := r.File
	if dir == "" {
		dir = "."
	}
	desc := "Run: pip freeze > requirements.lock  (Python)\n  OR: pip install pip-tools && pip-compile requirements.in\n  OR: uv lock  (if using uv)"
	fmt.Printf("  ℹ [MANUAL] %s — %s\n", dir, desc)
	return FixResult{RuleID: r.ID, File: dir, Applied: false, Description: desc}
}

func suggestManual(r core.CheckResult, msg string) FixResult {
	fmt.Printf("  ℹ [MANUAL REVIEW] %s:%d (%s) — %s\n", r.File, r.Line, r.ID, msg)
	return FixResult{RuleID: r.ID, File: r.File, Line: r.Line, Applied: false, Description: msg}
}

func appendEnvExample(sourceFile, varName string) {
	// Walk up to find project root (directory of sourceFile or parent)
	dir := sourceFile
	idx := strings.LastIndex(dir, "/")
	if idx >= 0 {
		dir = dir[:idx]
	}
	envExample := dir + "/.env.example"
	f, err := os.OpenFile(envExample, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func() {
		_ = f.Close()
	}()
	_, _ = fmt.Fprintf(f, "%s=\n", varName)
}

func buildLineDiff(file string, line int, original, fixed string) string {
	return fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d,1 +%d,1 @@\n- %s\n+ %s",
		file, file, line, line, strings.TrimSpace(original), strings.TrimSpace(fixed))
}

func buildFileDiff(file, original, fixed string) string {
	origLines := strings.Split(original, "\n")
	fixedLines := strings.Split(fixed, "\n")
	var diff strings.Builder
	fmt.Fprintf(&diff, "--- a/%s\n+++ b/%s\n", file, file)
	for i, ol := range origLines {
		if i >= len(fixedLines) {
			fmt.Fprintf(&diff, "- %s\n", ol)
			continue
		}
		if ol != fixedLines[i] {
			fmt.Fprintf(&diff, "- %s\n+ %s\n", ol, fixedLines[i])
		}
	}
	return diff.String()
}
