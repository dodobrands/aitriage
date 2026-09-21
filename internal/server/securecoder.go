package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/server/repositories"
)

// ── SecureCoder-Compatible API Handlers ─────────────────────────────────────
//
// These endpoints implement the SecureCoder API contract so that
// Antigravity IDE (or any compatible client) can use AITriage as a
// scanner backend. All endpoints are additive — they do NOT modify
// or interfere with existing AITriage functionality.

// ── GET & POST /api/securecoder/config ────────────────────────────────────────

func (s *Server) handleSecureCoderConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	//nolint:staticcheck // Explicit GET/POST branches mirror the compatibility API contract.
	if r.Method == http.MethodGet {
		enabledStr, _ := s.configRepo.Get(ctx, "securecoder_enabled")
		backendStr, _ := s.configRepo.Get(ctx, "securecoder_scanner_backend")
		rulesetStr, _ := s.configRepo.Get(ctx, "securecoder_ruleset")
		autostartStr, _ := s.configRepo.Get(ctx, "securecoder_autostart_fixes")
		ignoreModeStr, _ := s.configRepo.Get(ctx, "securecoder_ignore_mode")
		debugStr, _ := s.configRepo.Get(ctx, "securecoder_debug")

		// Defaults
		enabled := enabledStr != "false"
		backend := backendStr
		if backend == "" {
			backend = "semgrep"
		}
		ruleset := rulesetStr
		if ruleset == "" {
			ruleset = "fast"
		}
		autostart := autostartStr != "false"
		ignoreMode := ignoreModeStr
		if ignoreMode == "" {
			ignoreMode = "workspace"
		}
		debug := debugStr == "true"

		tools := map[string]bool{
			"semgrep":  external.IsInstalled("semgrep"),
			"bandit":   external.IsInstalled("bandit"),
			"gitleaks": external.IsInstalled("gitleaks"),
			"trivy":    external.IsInstalled("trivy"),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":        enabled,
			"scannerBackend": backend,
			"ruleSet":        ruleset,
			"autostartFixes": autostart,
			"ignoreMode":     ignoreMode,
			"debug":          debug,
			"version":        "1.5.0",
			"tools":          tools,
		})
		return
	} else if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var req struct {
			Enabled        *bool   `json:"enabled"`
			ScannerBackend *string `json:"scannerBackend"`
			RuleSet        *string `json:"ruleSet"`
			AutostartFixes *bool   `json:"autostartFixes"`
			IgnoreMode     *string `json:"ignoreMode"`
			Debug          *bool   `json:"debug"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		if req.Enabled != nil {
			val := "true"
			if !*req.Enabled {
				val = "false"
			}
			_ = s.configRepo.Set(ctx, "securecoder_enabled", val)
		}
		if req.ScannerBackend != nil {
			_ = s.configRepo.Set(ctx, "securecoder_scanner_backend", *req.ScannerBackend)
		}
		if req.RuleSet != nil {
			_ = s.configRepo.Set(ctx, "securecoder_ruleset", *req.RuleSet)
		}
		if req.AutostartFixes != nil {
			val := "true"
			if !*req.AutostartFixes {
				val = "false"
			}
			_ = s.configRepo.Set(ctx, "securecoder_autostart_fixes", val)
		}
		if req.IgnoreMode != nil {
			_ = s.configRepo.Set(ctx, "securecoder_ignore_mode", *req.IgnoreMode)
		}
		if req.Debug != nil {
			val := "true"
			if !*req.Debug {
				val = "false"
			}
			_ = s.configRepo.Set(ctx, "securecoder_debug", val)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

// ── POST /api/securecoder/scan ──────────────────────────────────────────────

type secureCoderScanRequest struct {
	FilePath string `json:"filePath"`
}

type secureCoderFindingResponse struct {
	Subcategory string `json:"subcategory"`
	Message     string `json:"message"`
	Location    struct {
		Path  string `json:"path"`
		Range struct {
			TextRange struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndLine     int `json:"endLine"`
				EndColumn   int `json:"endColumn"`
			} `json:"textRange"`
		} `json:"range"`
	} `json:"location"`
	Labels struct {
		Severity           string `json:"severity"`
		CWE                string `json:"cwe"`
		Category           string `json:"category"`
		VulnerabilityClass string `json:"vulnerability_class"`
	} `json:"labels"`
}

func (s *Server) handleSecureCoderScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req secureCoderScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.FilePath == "" {
		jsonError(w, "filePath is required", http.StatusBadRequest)
		return
	}

	containerPath, err := s.resolveProjectPath(req.FilePath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	slog.Info("SecureCoder scan requested", "filePath", req.FilePath, "full", containerPath)
	ctx := r.Context()

	// Use the project directory (parent of file) for scanner context
	projectDir := filepath.Dir(containerPath)

	var findings []secureCoderFindingResponse

	// 1. Run core SAST engine on the single file
	report, err := scanner.Scan(ctx, projectDir, scanner.ScanOptions{
		FileFilter: []string{containerPath},
	})
	if err == nil {
		for _, result := range report.Results {
			f := secureCoderFindingResponse{}
			f.Subcategory = result.ID
			f.Message = result.Suggestion
			if f.Message == "" {
				f.Message = result.Name
			}
			f.Location.Path = result.File
			f.Location.Range.TextRange.StartLine = result.Line
			f.Location.Range.TextRange.EndLine = result.Line
			f.Labels.Severity = strings.ToUpper(result.Severity)
			f.Labels.CWE = result.OWASPMapping
			f.Labels.Category = "security"
			f.Labels.VulnerabilityClass = result.Name
			findings = append(findings, f)
		}
	} else {
		slog.Error("SecureCoder core scan failed", "error", err)
	}

	// 2. Run external scanners on the single file (semgrep)
	if external.IsInstalled("semgrep") {
		extFindings, err := external.RunSemgrep(ctx, projectDir, "auto")
		if err == nil {
			for _, ext := range extFindings {
				// Only include findings matching our target file
				if ext.File != containerPath && ext.File != req.FilePath {
					relPath, _ := filepath.Rel(projectDir, containerPath)
					if ext.File != relPath {
						continue
					}
				}
				f := secureCoderFindingResponse{}
				f.Subcategory = ext.RuleID
				f.Message = ext.Message
				f.Location.Path = ext.File
				f.Location.Range.TextRange.StartLine = ext.Line
				f.Location.Range.TextRange.EndLine = ext.EndLine
				f.Location.Range.TextRange.StartColumn = ext.StartColumn
				f.Location.Range.TextRange.EndColumn = ext.EndColumn
				f.Labels.Severity = strings.ToUpper(ext.Severity)
				f.Labels.CWE = ext.CWE
				f.Labels.Category = "security"
				f.Labels.VulnerabilityClass = ext.VulnerabilityClass
				findings = append(findings, f)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"findings": findings,
		"errors":   []string{},
	})
}

// ── POST /api/securecoder/ignore ────────────────────────────────────────────

func (s *Server) handleSecureCoderIgnore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req external.IgnoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.FilePath == "" || req.RuleID == "" {
		jsonError(w, "filePath and ruleId are required", http.StatusBadRequest)
		return
	}

	// Default reason
	if req.Reason == "" {
		req.Reason = "False Positive"
	}

	ctx := r.Context()
	entry := repositories.IgnoredFinding{
		RuleID:             req.RuleID,
		FilePath:           req.FilePath,
		LineNumber:         req.LineNumber,
		CodeSnippet:        req.CodeSnippet,
		VulnerabilityClass: req.VulnerabilityClass,
		Reason:             req.Reason,
	}

	result, err := s.ignoreRepo.Create(ctx, entry)
	if err != nil {
		slog.Error("Failed to create ignored finding", "error", err)
		jsonError(w, "failed to ignore finding", http.StatusInternalServerError)
		return
	}

	// Also update the finding status in the findings table if it exists
	_, _ = s.db.ExecContext(ctx,
		`UPDATE findings SET status = ?, is_false_positive = ?, fp_reason = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE rule_id = ? AND file_path = ? AND status NOT IN ('triage')`,
		mapReasonToStatus(req.Reason), boolToInt(req.Reason == "False Positive"),
		req.Reason, req.RuleID, req.FilePath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(external.IgnoreResponse{
		Success:     true,
		VulnID:      result.VulnID,
		ContentHash: result.ContentHash,
	})
}

// ── GET /api/securecoder/ignored ─────────────────────────────────────────────

func (s *Server) handleSecureCoderIgnored(w http.ResponseWriter, r *http.Request) {
	//nolint:staticcheck // Explicit GET/non-GET branches keep response handling adjacent.
	if r.Method == http.MethodGet {
		entries, err := s.ignoreRepo.List(r.Context())
		if err != nil {
			slog.Error("Failed to list ignored findings", "error", err)
			jsonError(w, "failed to list ignored findings", http.StatusInternalServerError)
			return
		}

		apiEntries := make([]external.IgnoreEntry, 0, len(entries))
		for _, e := range entries {
			apiEntries = append(apiEntries, external.IgnoreEntry{
				VulnID:      e.VulnID,
				RuleID:      e.RuleID,
				FilePath:    e.FilePath,
				ContentHash: e.ContentHash,
				Reason:      e.Reason,
				Timestamp:   e.CreatedAt.UnixMilli(),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": apiEntries,
		})
		return
	} else if r.Method == http.MethodDelete {
		vulnID := r.URL.Query().Get("vulnId")
		ctx := r.Context()
		if vulnID != "" {
			err := s.ignoreRepo.Delete(ctx, vulnID)
			if err != nil {
				slog.Error("Failed to delete ignored finding", "vulnId", vulnID, "error", err)
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			err := s.ignoreRepo.ClearAll(ctx)
			if err != nil {
				slog.Error("Failed to clear all ignored findings", "error", err)
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

// ── POST /api/securecoder/fix_completed ──────────────────────────────────────

func (s *Server) handleSecureCoderFixCompleted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FindingsCountBefore     int    `json:"findingsCountBefore"`
		FindingsCountAfter      int    `json:"findingsCountAfter"`
		FindingsByFiletypeAfter string `json:"findingsByFiletypeAfter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	fixed := req.FindingsCountBefore - req.FindingsCountAfter
	slog.Info("SecureCoder fix completed",
		"before", req.FindingsCountBefore,
		"after", req.FindingsCountAfter,
		"fixed", fixed,
		"byFiletype", req.FindingsByFiletypeAfter)

	// Create audit log entry
	ctx := r.Context()
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO audit_log (action, entity_type, old_value, new_value, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, "securecoder_fix_completed", "remediation",
		fmt.Sprintf("%d findings", req.FindingsCountBefore),
		fmt.Sprintf("%d findings remaining (%d fixed). By filetype: %s", req.FindingsCountAfter, fixed, req.FindingsByFiletypeAfter),
		time.Now())

	// Create notification
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO notifications (user_id, title, body, type)
		SELECT id, ?, ?, 'success' FROM users WHERE global_role IN ('superadmin', 'admin') LIMIT 1
	`, "SecureCoder Remediation Complete",
		fmt.Sprintf("Fixed %d of %d findings. %d remaining.", fixed, req.FindingsCountBefore, req.FindingsCountAfter))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    true,
		"fixed": fixed,
	})
}

// ── POST /api/securecoder/dependency/scan ───────────────────────────────────

func (s *Server) handleSecureCoderDepScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Registry string                       `json:"registry"`
		Packages []external.DepPackageRequest `json:"packages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Registry == "" || len(req.Packages) == 0 {
		jsonError(w, "registry and packages are required", http.StatusBadRequest)
		return
	}

	// Validate registry
	validRegistries := map[string]bool{
		"npm": true, "pypi": true, "gomodproxy": true,
		"rubygems": true, "crates.io": true, "maven": true, "nuget": true,
	}
	if !validRegistries[req.Registry] {
		jsonError(w, fmt.Sprintf("unsupported registry: %s. Valid: npm, pypi, gomodproxy, rubygems, crates.io, maven, nuget", req.Registry), http.StatusBadRequest)
		return
	}

	slog.Info("SecureCoder dependency scan", "registry", req.Registry, "packages", len(req.Packages))

	// First try to proxy to SecureCoder if it's running
	ctx := r.Context()
	if external.IsSecureCoderRunning() {
		findings, err := external.RunSecureCoderDeps(ctx, req.Registry, req.Packages)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"unsafeDependencies": findings,
			})
			return
		}
		slog.Warn("SecureCoder dep scan proxy failed, using built-in", "error", err)
	}

	// Built-in basic dependency checking using deps.dev API
	unsafeDeps, err := external.QueryDepsDev(ctx, req.Registry, req.Packages)
	if err != nil {
		slog.Error("Native deps.dev scan failed", "error", err)
		unsafeDeps = []external.DepFinding{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"unsafeDependencies": unsafeDeps,
	})
}

// ── POST /api/securecoder/scan-directory ─────────────────────────────────────
// Bonus: Full directory scan using SecureCoder-compatible response format

func (s *Server) handleSecureCoderScanDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path         string `json:"path"`
		External     bool   `json:"external,omitempty"`
		ProbeNetwork bool   `json:"probe_network,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	containerPath, err := s.resolveProjectPath(req.Path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	ctx := r.Context()
	rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
		ProjectPath: containerPath,
		RunExternal: req.External,
		// No implicit port scan of the host: see requestedProbeHost.
		ProbeHost: requestedProbeHost(req.ProbeNetwork),
	})

	var findings []secureCoderFindingResponse
	for _, result := range rich.Report.Results {
		f := secureCoderFindingResponse{}
		f.Subcategory = result.ID
		f.Message = result.Suggestion
		if f.Message == "" {
			f.Message = result.Name
		}
		f.Location.Path = result.File
		f.Location.Range.TextRange.StartLine = result.Line
		f.Location.Range.TextRange.EndLine = result.Line
		f.Labels.Severity = strings.ToUpper(result.Severity)
		f.Labels.CWE = result.OWASPMapping
		f.Labels.Category = "security"
		f.Labels.VulnerabilityClass = result.Name
		findings = append(findings, f)
	}

	for _, ext := range rich.External {
		f := secureCoderFindingResponse{}
		f.Subcategory = ext.RuleID
		f.Message = ext.Message
		f.Location.Path = ext.File
		f.Location.Range.TextRange.StartLine = ext.Line
		f.Location.Range.TextRange.EndLine = ext.EndLine
		f.Labels.Severity = strings.ToUpper(ext.Severity)
		f.Labels.CWE = ext.CWE
		f.Labels.Category = "security"
		f.Labels.VulnerabilityClass = ext.VulnerabilityClass
		findings = append(findings, f)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"findings": findings,
		"errors":   []string{},
	})
}

// ── Wiz Authentication Endpoints ─────────────────────────────────────────────

func (s *Server) handleWizStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	status, err := external.WizAuthStatus()
	if err != nil {
		slog.Error("Wiz auth status failed", "error", err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) handleWizLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, err := external.StartWizAuth(r.Context())
	if err != nil {
		slog.Error("Wiz start auth failed", "error", err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(session)
}

func (s *Server) handleWizLoginPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session := external.GetActiveLoginSession()
	w.Header().Set("Content-Type", "application/json")
	if session == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "none"})
		return
	}
	_ = json.NewEncoder(w).Encode(session)
}

func (s *Server) handleWizLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	err := external.WizLogout()
	if err != nil {
		slog.Error("Wiz logout failed", "error", err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// ── Ignore File Editor Endpoints ─────────────────────────────────────────────

func (s *Server) handleSecureCoderIgnoreFile(w http.ResponseWriter, r *http.Request) {
	ignoreDir := filepath.Join(os.Getenv("HOME"), ".securecoder")
	ignorePath := filepath.Join(ignoreDir, ".securecoderignore")

	//nolint:staticcheck // Explicit read/write branches keep filesystem effects obvious.
	if r.Method == http.MethodGet {
		if _, err := os.Stat(ignorePath); os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"content": ""})
			return
		}
		content, err := os.ReadFile(ignorePath)
		if err != nil {
			slog.Error("Failed to read ignore file", "error", err)
			jsonError(w, "failed to read ignore file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"content": string(content)})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(ignoreDir, 0755); err != nil {
			slog.Error("Failed to create securecoder directory", "error", err)
			jsonError(w, "failed to create directory", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(ignorePath, []byte(req.Content), 0644); err != nil {
			slog.Error("Failed to write ignore file", "error", err)
			jsonError(w, "failed to write ignore file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func mapReasonToStatus(reason string) string {
	switch reason {
	case "False Positive":
		return "false_positive"
	case "Accepted Risk", "Won't Fix":
		return "risk_accepted"
	default:
		return "false_positive"
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Ensure context import is used (for future extensions)
var _ context.Context
