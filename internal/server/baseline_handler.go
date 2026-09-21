package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/scanner"
)

// A baseline accepts today's findings as the starting line so the gate judges
// only new work. It is how a team adopts AITriage on an existing codebase
// without a wall of red that nobody can act on.
//
// It existed only as a CLI command, which meant the people most likely to need
// it — those working entirely in the Web UI — could not reach it. Web, CLI and
// the AI IDE tools expose the same capability against the same
// `.aitriage-baseline.json` file, so a baseline created in one surface is
// honoured by the others.

type baselineStatusResponse struct {
	OK         bool           `json:"ok"`
	Exists     bool           `json:"exists"`
	Path       string         `json:"path"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
}

// handleBaseline serves the baseline lifecycle: inspect, create/update, clear.
func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.baselineStatus(w, r)
	case http.MethodPost:
		s.baselineWrite(w, r)
	case http.MethodDelete:
		s.baselineClear(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) baselineStatus(w http.ResponseWriter, r *http.Request) {
	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(r.URL.Query().Get("path")))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	existing, err := baseline.Load(projectPath)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to read baseline: %v", err), http.StatusInternalServerError)
		return
	}

	resp := baselineStatusResponse{
		OK:   true,
		Path: filepath.Join(projectPath, baseline.BaselineFile),
	}
	if existing != nil {
		stats := existing.Stats()
		resp.Exists = true
		resp.Total = stats.Total
		resp.BySeverity = stats.BySeverity
		resp.CreatedAt = existing.CreatedAt.Format("2006-01-02T15:04:05Z")
		resp.UpdatedAt = existing.UpdatedAt.Format("2006-01-02T15:04:05Z")
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// baselineWrite scans the project and accepts the findings it reports. Create
// and update are the same operation: both record the current state as the new
// starting line. The scan is deterministic and needs no LLM.
func (s *Server) baselineWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	// An empty body is allowed and means "the default project".
	_ = json.NewDecoder(r.Body).Decode(&req)

	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(req.Path))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	report, err := scanner.Scan(r.Context(), projectPath, scanner.ScanOptions{})
	if err != nil {
		jsonError(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	created := baseline.New(report.Results)
	if existing, loadErr := baseline.Load(projectPath); loadErr == nil && existing != nil {
		// Preserve the original creation date so the record shows how long the
		// project has been operating against a baseline.
		created.CreatedAt = existing.CreatedAt
	}

	if err := baseline.Save(projectPath, created); err != nil {
		jsonError(w, fmt.Sprintf("failed to write baseline: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Baseline written", "path", projectPath, "findings", len(created.Findings))

	stats := created.Stats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(baselineStatusResponse{
		OK:         true,
		Exists:     true,
		Path:       filepath.Join(projectPath, baseline.BaselineFile),
		Total:      stats.Total,
		BySeverity: stats.BySeverity,
		CreatedAt:  created.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  created.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

func (s *Server) baselineClear(w http.ResponseWriter, r *http.Request) {
	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(r.URL.Query().Get("path")))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	target := filepath.Join(projectPath, baseline.BaselineFile)
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		jsonError(w, fmt.Sprintf("failed to remove baseline: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Baseline cleared", "path", projectPath)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(baselineStatusResponse{OK: true, Exists: false, Path: target})
}

func requestedPathOrDefault(path string) string {
	if path == "" {
		return "."
	}
	return path
}
