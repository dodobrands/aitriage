package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/engine/statefile"
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
//
// The container runtime is the exception. It mounts the project read-only at
// /workspace and only <project>/aitriage-reports read-write
// (internal/runtime.DockerRunArgs), so writing the project file there can only
// fail. The baseline the Web UI writes then goes to a local copy under the
// reports directory, at a path that mirrors the scanned folder. The project's
// own file — committed with the repository or written by `aitriage baseline`
// — keeps applying alongside it: a finding accepted in either is accepted
// (baseline.LoadAt). The IDE tools in the container use the same location.

type baselineStatusResponse struct {
	OK         bool           `json:"ok"`
	Exists     bool           `json:"exists"`
	Path       string         `json:"path"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
	// ReadOnly reports that the baseline in effect is only the project's own
	// file, which this server cannot change or remove. Updating writes a local
	// copy that applies on top of it; the file itself is changed from a
	// terminal.
	ReadOnly bool `json:"read_only,omitempty"`
	// Note explains a local copy in effect: its findings are accepted in
	// addition to the project's, and only reach CI once committed.
	Note string `json:"note,omitempty"`
}

// describeBaseline reports b, the baseline that applies at loc.
func describeBaseline(b *baseline.Baseline, loc statefile.Location) baselineStatusResponse {
	stats := b.Stats()
	resp := baselineStatusResponse{
		OK:         true,
		Exists:     true,
		Path:       loc.CurrentFile(),
		Total:      stats.Total,
		BySeverity: stats.BySeverity,
		CreatedAt:  b.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  b.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		ReadOnly:   loc.Redirected() && !loc.HasCopy(),
	}
	if loc.HasCopy() {
		resp.Note = statefile.LocalOverrideNote
	}
	return resp
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

	loc := baseline.Locate(projectPath)
	existing, err := baseline.LoadAt(loc)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to read baseline: %v", err), http.StatusInternalServerError)
		return
	}

	resp := baselineStatusResponse{OK: true, Path: loc.WriteFile()}
	if existing != nil {
		resp = describeBaseline(existing, loc)
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
	loc := baseline.Locate(projectPath)

	// Run every scanner that is available, so the baseline covers what the
	// project actually reports rather than only the built-in engine's share.
	rich := orchestrator.RunAllScanners(r.Context(), orchestrator.Options{
		ProjectPath: projectPath,
		RunExternal: true,
	})

	created := baseline.NewFromItems(orchestrator.BaselineItems(&rich))
	if existing, loadErr := baseline.LoadAt(loc); loadErr == nil && existing != nil {
		// Preserve the original creation date so the record shows how long the
		// project has been operating against a baseline.
		created.CreatedAt = existing.CreatedAt
	}

	if err := baseline.SaveAt(loc, created); err != nil {
		// The error already says the baseline could not be written.
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Baseline written", "path", loc.WriteFile(), "findings", len(created.Findings))

	// In the container the project's own baseline keeps applying next to the
	// copy just written, so report what applies now.
	applied := created
	if merged, loadErr := baseline.LoadAt(loc); loadErr == nil && merged != nil {
		applied = merged
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(describeBaseline(applied, loc))
}

func (s *Server) baselineClear(w http.ResponseWriter, r *http.Request) {
	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(r.URL.Query().Get("path")))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	loc := baseline.Locate(projectPath)
	target := loc.WriteFile()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		jsonError(w, fmt.Sprintf("failed to remove baseline: %v", err), http.StatusInternalServerError)
		return
	}
	slog.Info("Baseline cleared", "path", target)

	resp := baselineStatusResponse{OK: true, Exists: false, Path: target}
	// A read-only project's own baseline cannot be removed from here and keeps
	// applying. Report it rather than claim that no baseline is left.
	if loc.Redirected() {
		if remaining, loadErr := baseline.LoadAt(loc); loadErr == nil && remaining != nil {
			resp = describeBaseline(remaining, loc)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func requestedPathOrDefault(path string) string {
	if path == "" {
		return "."
	}
	return path
}
