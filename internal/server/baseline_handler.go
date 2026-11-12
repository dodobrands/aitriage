package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
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
// fail. The Web UI then keeps the baseline it manages under the reports
// directory, at a path that mirrors the scanned folder, and still honours the
// project's own file — committed with the repository or written by
// `aitriage baseline` — whenever it has no copy of its own.

// webBaselinesDir is the folder under the reports directory that holds the
// baselines the Web UI writes when the project itself is read-only.
const webBaselinesDir = "baselines"

type baselineStatusResponse struct {
	OK         bool           `json:"ok"`
	Exists     bool           `json:"exists"`
	Path       string         `json:"path"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
	// ReadOnly reports that the baseline in effect is the project's own file,
	// which this server cannot change or remove. Updating writes a copy that
	// takes precedence; changing the file itself is done from a terminal.
	ReadOnly bool `json:"read_only,omitempty"`
}

// webBaselineStore is where the Web UI keeps the baseline of one scanned folder.
type webBaselineStore struct {
	// projectDir is the scanned folder. Its own .aitriage-baseline.json is the
	// file the CLI and the IDE tools read and write.
	projectDir string
	// writeDir receives .aitriage-baseline.json on create and update and loses
	// it on clear. It is projectDir unless the project is mounted read-only.
	writeDir string
}

// webBaseline resolves where the baseline for projectPath is read and written.
func (s *Server) webBaseline(projectPath string) webBaselineStore {
	store := webBaselineStore{projectDir: projectPath, writeDir: projectPath}
	if os.Getenv("AITRIAGE_RUNTIME") != "container" {
		return store
	}
	reports := strings.TrimSpace(os.Getenv("AITRIAGE_REPORTS_DIR"))
	rel, ok := s.projectRelativeDir(projectPath)
	if reports == "" || !ok {
		// Without a reports directory there is nowhere else to write; the
		// attempt on the project fails and the error says why.
		return store
	}
	store.writeDir = filepath.Join(reports, webBaselinesDir, rel)
	return store
}

// effectiveBaselineDir is the folder whose baseline a Web scan of projectPath
// applies.
func (s *Server) effectiveBaselineDir(projectPath string) string {
	return s.webBaseline(projectPath).readDir()
}

// projectRelativeDir expresses a resolved project path relative to the opened
// project root, so baselines of different folders never share a file.
func (s *Server) projectRelativeDir(projectPath string) (string, bool) {
	if s.hostPrefix == "" {
		return "", false
	}
	root, err := filepath.Abs(s.hostPrefix)
	if err != nil {
		return "", false
	}
	if resolved, resolveErr := filepath.EvalSymlinks(root); resolveErr == nil {
		root = resolved
	}
	rel, err := filepath.Rel(root, projectPath)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// readDir returns the folder whose baseline applies: the Web UI's own copy
// when there is one, otherwise the project's file.
func (st webBaselineStore) readDir() string {
	if st.writeDir == st.projectDir {
		return st.projectDir
	}
	_, err := os.Stat(filepath.Join(st.writeDir, baseline.BaselineFile))
	if err == nil || !os.IsNotExist(err) {
		// Present, or present but unreadable: either way the load must see it
		// and report, rather than silently fall back to another file.
		return st.writeDir
	}
	return st.projectDir
}

func (st webBaselineStore) writeFile() string {
	return filepath.Join(st.writeDir, baseline.BaselineFile)
}

// prepare creates the mirrored folder under the reports directory. The
// project folder is never created: it exists, or the request was wrong.
func (st webBaselineStore) prepare() error {
	if st.writeDir == st.projectDir {
		return nil
	}
	return os.MkdirAll(st.writeDir, 0o700)
}

func describeBaseline(b *baseline.Baseline, file string, readOnly bool) baselineStatusResponse {
	stats := b.Stats()
	return baselineStatusResponse{
		OK:         true,
		Exists:     true,
		Path:       file,
		Total:      stats.Total,
		BySeverity: stats.BySeverity,
		CreatedAt:  b.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  b.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		ReadOnly:   readOnly,
	}
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

	store := s.webBaseline(projectPath)
	dir := store.readDir()
	existing, err := baseline.Load(dir)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to read baseline: %v", err), http.StatusInternalServerError)
		return
	}

	resp := baselineStatusResponse{OK: true, Path: store.writeFile()}
	if existing != nil {
		resp = describeBaseline(existing, filepath.Join(dir, baseline.BaselineFile), dir != store.writeDir)
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
	store := s.webBaseline(projectPath)

	// Run every scanner that is available, so the baseline covers what the
	// project actually reports rather than only the built-in engine's share.
	rich := orchestrator.RunAllScanners(r.Context(), orchestrator.Options{
		ProjectPath: projectPath,
		RunExternal: true,
	})

	created := baseline.NewFromItems(orchestrator.BaselineItems(&rich))
	if existing, loadErr := baseline.Load(store.readDir()); loadErr == nil && existing != nil {
		// Preserve the original creation date so the record shows how long the
		// project has been operating against a baseline.
		created.CreatedAt = existing.CreatedAt
	}

	if err := store.prepare(); err != nil {
		jsonError(w, fmt.Sprintf("failed to write baseline: %v", err), http.StatusInternalServerError)
		return
	}
	if err := baseline.Save(store.writeDir, created); err != nil {
		jsonError(w, fmt.Sprintf("failed to write baseline: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Baseline written", "path", store.writeFile(), "findings", len(created.Findings))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(describeBaseline(created, store.writeFile(), false))
}

func (s *Server) baselineClear(w http.ResponseWriter, r *http.Request) {
	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(r.URL.Query().Get("path")))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	store := s.webBaseline(projectPath)
	target := store.writeFile()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		jsonError(w, fmt.Sprintf("failed to remove baseline: %v", err), http.StatusInternalServerError)
		return
	}
	slog.Info("Baseline cleared", "path", target)

	resp := baselineStatusResponse{OK: true, Exists: false, Path: target}
	// A read-only project's own baseline cannot be removed from here and keeps
	// applying. Report it rather than claim that no baseline is left.
	if dir := store.readDir(); dir != store.writeDir {
		if remaining, loadErr := baseline.Load(dir); loadErr == nil && remaining != nil {
			resp = describeBaseline(remaining, filepath.Join(dir, baseline.BaselineFile), true)
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
