package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/suppression"
	"github.com/dodobrands/aitriage/internal/server/middleware"
)

// The Web UI recorded dismissals in its own SQLite table, which no other surface
// can read: the CLI has no database, and an IDE agent talks to a different
// process entirely. A false positive marked here stayed marked only here.
//
// These endpoints write the shared project file, so a decision made in the
// browser is visible from the terminal and to an agent. The existing
// /api/securecoder/ignore* endpoints keep working for the dashboard's own state;
// this is the portable record that travels with the repository.

type suppressionEntryDTO struct {
	Fingerprint string `json:"fingerprint"`
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Reason      string `json:"reason"`
	Note        string `json:"note,omitempty"`
	Author      string `json:"author,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type suppressionListResponse struct {
	OK            bool                  `json:"ok"`
	Path          string                `json:"path"`
	Total         int                   `json:"total"`
	CountByReason map[string]int        `json:"count_by_reason"`
	Entries       []suppressionEntryDTO `json:"entries"`
}

// handleSuppressions serves the portable dismissal record: list, add, remove.
func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.suppressionList(w, r)
	case http.MethodPost:
		s.suppressionAdd(w, r)
	case http.MethodDelete:
		s.suppressionRemove(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) suppressionList(w http.ResponseWriter, r *http.Request) {
	projectPath, store, err := s.loadSuppressions(r.URL.Query().Get("path"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeSuppressionList(w, projectPath, store)
}

func (s *Server) suppressionAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string `json:"path"`
		Source   string `json:"source"`
		RuleID   string `json:"rule_id"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		Evidence string `json:"evidence"`
		Severity string `json:"severity"`
		Reason   string `json:"reason"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.RuleID == "" {
		jsonError(w, "rule_id is required", http.StatusBadRequest)
		return
	}

	projectPath, store, err := s.loadSuppressions(req.Path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	item := baseline.Item{
		Source: req.Source,
		RuleID: req.RuleID,
		// Relative to the project: the record is committed and must mean the
		// same thing on every machine.
		File:     baseline.RelativePath(projectPath, req.File),
		Line:     req.Line,
		Severity: req.Severity,
		Evidence: req.Evidence,
	}
	entry, _, err := store.Add(item, req.Reason, req.Note, usernameFromRequest(r))
	if err != nil {
		// A rejected reason or a missing justification is the caller's mistake,
		// not a server fault.
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := suppression.Save(projectPath, store); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Finding dismissed", "rule", entry.RuleID, "source", entry.Source, "reason", entry.Reason)
	writeSuppressionList(w, projectPath, store)
}

func (s *Server) suppressionRemove(w http.ResponseWriter, r *http.Request) {
	identifier := r.URL.Query().Get("id")
	if identifier == "" {
		jsonError(w, "id (rule id or fingerprint) is required", http.StatusBadRequest)
		return
	}

	projectPath, store, err := s.loadSuppressions(r.URL.Query().Get("path"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if removed := store.Remove(identifier); removed == 0 {
		jsonError(w, fmt.Sprintf("no dismissal matches %q", identifier), http.StatusNotFound)
		return
	}
	if err := suppression.Save(projectPath, store); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeSuppressionList(w, projectPath, store)
}

func (s *Server) loadSuppressions(requestedPath string) (string, *suppression.Store, error) {
	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(requestedPath))
	if err != nil {
		return "", nil, err
	}
	store, err := suppression.Load(projectPath)
	if err != nil {
		return "", nil, err
	}
	return projectPath, store, nil
}

func writeSuppressionList(w http.ResponseWriter, projectPath string, store *suppression.Store) {
	entries := store.List()
	dto := make([]suppressionEntryDTO, 0, len(entries))
	for _, entry := range entries {
		dto = append(dto, suppressionEntryDTO{
			Fingerprint: entry.Fingerprint,
			Source:      entry.Source,
			RuleID:      entry.RuleID,
			File:        entry.File,
			Severity:    entry.Severity,
			Reason:      entry.Reason,
			Note:        entry.Note,
			Author:      entry.Author,
			CreatedAt:   entry.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(suppressionListResponse{
		OK:            true,
		Path:          projectPath + "/" + suppression.File,
		Total:         len(dto),
		CountByReason: store.CountByReason(),
		Entries:       dto,
	})
}

// usernameFromRequest records who made the decision. It is best-effort: an
// unattributed decision is better than none.
func usernameFromRequest(r *http.Request) string {
	claims, err := middleware.ExtractClaims(r)
	if err != nil || claims == nil {
		return ""
	}
	return claims.Username
}
