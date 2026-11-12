package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/statefile"
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
//
// In the container runtime the project is mounted read-only, so decisions are
// written to a local copy under the reports directory instead. Every scan in
// the container applies that copy on top of the project's own file
// (suppression.LoadAt): local entries win for the same finding and stay in
// force after the project drops its own. The copy reaches CI only once it is
// copied into the project and committed, and a decision that lives in the
// project's file can only be undone there.

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
	// Note explains a local copy in effect and anything a removal could not
	// undo.
	Note string `json:"note,omitempty"`
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
	record, err := s.openSuppressions(r.URL.Query().Get("path"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeSuppressionList(w, record, "")
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
		// RuleWide must be set to record a dismissal that is not tied to a
		// file; such a decision covers the rule across the whole project.
		RuleWide bool `json:"rule_wide"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.RuleID == "" {
		jsonError(w, "rule_id is required", http.StatusBadRequest)
		return
	}

	record, err := s.openSuppressions(req.Path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	item := baseline.Item{
		Source: req.Source,
		RuleID: req.RuleID,
		// Relative to the project: the record is committed and must mean the
		// same thing on every machine.
		File:     baseline.RelativePath(record.Location.ProjectDir, req.File),
		Line:     req.Line,
		Severity: req.Severity,
		Evidence: req.Evidence,
	}
	if err := suppression.ValidateScope(item, req.RuleWide); err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	entry, _, err := record.Add(item, req.Reason, req.Note, usernameFromRequest(r))
	if err != nil {
		// A rejected reason or a missing justification is the caller's mistake,
		// not a server fault.
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := record.Save(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Finding dismissed", "rule", entry.RuleID, "source", entry.Source, "reason", entry.Reason, "path", record.Location.WriteFile())
	writeSuppressionList(w, record, "This dismissal "+suppression.DescribeScope(item)+".")
}

func (s *Server) suppressionRemove(w http.ResponseWriter, r *http.Request) {
	identifier := r.URL.Query().Get("id")
	if identifier == "" {
		jsonError(w, "id (rule id or fingerprint) is required", http.StatusBadRequest)
		return
	}

	record, err := s.openSuppressions(r.URL.Query().Get("path"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	removed, committed := record.Remove(identifier)
	switch {
	case removed == 0 && committed > 0:
		jsonError(w, committedDecisionMessage(identifier), http.StatusConflict)
		return
	case removed == 0:
		jsonError(w, fmt.Sprintf("no dismissal matches %q", identifier), http.StatusNotFound)
		return
	}
	if err := record.Save(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	note := ""
	if committed > 0 {
		note = committedDecisionMessage(identifier)
	}
	writeSuppressionList(w, record, note)
}

// committedDecisionMessage explains why a decision cannot be undone from the
// container: it is recorded in the project's own file, which is read-only
// there.
func committedDecisionMessage(identifier string) string {
	return fmt.Sprintf("%q is still dismissed by the project's own %s, which is read-only here; remove it there and commit the change", identifier, suppression.File)
}

// openSuppressions reads the dismissals of the requested folder.
func (s *Server) openSuppressions(requestedPath string) (*suppression.Record, error) {
	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(requestedPath))
	if err != nil {
		return nil, err
	}
	return suppression.Open(suppression.Locate(projectPath))
}

// writeSuppressionList reports the dismissals that apply, the file they are
// recorded in and, in the container runtime, how the local copy relates to
// the project's own file.
func writeSuppressionList(w http.ResponseWriter, record *suppression.Record, note string) {
	store := record.Applied
	if record.Location.HasCopy() {
		note = strings.TrimSpace(note + " " + statefile.LocalOverrideNote)
	}
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
		Path:          record.Location.CurrentFile(),
		Total:         len(dto),
		CountByReason: store.CountByReason(),
		Entries:       dto,
		Note:          note,
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
