package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/server/repositories"
	"github.com/dodobrands/aitriage/internal/server/utils"
)

type FindingHandler struct {
	repo *repositories.FindingRepository
}

func NewFindingHandler(repo *repositories.FindingRepository) *FindingHandler {
	return &FindingHandler{repo: repo}
}

func (h *FindingHandler) HandleListFindings(w http.ResponseWriter, r *http.Request) {
	var findings []models.Finding
	var err error
	if value := r.URL.Query().Get("engagement_id"); value != "" {
		id, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || id <= 0 {
			utils.JSONError(w, "invalid engagement_id", http.StatusBadRequest)
			return
		}
		findings, err = h.repo.List(r.Context(), id)
	} else if value := r.URL.Query().Get("product_id"); value != "" {
		id, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || id <= 0 {
			utils.JSONError(w, "invalid product_id", http.StatusBadRequest)
			return
		}
		findings, err = h.repo.ListByProductID(r.Context(), id)
	} else {
		findings, err = h.repo.ListAll(r.Context())
	}
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if findings == nil {
		findings = []models.Finding{}
	}
	utils.JSONResponse(w, map[string]any{"findings": findings, "ok": true})
}

func (h *FindingHandler) HandleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/findings/"), "/")
	if len(parts) != 1 || parts[0] == "" {
		utils.JSONError(w, "missing finding id", http.StatusBadRequest)
		return
	}
	findingID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || findingID <= 0 {
		utils.JSONError(w, "invalid finding id", http.StatusBadRequest)
		return
	}

	var req struct {
		Action       string `json:"action"`        // "status" or "kanban"
		Status       string `json:"status"`        // e.g. "open", "in_progress", "fixed"
		KanbanColumn string `json:"kanban_column"` // e.g. "backlog", "todo", "in_progress", "done"
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		utils.JSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var updateErr error
	switch req.Action {
	case "status":
		status, valid := models.NormalizeFindingStatus(req.Status)
		if !valid {
			utils.JSONError(w, "invalid finding status", http.StatusBadRequest)
			return
		}
		updateErr = h.repo.UpdateStatus(r.Context(), findingID, status)
	case "kanban":
		switch req.KanbanColumn {
		case "backlog", "todo", "in_progress", "review", "done":
		default:
			utils.JSONError(w, "invalid kanban column", http.StatusBadRequest)
			return
		}
		updateErr = h.repo.UpdateKanbanColumn(r.Context(), findingID, req.KanbanColumn)
	default:
		utils.JSONError(w, "invalid action", http.StatusBadRequest)
		return
	}
	if errors.Is(updateErr, sql.ErrNoRows) {
		utils.JSONError(w, "finding not found", http.StatusNotFound)
		return
	}
	if updateErr != nil {
		utils.JSONError(w, "failed to update finding", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
