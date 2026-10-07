package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/dodobrands/aitriage/internal/server/repositories"
	"github.com/dodobrands/aitriage/internal/server/utils"
)

type MetricsHandler struct {
	repo *repositories.MetricsRepository
}

func NewMetricsHandler(repo *repositories.MetricsRepository) *MetricsHandler {
	return &MetricsHandler{repo: repo}
}

func (h *MetricsHandler) HandleGetDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	var metrics *repositories.DashboardMetrics
	var err error
	if value := r.URL.Query().Get("product_id"); value != "" {
		id, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || id <= 0 {
			utils.JSONError(w, "invalid product_id", http.StatusBadRequest)
			return
		}
		metrics, err = h.repo.GetProductMetrics(r.Context(), id)
	} else {
		metrics, err = h.repo.GetDashboardMetrics(r.Context())
	}
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "metrics": metrics})
}
