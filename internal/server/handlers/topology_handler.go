package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dodobrands/aitriage/internal/server/repositories"
)

type TopologyResponse struct {
	Ok    bool                        `json:"ok"`
	Nodes []repositories.TopologyNode `json:"nodes"`
	Links []repositories.TopologyLink `json:"links"`
}

type TopologyHandler struct {
	repo *repositories.TopologyRepository
}

func NewTopologyHandler(repo *repositories.TopologyRepository) *TopologyHandler {
	return &TopologyHandler{repo: repo}
}

func (h *TopologyHandler) HandleGetTopology(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.repo.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	links, err := h.repo.ListLinks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Note: We no longer seed fake topology data here.
	// If the database is empty, we return empty arrays so the dashboard reflects the clean state.
	if len(nodes) == 0 {
		nodes = []repositories.TopologyNode{}
		links = []repositories.TopologyLink{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TopologyResponse{
		Ok:    true,
		Nodes: nodes,
		Links: links,
	})
}
