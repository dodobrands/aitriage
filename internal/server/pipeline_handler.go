package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
	"github.com/dodobrands/aitriage/internal/models"
)

// handlePipeline exposes the canonical Runway/CI graph as an SSE stream for
// the advanced Web view. The scan keeps running if the browser disconnects;
// its durable session and artifacts can still be opened from Runway History.
func (s *Server) handlePipeline(w http.ResponseWriter, r *http.Request) {
	if s.llmClient == nil {
		jsonError(w, llmUnavailableMessage, http.StatusServiceUnavailable)
		return
	}

	productID, err := strconv.ParseInt(r.URL.Query().Get("product_id"), 10, 64)
	if err != nil || productID <= 0 {
		jsonError(w, "valid product_id is required", http.StatusBadRequest)
		return
	}
	product, err := s.productRepo.GetByID(r.Context(), productID)
	if err != nil || product == nil {
		jsonError(w, "product not found", http.StatusNotFound)
		return
	}
	findings, err := s.findingRepo.ListByProductID(r.Context(), productID)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to load findings: %v", err), http.StatusInternalServerError)
		return
	}
	if len(findings) == 0 {
		jsonError(w, "No findings found for this product. Run a scan first.", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sendSSE := func(data any) {
		jsonBytes, marshalErr := json.Marshal(data)
		if marshalErr != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonBytes)
		flusher.Flush()
	}

	session := &models.RunwaySession{
		ProductID: productID,
		Status:    "in_progress",
		AutoMode:  true,
	}
	if err := s.runwayRepo.Create(r.Context(), session); err != nil {
		sendSSE(map[string]any{"error": fmt.Sprintf("failed to create Runway session: %v", err)})
		return
	}

	slog.Info("Canonical Web pipeline started", "product_id", productID, "session_id", session.ID, "findings_count", len(findings))
	sendSSE(map[string]any{
		"session_id": session.ID,
		"step":       0,
		"total":      7,
		"label":      "Preparing repository context…",
		"progress":   2,
	})
	go s.runRunwaySession(session, product, findings, prompts.NormalizeLanguage(r.URL.Query().Get("lang")))

	ticker := time.NewTicker(450 * time.Millisecond)
	defer ticker.Stop()
	lastSignature := ""
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			current, getErr := s.runwayRepo.GetByID(r.Context(), session.ID)
			if getErr != nil {
				sendSSE(map[string]any{"session_id": session.ID, "error": "Runway session became unavailable"})
				return
			}

			progressMessage := ""
			if current.ProgressMessage != nil {
				progressMessage = *current.ProgressMessage
			}
			signature := fmt.Sprintf("%s:%d:%s", current.Status, current.CurrentStep, progressMessage)
			if signature != lastSignature {
				lastSignature = signature
				sendSSE(map[string]any{
					"session_id": current.ID,
					"step":       current.CurrentStep,
					"total":      7,
					"label":      pipelineStageLabel(progressMessage, current.CurrentStep),
					"progress":   pipelineProgress(current.CurrentStep, current.Status),
				})
			}

			switch current.Status {
			case "completed":
				stats := s.pipelineStats(current.ID, len(findings))
				sendSSE(map[string]any{
					"done":       true,
					"session_id": current.ID,
					"progress":   100,
					"stats":      stats,
					"report":     stringValue(current.AuditReport),
					"fix_spec":   stringValue(current.Remediation),
					"usage": map[string]int{
						"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
					},
				})
				return
			case "failed":
				sendSSE(map[string]any{
					"session_id": current.ID,
					"error":      stringValue(current.ErrorMessage),
				})
				return
			}
		}
	}
}

func (s *Server) pipelineStats(sessionID int64, fallbackTotal int) map[string]int {
	stats := map[string]int{"tp": 0, "fp": 0, "nr": 0, "poc": 0, "total": fallbackTotal}
	artifact, err := s.runwayArtifactRepo.Get(context.Background(), sessionID, models.RunwayArtifactAgentDataJSON)
	if err != nil || artifact == nil {
		return stats
	}
	var data graph.AIAgentData
	if err := json.Unmarshal([]byte(artifact.Content), &data); err != nil {
		return stats
	}
	stats["tp"] = data.Stats.TruePositives
	stats["fp"] = data.Stats.FalsePositives
	stats["nr"] = data.Stats.NeedsReview
	stats["total"] = data.Stats.Total
	return stats
}

func pipelineStageLabel(progressMessage string, step int) string {
	labels := map[string]string{
		"preparing_context":      "Preparing repository context…",
		"building_threat_model":  "Building threat model and dispositions…",
		"verifying_poc":          "Verifying exploitability…",
		"computing_health_check": "Computing policy gate and health score…",
		"generating_report":      "Generating canonical security report…",
		"generating_fix_spec":    "Generating AI fix specification…",
		"generating_summary":     "Building AI remediation handoff…",
		"completed":              "SecureCoder pipeline completed",
		"failed":                 "SecureCoder pipeline failed",
	}
	if label := labels[strings.TrimSpace(progressMessage)]; label != "" {
		return label
	}
	return fmt.Sprintf("SecureCoder stage %d of 7", step)
}

func pipelineProgress(step int, status string) int {
	if status == "completed" {
		return 100
	}
	if step < 1 {
		return 2
	}
	if step > 7 {
		step = 7
	}
	return step * 14
}
