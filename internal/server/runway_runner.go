package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/graph"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// runRunwaySession is the canonical Web execution path. Simple mode and the
// advanced pipeline both use this method, which in turn uses the same graph.Run
// orchestrator and handoff builder as CI/CD.
func (s *Server) runRunwaySession(session *models.RunwaySession, product *models.Product, findings []models.Finding, language string) {
	ctx := context.Background()

	// This runs in a detached goroutine, where net/http cannot recover for us:
	// an unhandled panic here would take the whole server down mid-audit. Record
	// it against the session instead, so the failure is visible and survivable.
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Error("Runway session panicked",
				"session_id", session.ID,
				"panic", recovered,
				"stack", string(debug.Stack()))
			s.markRunwayFailed(ctx, session, fmt.Errorf("internal error during audit: %v", recovered))
		}
	}()
	updateProgress := func(step int, progressMessage string) {
		session.Status = "running"
		session.CurrentStep = step
		session.ProgressMessage = &progressMessage
		session.ErrorMessage = nil
		if err := s.runwayRepo.Update(ctx, session); err != nil {
			slog.Error("Failed to update runway progress", "session_id", session.ID, "step", step, "progress", progressMessage, "error", err)
		}
	}

	projectPath, err := s.resolveRunwayProjectPath(product)
	if err != nil {
		s.markRunwayFailed(ctx, session, err)
		return
	}

	cfg := config.LoadConfig(".")
	state := &graph.AgentState{
		ProjectPath:    projectPath,
		BatchSize:      cfg.LLM.BatchSize,
		Language:       language,
		RunwayProgress: updateProgress,
	}
	for _, finding := range findings {
		if finding.Status == "triage" {
			continue
		}
		filePath := ""
		if finding.FilePath != nil {
			filePath = *finding.FilePath
		}
		line := 0
		if finding.LineNumber != nil {
			line = *finding.LineNumber
		}
		state.ExternalFindings = append(state.ExternalFindings, external.UnifiedFinding{
			RuleID:   finding.RuleID,
			Severity: finding.Severity,
			File:     filePath,
			Line:     line,
			Message:  finding.Title,
		})
	}

	session.Status = "running"
	session.CurrentStep = 1
	session.ScanCountBefore = len(state.ExternalFindings)
	progressMessage := "preparing_context"
	session.ProgressMessage = &progressMessage
	session.ErrorMessage = nil
	if err := s.runwayRepo.Update(ctx, session); err != nil {
		slog.Error("Failed to mark runway session running", "session_id", session.ID, "error", err)
		return
	}

	if err := graph.Run(ctx, state, s.llmClient); err != nil {
		s.markRunwayFailed(ctx, session, err)
		return
	}

	tmJSON := "{}"
	if state.ThreatModel != nil {
		value, _ := json.MarshalIndent(state.ThreatModel, "", "  ")
		tmJSON = string(value)
	}
	session.ThreatModel = &tmJSON

	pocJSON := "[]"
	if len(state.PoCResults) > 0 {
		value, _ := json.MarshalIndent(state.PoCResults, "", "  ")
		pocJSON = string(value)
	}
	session.PoC = &pocJSON
	session.AuditReport = &state.ReportMarkdown
	if strings.TrimSpace(state.SummaryMarkdown) != "" {
		session.SecurityPlan = &state.SummaryMarkdown
	}
	if strings.TrimSpace(state.AIFixSpec) != "" {
		session.Remediation = &state.AIFixSpec
	}
	if state.AgentHandoff != nil {
		session.ScanCountAfter = state.AgentHandoff.AgentData.Stats.TruePositives + state.AgentHandoff.AgentData.Stats.NeedsReview
	}

	if err := s.persistRunwayArtifacts(ctx, session.ID, state); err != nil {
		slog.Error("Failed to persist Runway artifact bundle", "session_id", session.ID, "error", err)
		s.markRunwayFailed(ctx, session, err)
		return
	}
	progressMessage = "completed"
	session.Status = "completed"
	session.CurrentStep = 7
	session.ProgressMessage = &progressMessage
	if err := s.runwayRepo.Update(ctx, session); err != nil {
		slog.Error("Failed to persist runway session result", "session_id", session.ID, "error", err)
	}
}

func (s *Server) resolveRunwayProjectPath(product *models.Product) (string, error) {
	requested := "."
	if product != nil && product.RepoURL != nil && strings.TrimSpace(*product.RepoURL) != "" {
		requested = *product.RepoURL
	}
	resolved, err := s.resolveProjectPath(requested)
	if err != nil {
		return "", fmt.Errorf("runway project path rejected: %w", err)
	}
	return resolved, nil
}

func (s *Server) markRunwayFailed(ctx context.Context, session *models.RunwaySession, cause error) {
	errorMessage := cause.Error()
	progressMessage := "failed"
	session.ErrorMessage = &errorMessage
	session.Status = "failed"
	session.ProgressMessage = &progressMessage
	if session.CurrentStep == 0 {
		session.CurrentStep = 1
	}
	if err := s.runwayRepo.Update(ctx, session); err != nil {
		slog.Error("Failed to persist runway failure", "session_id", session.ID, "error", err)
	}
}
