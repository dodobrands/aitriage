package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

func (s *Server) handleFindingSource(w http.ResponseWriter, r *http.Request) {
	id, err := findingIDFromActionPath(r.URL.Path, "/source")
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	finding, err := s.findingRepo.GetByID(r.Context(), id)
	if err != nil {
		jsonError(w, "finding not found", http.StatusNotFound)
		return
	}
	root, rootErr := s.resolveFindingScanPath(r.Context(), finding)
	if rootErr != nil && !filepath.IsAbs(stringValue(finding.FilePath)) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "source_available": false, "source": ""})
		return
	}
	excerpt := s.readFindingSourceExcerpt(root, stringValue(finding.FilePath), stringValue(finding.FilePath), intValue(finding.LineNumber), 4)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "source": excerpt.Source, "source_available": excerpt.Available, "lines": excerpt.Lines})
}

func verificationScanError(ctx context.Context, finding *models.Finding, rich *llm.RichScanResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	required := []string{"aitriage"}
	switch strings.ToLower(finding.Stack) {
	case "semgrep", "bandit", "gitleaks", "nfr", "deploy", "git-history":
		required = []string{strings.ToLower(finding.Stack)}
	case "trivy":
		required = []string{"trivy_fs", "trivy_config"}
	case "network":
		return fmt.Errorf("network finding requires an explicit network verification scope")
	}
	for _, scanner := range required {
		completed := false
		for _, execution := range rich.ScannerExecutions {
			if execution.Scanner == scanner {
				if execution.Status != external.StatusCompleted {
					return fmt.Errorf("%s did not complete (%s)", scanner, execution.Status)
				}
				completed = true
			}
		}
		if !completed {
			return fmt.Errorf("%s has no completed execution", scanner)
		}
	}
	return nil
}
