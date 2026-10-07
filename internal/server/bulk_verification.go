package server

import (
	"encoding/json"
	"net/http"

	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/models"
)

type bulkVerificationResult struct {
	ID    int64  `json:"id"`
	Fixed bool   `json:"fixed"`
	Error string `json:"error,omitempty"`
}

// Scan each repository once for a batch rather than once for every selected row.
func (s *Server) handleBulkFindingVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil || len(req.IDs) == 0 || len(req.IDs) > 100 {
		jsonError(w, "provide 1 to 100 finding ids", http.StatusBadRequest)
		return
	}
	results := make([]bulkVerificationResult, len(req.IDs))
	groups := map[string][]int{}
	findings := map[int]*models.Finding{}
	seen := map[int64]bool{}
	ctx := r.Context()
	for i, id := range req.IDs {
		results[i].ID = id
		if id <= 0 || seen[id] {
			results[i].Error = "invalid or duplicate finding id"
			continue
		}
		seen[id] = true
		finding, err := s.findingRepo.GetByID(ctx, id)
		if err != nil {
			results[i].Error = "finding not found"
			continue
		}
		root, err := s.resolveFindingScanPath(ctx, finding)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		findings[i] = finding
		groups[root] = append(groups[root], i)
	}
	for root, indexes := range groups {
		external := false
		pending := []int{}
		for _, i := range indexes {
			f := findings[i]
			if err := s.findingRepo.MarkPendingVerification(ctx, f.ID); err != nil {
				results[i].Error = "failed to start verification"
				continue
			}
			pending = append(pending, i)
			external = external || shouldRunExternalForFinding(f)
		}
		if len(pending) == 0 {
			continue
		}
		rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{ProjectPath: root, RunExternal: external})
		for _, i := range pending {
			f := findings[i]
			if err := verificationScanError(ctx, f, &rich); err != nil {
				results[i].Error = err.Error()
				_ = s.findingRepo.MarkVerificationError(ctx, f.ID, f.Status, "Verification incomplete: "+err.Error())
				continue
			}
			present, _ := findingStillPresent(f, root, &rich)
			summary := "Verification passed: AITriage did not detect this finding in the repeated scan."
			if present {
				summary = "Verification failed: AITriage still detects this finding."
			}
			if err := s.findingRepo.MarkVerificationResult(ctx, f.ID, !present, summary); err != nil {
				results[i].Error = "failed to save verification result"
				continue
			}
			results[i].Fixed = !present
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "results": results})
}
