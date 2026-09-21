package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner/deployaudit"
	"github.com/dodobrands/aitriage/internal/scanner/entropy"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
)

// An AI IDE could ask a single question — "are the NFR controls in place?",
// "is the Dockerfile sane?", "did a secret ever reach git history?" — while the
// Web UI could only run everything. A quick check is what someone reaches for
// before a commit; making them wait for a full audit means they skip it.
//
// These endpoints run the same scanners as the MCP tools of the same names, so
// the answers match whichever surface asked.

type checkResponse struct {
	OK       bool   `json:"ok"`
	Check    string `json:"check"`
	Path     string `json:"path"`
	Count    int    `json:"count"`
	Findings any    `json:"findings"`
	Summary  string `json:"summary"`
}

// handleCheck serves /api/check/{nfr|deploy|entropy}.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	kind := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/check/"), "/")
	requested := r.URL.Query().Get("path")
	if r.Method == http.MethodPost {
		var req struct {
			Path string `json:"path"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Path != "" {
			requested = req.Path
		}
	}

	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(requested))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	switch kind {
	case "nfr":
		findings, err := nfr.CheckNFR(projectPath)
		if err != nil {
			jsonError(w, fmt.Sprintf("NFR check failed: %v", err), http.StatusInternalServerError)
			return
		}
		if findings == nil {
			findings = []nfr.NFRFinding{}
		}
		writeCheck(w, "nfr", projectPath, len(findings), findings,
			fmt.Sprintf("%d non-functional requirement issue(s): missing rate limiting, CORS, unprotected routes and similar controls.", len(findings)))

	case "deploy":
		findings, err := deployaudit.AuditDeployFiles(projectPath)
		if err != nil {
			jsonError(w, fmt.Sprintf("deploy audit failed: %v", err), http.StatusInternalServerError)
			return
		}
		if findings == nil {
			findings = []deployaudit.DeployFinding{}
		}
		writeCheck(w, "deploy", projectPath, len(findings), findings,
			fmt.Sprintf("%d infrastructure issue(s) in Dockerfiles, compose files and CI configuration.", len(findings)))

	case "entropy":
		// Two questions, one answer: which files concentrate risk, and whether a
		// secret ever reached git history — a secret removed from the working
		// tree is still in the history unless it was rewritten.
		critical := entropy.FindCriticalFiles(projectPath)
		leaks := entropy.ScanGitHistory(projectPath)
		payload := map[string]any{
			"critical_files": critical,
			"history_leaks":  leaks,
		}
		writeCheck(w, "entropy", projectPath, len(critical)+len(leaks), payload,
			fmt.Sprintf("%d high-churn file(s) and %d secret(s) found in git history.", len(critical), len(leaks)))

	default:
		jsonError(w, fmt.Sprintf("unknown check %q (supported: nfr, deploy, entropy)", kind), http.StatusNotFound)
	}
}

func writeCheck(w http.ResponseWriter, kind, path string, count int, findings any, summary string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(checkResponse{
		OK:       true,
		Check:    kind,
		Path:     path,
		Count:    count,
		Findings: findings,
		Summary:  summary,
	})
}
