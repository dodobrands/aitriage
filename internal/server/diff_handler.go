package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dodobrands/aitriage/internal/engine/history"
	"github.com/dodobrands/aitriage/internal/scanner"
)

// "What changed since last time?" is the question a team asks on every commit,
// and the only useful answer when a repository already carries a backlog. The
// CLI answers it with `watch`, an AI IDE with aitriage_diff, and the Web UI
// could not answer it at all — it could only report the whole pile again.
//
// This runs the same comparison against the same saved history, so all three
// surfaces give the same answer.

type diffResponse struct {
	OK            bool   `json:"ok"`
	HasPrevious   bool   `json:"has_previous"`
	PreviousScore int    `json:"previous_score"`
	CurrentScore  int    `json:"current_score"`
	Delta         int    `json:"delta"`
	NewFindings   int    `json:"new_findings"`
	FixedFindings int    `json:"fixed_findings"`
	Diffs         any    `json:"diffs"`
	Summary       string `json:"summary"`
}

// handleDiff scans now and compares against the last saved scan.
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
		// Save records this scan as the new comparison point. It defaults to
		// true so repeated calls answer "since last time" rather than always
		// comparing against the first run ever made.
		Save *bool `json:"save"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	projectPath, err := s.resolveProjectPath(requestedPathOrDefault(req.Path))
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	previous, err := history.LoadLast(projectPath)
	if err != nil {
		jsonError(w, fmt.Sprintf("could not read scan history: %v", err), http.StatusInternalServerError)
		return
	}

	current, err := scanner.Scan(r.Context(), projectPath, scanner.ScanOptions{})
	if err != nil {
		jsonError(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	save := req.Save == nil || *req.Save
	if save {
		// A failure to record history must not fail the comparison the caller
		// asked for; it only means the next diff spans a longer period.
		_, _ = history.Save(projectPath, current)
	}

	if previous == nil {
		writeJSON(w, diffResponse{
			OK:           true,
			HasPrevious:  false,
			CurrentScore: current.SecurityScore,
			Diffs:        []any{},
			Summary:      "No earlier scan to compare against. This one is now the comparison point.",
		})
		return
	}

	diffs := history.Diff(previous.Report, current)
	added, fixed := countDiffDirections(diffs)

	writeJSON(w, diffResponse{
		OK:            true,
		HasPrevious:   true,
		PreviousScore: previous.Report.SecurityScore,
		CurrentScore:  current.SecurityScore,
		Delta:         current.SecurityScore - previous.Report.SecurityScore,
		NewFindings:   added,
		FixedFindings: fixed,
		Diffs:         diffs,
		Summary:       history.FormatDiff(diffs, previous.Report.SecurityScore, current.SecurityScore),
	})
}

// countDiffDirections splits the diff into regressions and fixes so a caller can
// gate on "nothing new" without parsing prose.
func countDiffDirections(diffs []history.DiffEntry) (added, fixed int) {
	for _, d := range diffs {
		switch d.Change {
		case "added":
			added++
		case "fixed":
			fixed++
		}
	}
	return added, fixed
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
