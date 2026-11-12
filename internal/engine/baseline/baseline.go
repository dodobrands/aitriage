package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/statefile"
)

// ──────────────────────────────────────────────────────────────────────────────
// Baseline provides a mechanism to "accept" current findings and only alert on
// NEW findings. This prevents alert fatigue on legacy codebases.
//
// Usage:
//   aitriage baseline create .       → Scan and save all findings as accepted
//   aitriage scan . --baseline       → Report only new findings vs baseline
// ──────────────────────────────────────────────────────────────────────────────

const (
	Version      = "1"
	BaselineFile = ".aitriage-baseline.json"
)

// Baseline represents the set of accepted (baselined) findings for a project.
type Baseline struct {
	Version   string             `json:"version"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
	Findings  map[string]Finding `json:"findings"` // key = fingerprint
}

// Finding is a single baselined finding with enough info to reconstruct context.
type Finding struct {
	// Source names the scanner that reported it. Absent in version "1" files,
	// where every entry came from the built-in engine.
	Source   string `json:"source,omitempty"`
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Hash     string `json:"hash"` // SHA256 of (ruleID + file + evidence)
}

// ── Fingerprinting ───────────────────────────────────────────────────────────

// Fingerprint generates a stable unique identifier for a finding.
// Uses ruleID + file + evidence to tolerate line number shifts.
func Fingerprint(r core.CheckResult) string {
	data := fmt.Sprintf("%s|%s|%s", r.ID, r.File, r.Evidence)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:12]) // 24-char hex
}

// ── Create / Load / Save ─────────────────────────────────────────────────────

// newEmpty builds an empty baseline stamped with the current time.
func newEmpty() *Baseline {
	now := time.Now().UTC()
	return &Baseline{
		Version:   Version,
		CreatedAt: now,
		UpdatedAt: now,
		Findings:  map[string]Finding{},
	}
}

// New creates a baseline from built-in engine results.
//
// Deprecated: use NewFromItems, which accepts findings from every scanner. This
// remains for callers that only have core results.
func New(results []core.CheckResult) *Baseline {
	b := newEmpty()
	for _, r := range results {
		fp := Fingerprint(r)
		b.Findings[fp] = Finding{
			Source:   "core",
			RuleID:   r.ID,
			File:     r.File,
			Line:     r.Line,
			Name:     r.Name,
			Severity: r.Severity,
			Hash:     fp,
		}
	}
	return b
}

// Load reads the baseline file from the project directory.
// Returns nil, nil if no baseline exists yet.
func Load(projectPath string) (*Baseline, error) {
	path := filepath.Join(projectPath, BaselineFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}
	return &b, nil
}

// Save writes the baseline to the project directory.
func Save(projectPath string, b *Baseline) error {
	b.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	path := filepath.Join(projectPath, BaselineFile)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}
	return nil
}

// ReportsArea is the folder under the reports directory that holds the
// baselines written while the project is mounted read-only.
const ReportsArea = "baselines"

// Locate returns where the baseline of the scanned folder projectPath is read
// and written: the project's own file natively, plus a local copy under the
// reports directory in the container runtime (see statefile).
func Locate(projectPath string) statefile.Location {
	return statefile.Locate(projectPath, ReportsArea, BaselineFile)
}

// LoadAt reads the baseline that applies at loc, or nil, nil when there is
// none. Natively that is the project's own file. In the container runtime it
// is that file together with the local copy: a finding accepted in either is
// accepted, and for a finding in both the copy's record is kept. Findings the
// project accepts after the copy was written still count, and the copy keeps
// accepting what the project later drops, until it is committed or cleared.
func LoadAt(loc statefile.Location) (*Baseline, error) {
	project, err := Load(loc.ProjectDir)
	if err != nil || !loc.Redirected() {
		return project, err
	}
	local, err := Load(loc.WriteDir)
	if err != nil {
		return nil, err
	}
	switch {
	case project == nil:
		return local, nil
	case local == nil:
		return project, nil
	}

	merged := &Baseline{
		// The project file's format decides how its older entries match. The
		// local copy is always written in the current format, whose entries
		// every version matches exactly.
		Version:   project.Version,
		CreatedAt: project.CreatedAt,
		UpdatedAt: project.UpdatedAt,
		Findings:  make(map[string]Finding, len(project.Findings)+len(local.Findings)),
	}
	if !local.CreatedAt.IsZero() && (merged.CreatedAt.IsZero() || local.CreatedAt.Before(merged.CreatedAt)) {
		merged.CreatedAt = local.CreatedAt
	}
	if local.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = local.UpdatedAt
	}
	for fp, f := range project.Findings {
		merged.Findings[fp] = f
	}
	for fp, f := range local.Findings {
		merged.Findings[fp] = f
	}
	return merged, nil
}

// SaveAt writes the baseline where loc sends writes, creating its folder under
// the reports directory when the project is read-only.
func SaveAt(loc statefile.Location, b *Baseline) error {
	if err := loc.Prepare(); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}
	return Save(loc.WriteDir, b)
}

// ── Filtering ────────────────────────────────────────────────────────────────

// FilterResult contains the results of filtering findings against a baseline.
type FilterResult struct {
	New      []core.CheckResult // Findings NOT in the baseline (regressions)
	Baseline []core.CheckResult // Findings that ARE in the baseline (accepted)
}

// FilterInProject matches core findings using the same project-relative paths
// that NewFromItems stores. It also retains matching for older baseline files.
func FilterInProject(projectPath string, results []core.CheckResult, b *Baseline) FilterResult {
	if b == nil || len(b.Findings) == 0 {
		return FilterResult{New: results}
	}

	var fr FilterResult
	for _, r := range results {
		item := Relativize(projectPath, FromCore([]core.CheckResult{r}))[0]
		if b.AcceptsInProject(projectPath, item) {
			fr.Baseline = append(fr.Baseline, r)
		} else {
			fr.New = append(fr.New, r)
		}
	}
	return fr
}

// ── Stats ────────────────────────────────────────────────────────────────────

// Stats returns a human-readable summary of the baseline.
type Stats struct {
	Total      int
	BySeverity map[string]int
}

func (b *Baseline) Stats() Stats {
	s := Stats{
		Total:      len(b.Findings),
		BySeverity: make(map[string]int),
	}
	for _, f := range b.Findings {
		s.BySeverity[f.Severity]++
	}
	return s
}

// FormatStats returns a human-readable summary of what's in the baseline.
func (b *Baseline) FormatStats() string {
	s := b.Stats()
	if s.Total == 0 {
		return "Baseline is empty — no findings accepted."
	}

	out := fmt.Sprintf("Baseline: %d findings accepted\n", s.Total)

	// Sort severities for stable output
	sevs := make([]string, 0, len(s.BySeverity))
	for sev := range s.BySeverity {
		sevs = append(sevs, sev)
	}
	sort.Strings(sevs)

	for _, sev := range sevs {
		out += fmt.Sprintf("  %s: %d\n", sev, s.BySeverity[sev])
	}
	out += fmt.Sprintf("\nCreated: %s\nUpdated: %s\n", b.CreatedAt.Format(time.RFC3339), b.UpdatedAt.Format(time.RFC3339))
	return out
}
