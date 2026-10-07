package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	gitignore "github.com/sabhiram/go-gitignore"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/healthpolicy"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deps"
	"github.com/dodobrands/aitriage/internal/scanner/detector"
)

type ScanOptions struct {
	MinSeverity   string
	ExcludePaths  []string
	ForceStack    string
	UniversalOnly bool
	FileFilter    []string // If non-empty, scan ONLY these files (absolute paths)
}

type ScanReport struct {
	ProjectPath         string               `json:"project_path"`
	Stacks              []detector.Stack     `json:"stacks"`
	Results             []core.CheckResult   `json:"results"`
	HasCriticalFailures bool                 `json:"has_critical_failures"`
	SecurityScore       int                  `json:"security_score"`
	SecurityGrade       string               `json:"security_grade"`
	HealthCheck         healthcheck.Result   `json:"health_check"`
	Dependencies        []deps.Dependency    `json:"dependencies"`
	DependencyGraph     deps.DependencyGraph `json:"dependency_graph"`
	AISummary           string               `json:"ai_summary,omitempty"`
	TotalFiles          int                  `json:"total_files"`
	RulesApplied        int                  `json:"rules_applied"`
	ScanDuration        time.Duration        `json:"scan_duration_ms"`
	Config              *config.Config       `json:"-"` // not serialized; used by CLI
}

// ToJSON serializes ScanReport to JSON. Used by MCP tools and agent mode.
func (r ScanReport) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// Scan runs a full deterministic scan of the project.
// Accepts a context for cancellation from MCP and agent modes.
// Returns ScanReport and error — does NOT call os.Exit.
func Scan(ctx context.Context, projectPath string, opts ScanOptions) (ScanReport, error) {
	start := time.Now()

	empty := ScanReport{
		ProjectPath: projectPath,
		Stacks:      []detector.Stack{detector.UnknownStack},
		Results:     nil,
	}

	if info, err := os.Stat(projectPath); err != nil || !info.IsDir() {
		return empty, fmt.Errorf("path %q is not a valid directory", projectPath)
	}

	// Resolve to an absolute path so per-file content reads, project grouping,
	// and the --staged/--diff file filter (which compares absolute paths) all
	// work identically whether the caller passed ".", "./", or an absolute path.
	// Without this, `aitriage scan .` — the exact form used by the pre-commit
	// hook and CI — would run project-level checks but silently skip per-file
	// analysis (including secret detection).
	if abs, err := filepath.Abs(projectPath); err == nil {
		projectPath = abs
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return empty, ctx.Err()
	default:
	}

	ws, err := core.NewWorkspace(projectPath)
	if err != nil {
		slog.Error("Failed to create workspace", "error", err)
		return empty, fmt.Errorf("failed to create workspace: %w", err)
	}

	if len(opts.ExcludePaths) > 0 {
		ignored := gitignore.CompileIgnoreLines(opts.ExcludePaths...)
		kept := ws.Files[:0]
		for _, file := range ws.Files {
			rel, err := filepath.Rel(projectPath, file.Path)
			if err != nil || !ignored.MatchesPath(filepath.ToSlash(rel)) {
				kept = append(kept, file)
			}
		}
		ws.Files = kept
	}
	projects := detector.DetectProjects(ws)
	ws.Projects = projects

	// Apply file filter (for --diff / --staged) — keep only matching files
	if len(opts.FileFilter) > 0 {
		allowed := make(map[string]bool, len(opts.FileFilter))
		for _, f := range opts.FileFilter {
			abs, err := filepath.Abs(f)
			if err == nil {
				allowed[abs] = true
			} else {
				allowed[f] = true
			}
		}
		for _, proj := range projects {
			filtered := proj.Files[:0]
			for _, fi := range proj.Files {
				if allowed[fi.Path] {
					filtered = append(filtered, fi)
				}
			}
			proj.Files = filtered
		}
	}

	var allStacks []detector.Stack
	seenStacks := make(map[detector.Stack]bool)
	for _, p := range projects {
		st := detector.Stack(p.Stack)
		if !seenStacks[st] {
			allStacks = append(allStacks, st)
			seenStacks[st] = true
		}
	}

	var results []core.CheckResult

	// Init YAML Rule Engine
	eng, err := engine.NewEngine(ws.Config)
	if err != nil {
		slog.Error("Failed to initialize rule engine", "error", err)
		return empty, fmt.Errorf("failed to initialize rule engine: %w", err)
	}

	// Run engine on each project in the workspace
	for _, proj := range projects {
		// Check context cancellation between projects
		select {
		case <-ctx.Done():
			return empty, ctx.Err()
		default:
		}

		if opts.UniversalOnly && proj.Stack != string(detector.Universal) && proj.Stack != string(detector.UnknownStack) {
			continue // skip specific stacks if forced to universal only
		}

		if opts.ForceStack != "" && proj.Stack != opts.ForceStack {
			proj.Stack = opts.ForceStack
		}

		res := eng.Run(proj)
		results = append(results, res...)
	}

	if opts.MinSeverity != "" {
		rank := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
		minimum := rank[strings.ToUpper(opts.MinSeverity)]
		kept := results[:0]
		for _, result := range results {
			if rank[strings.ToUpper(result.Severity)] >= minimum {
				kept = append(kept, result)
			}
		}
		results = kept
	}
	// Deduplicate: project-level rules (no file) — keep one per ID
	// File-level rules — keep one per ID+File+Line combination
	seen := make(map[string]bool)
	deduped := results[:0]
	for _, r := range results {
		var key string
		if r.File == "" {
			key = r.ID // project-level: one per rule
		} else {
			key = fmt.Sprintf("%s|%s|%d", r.ID, r.File, r.Line)
		}
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, r)
		}
	}
	results = deduped

	// Apply Audit Statuses
	auditStore := core.NewAuditStore(projectPath)
	for i := range results {
		relPath := results[i].File
		// Normalize to relative path for consistent audit keys
		if relPath != "" && filepath.IsAbs(relPath) {
			relPath, _ = filepath.Rel(projectPath, relPath)
		}
		status := auditStore.GetStatus(results[i].ID, relPath)
		results[i].AuditStatus = status
	}

	healthResult := healthcheck.ApplyPolicy(
		healthcheck.Evaluate(healthcheck.FromCoreResults(results)),
		healthpolicy.FromConfig(ws.Config),
	)
	hasCritical := healthResult.HasCriticalFailures
	securityScore := healthResult.Score
	securityGrade := healthResult.Grade

	for i := range results {
		results[i].OWASPMapping = healthcheck.GetOWASP(results[i].ID)
	}

	projectGraph := deps.GenerateGraph(ws)

	return ScanReport{
		ProjectPath:         projectPath,
		Stacks:              allStacks,
		Results:             results,
		HasCriticalFailures: hasCritical,
		SecurityScore:       securityScore,
		SecurityGrade:       securityGrade,
		HealthCheck:         healthResult,
		Dependencies:        projectGraph.Nodes,
		DependencyGraph:     projectGraph,
		TotalFiles:          len(ws.Files),
		RulesApplied:        len(results),
		ScanDuration:        time.Since(start),
		Config:              ws.Config,
	}, nil
}
