package repositories

import (
	"context"
	"fmt"
	"sort"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

func (r *MetricsRepository) GetProductMetrics(ctx context.Context, id int64) (*DashboardMetrics, error) {
	var exists int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM products WHERE id = ?", id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, fmt.Errorf("product not found")
	}
	findings, err := NewFindingRepository(r.db).ListByProductID(ctx, id)
	if err != nil {
		return nil, err
	}
	m := &DashboardMetrics{TotalProducts: 1, SeverityCounts: map[string]int{}, MTTR: map[string]string{}, TopRiskyProducts: []RiskyProduct{}, RecentEngagements: []RecentEngagement{}, TopFiles: []TopFile{}, StatusBreakdown: []StatusBreakdown{}, StackBreakdown: []StackBreakdown{}}
	input := healthcheck.Input{}
	statuses, stacks, files := map[string]int{}, map[string]int{}, map[string]int{}
	for _, f := range findings {
		m.TotalFindings++
		statuses[f.Status]++
		stacks[f.Stack]++
		if models.FindingResolved(&f) {
			m.ResolvedFindings++
			continue
		}
		active := models.FindingActive(&f)
		if active {
			m.OpenFindings++
			m.SeverityCounts[f.Severity]++
			if f.SLABreached {
				m.SLABreached++
			}
			if f.FilePath != nil && *f.FilePath != "" {
				files[*f.FilePath]++
			}
		}
		file, line := "", 0
		if f.FilePath != nil {
			file = *f.FilePath
		}
		if f.LineNumber != nil {
			line = *f.LineNumber
		}
		input.Findings = append(input.Findings, healthcheck.Finding{Source: f.Stack, Class: f.RuleID, Severity: f.Severity, File: file, Line: line, Ignored: !active})
	}
	score := healthcheck.Evaluate(input)
	m.SecurityScore, m.SecurityGrade = score.Score, score.Grade
	for status, count := range statuses {
		m.StatusBreakdown = append(m.StatusBreakdown, StatusBreakdown{status, count})
	}
	for stack, count := range stacks {
		m.StackBreakdown = append(m.StackBreakdown, StackBreakdown{stack, count})
	}
	for file, count := range files {
		m.TopFiles = append(m.TopFiles, TopFile{file, count})
	}
	sort.Slice(m.TopFiles, func(i, j int) bool {
		if m.TopFiles[i].Count == m.TopFiles[j].Count {
			return m.TopFiles[i].Path < m.TopFiles[j].Path
		}
		return m.TopFiles[i].Count > m.TopFiles[j].Count
	})
	sort.Slice(m.StatusBreakdown, func(i, j int) bool { return m.StatusBreakdown[i].Status < m.StatusBreakdown[j].Status })
	sort.Slice(m.StackBreakdown, func(i, j int) bool { return m.StackBreakdown[i].Stack < m.StackBreakdown[j].Stack })
	if len(m.TopFiles) > 8 {
		m.TopFiles = m.TopFiles[:8]
	}
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(CASE WHEN status IN ('in_progress', 'not_started') THEN 1 ELSE 0 END),0) FROM engagements WHERE product_id = ?", id).Scan(&m.TotalEngagements, &m.ActiveEngagements); err != nil {
		return nil, err
	}
	if err := r.populateFreshness(ctx, m, id); err != nil {
		return nil, err
	}
	return m, nil
}
