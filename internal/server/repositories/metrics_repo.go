package repositories

import (
	"context"
	"database/sql"

	"github.com/dodobrands/aitriage/internal/report/healthcheck"
)

type MetricsRepository struct {
	db *sql.DB
}

func NewMetricsRepository(db *sql.DB) *MetricsRepository {
	return &MetricsRepository{db: db}
}

type RiskyProduct struct {
	Name      string `json:"name"`
	RiskScore int    `json:"risk_score"`
	Trend     string `json:"trend"`
}

type RecentEngagement struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Date   string `json:"date"`
}

type TopFile struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type StatusBreakdown struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type StackBreakdown struct {
	Stack string `json:"stack"`
	Count int    `json:"count"`
}

type DashboardMetrics struct {
	TotalProducts     int                `json:"total_products"`
	ActiveEngagements int                `json:"active_engagements"`
	OpenFindings      int                `json:"open_findings"`
	SLABreached       int                `json:"sla_breached"`
	SeverityCounts    map[string]int     `json:"severity_counts"`
	TopRiskyProducts  []RiskyProduct     `json:"top_risky_products"`
	RecentEngagements []RecentEngagement `json:"recent_engagements"`
	MTTR              map[string]string  `json:"mttr"`

	// Extended metrics
	TotalFindings                int               `json:"total_findings"`
	ResolvedFindings             int               `json:"resolved_findings"`
	TopFiles                     []TopFile         `json:"top_files"`
	StatusBreakdown              []StatusBreakdown `json:"status_breakdown"`
	StackBreakdown               []StackBreakdown  `json:"stack_breakdown"`
	SecurityScore                int               `json:"security_score"`
	SecurityGrade                string            `json:"security_grade"`
	TotalEngagements             int               `json:"total_engagements"`
	LastSuccessfulScanAt         *string           `json:"last_successful_scan_at"`
	LastSuccessfulVerificationAt *string           `json:"last_successful_verification_at"`
}

func (r *MetricsRepository) GetDashboardMetrics(ctx context.Context) (*DashboardMetrics, error) {
	var metrics DashboardMetrics
	metrics.SeverityCounts = make(map[string]int)
	metrics.TopRiskyProducts = make([]RiskyProduct, 0)
	metrics.RecentEngagements = make([]RecentEngagement, 0)
	metrics.MTTR = make(map[string]string)
	metrics.TopFiles = make([]TopFile, 0)
	metrics.StatusBreakdown = make([]StatusBreakdown, 0)
	metrics.StackBreakdown = make([]StackBreakdown, 0)

	// Total Products
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM products`).Scan(&metrics.TotalProducts)
	if err != nil {
		return nil, err
	}

	err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM engagements WHERE status IN ('in_progress', 'not_started')`).Scan(&metrics.ActiveEngagements)
	if err != nil {
		return nil, err
	}

	err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM engagements`).Scan(&metrics.TotalEngagements)
	if err != nil {
		return nil, err
	}

	err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')`).Scan(&metrics.OpenFindings)
	if err != nil {
		return nil, err
	}

	// Total and resolved findings
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&metrics.TotalFindings)
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE LOWER(status) END) IN ('resolved', 'fixed', 'closed', 'mitigated')`).Scan(&metrics.ResolvedFindings)

	err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE sla_breached = 1 AND (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')`).Scan(&metrics.SLABreached)
	if err != nil {
		return nil, err
	}

	// Severity counts
	rows, err := r.db.QueryContext(ctx, `
		SELECT severity, COUNT(*) 
		FROM findings 
		WHERE (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')
		GROUP BY severity
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		metrics.SeverityCounts[severity] = count
	}

	// Compute security score using healthcheck
	hcInput := healthcheck.Input{}
	hcRows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(stack, 'unknown'), COALESCE(rule_id, 'unknown'), COALESCE(severity, 'INFO'), COALESCE(file_path, ''), COALESCE(line_number, 0), COALESCE(LOWER(status), 'open')
		FROM findings
		WHERE (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated')
	`)
	if err == nil {
		defer func() { _ = hcRows.Close() }()
		for hcRows.Next() {
			var src, class, sev, file, status string
			var line int
			if err := hcRows.Scan(&src, &class, &sev, &file, &line, &status); err == nil {
				ignored := (status == "false_positive" || status == "risk_accepted" || status == "accepted_risk")
				hcInput.Findings = append(hcInput.Findings, healthcheck.Finding{
					Source:   src,
					Class:    class,
					Severity: sev,
					File:     file,
					Line:     line,
					Ignored:  ignored,
				})
			}
		}
		res := healthcheck.Evaluate(hcInput)
		metrics.SecurityScore = res.Score
		metrics.SecurityGrade = res.Grade
	} else {
		return nil, err
	}

	// Top risky products — products with highest open finding count
	riskyRows, err := r.db.QueryContext(ctx, `
		SELECT p.name, COUNT(f.id) as finding_count
		FROM products p
		LEFT JOIN findings f ON f.product_id = p.id AND (CASE WHEN COALESCE(LOWER(f.status), 'open') IN ('open', '') AND f.verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(f.status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')
		GROUP BY p.id, p.name
		HAVING COUNT(f.id) > 0
		ORDER BY finding_count DESC
		LIMIT 5
	`)
	if err == nil {
		defer func() { _ = riskyRows.Close() }()
		for riskyRows.Next() {
			var name string
			var count int
			if err := riskyRows.Scan(&name, &count); err == nil {
				trend := "stable"
				if count > 20 {
					trend = "up"
				} else if count < 5 {
					trend = "down"
				}
				metrics.TopRiskyProducts = append(metrics.TopRiskyProducts, RiskyProduct{
					Name:      name,
					RiskScore: count,
					Trend:     trend,
				})
			}
		}
	}

	// Recent engagements
	engRows, err := r.db.QueryContext(ctx, `
		SELECT e.name, e.status, COALESCE(e.completed_at, e.started_at)
		FROM engagements e
		ORDER BY COALESCE(e.completed_at, e.started_at) DESC
		LIMIT 5
	`)
	if err == nil {
		defer func() { _ = engRows.Close() }()
		for engRows.Next() {
			var name, status, date string
			if err := engRows.Scan(&name, &status, &date); err == nil {
				metrics.RecentEngagements = append(metrics.RecentEngagements, RecentEngagement{
					Name:   name,
					Status: status,
					Date:   date,
				})
			}
		}
	}

	// MTTR by severity (average time to resolve)
	mttrRows, err := r.db.QueryContext(ctx, `
		SELECT severity, 
			ROUND(AVG(JULIANDAY(resolved_at) - JULIANDAY(created_at)), 1) || 'd'
		FROM findings
		WHERE resolved_at IS NOT NULL
		GROUP BY severity
	`)
	if err == nil {
		defer func() { _ = mttrRows.Close() }()
		for mttrRows.Next() {
			var sev, avgTime string
			if err := mttrRows.Scan(&sev, &avgTime); err == nil {
				metrics.MTTR[sev] = avgTime
			}
		}
	}

	// Top files by finding count
	fileRows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(file_path, 'unknown'), COUNT(*) as cnt
		FROM findings
		WHERE (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')
		AND file_path IS NOT NULL AND file_path != ''
		GROUP BY file_path
		ORDER BY cnt DESC
		LIMIT 8
	`)
	if err == nil {
		defer func() { _ = fileRows.Close() }()
		for fileRows.Next() {
			var path string
			var count int
			if err := fileRows.Scan(&path, &count); err == nil {
				metrics.TopFiles = append(metrics.TopFiles, TopFile{Path: path, Count: count})
			}
		}
	}

	// Status breakdown
	statusRows, err := r.db.QueryContext(ctx, `
		SELECT CASE
 WHEN LOWER(status) = 'fixed' OR (COALESCE(status,'open') IN ('open','') AND verification_status = 'fixed') THEN 'resolved'
 WHEN LOWER(status) = 'accepted_risk' THEN 'risk_accepted'
 ELSE COALESCE(NULLIF(LOWER(status),''), 'open') END AS normalized_status, COUNT(*)
		FROM findings
		GROUP BY normalized_status
		ORDER BY COUNT(*) DESC
	`)
	if err == nil {
		defer func() { _ = statusRows.Close() }()
		for statusRows.Next() {
			var status string
			var count int
			if err := statusRows.Scan(&status, &count); err == nil {
				metrics.StatusBreakdown = append(metrics.StatusBreakdown, StatusBreakdown{Status: status, Count: count})
			}
		}
	}

	// Stack breakdown
	stackRows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(stack, 'core'), COUNT(*)
		FROM findings
		WHERE (CASE WHEN COALESCE(LOWER(status), 'open') IN ('open', '') AND verification_status = 'fixed' THEN 'resolved' ELSE COALESCE(LOWER(status), 'open') END) NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')
		GROUP BY stack
		ORDER BY COUNT(*) DESC
	`)
	if err == nil {
		defer func() { _ = stackRows.Close() }()
		for stackRows.Next() {
			var stack string
			var count int
			if err := stackRows.Scan(&stack, &count); err == nil {
				metrics.StackBreakdown = append(metrics.StackBreakdown, StackBreakdown{Stack: stack, Count: count})
			}
		}
	}

	if err := r.populateFreshness(ctx, &metrics, 0); err != nil {
		return nil, err
	}
	return &metrics, nil
}
