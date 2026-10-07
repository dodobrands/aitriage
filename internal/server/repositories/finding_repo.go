package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dodobrands/aitriage/internal/models"
)

type FindingRepository struct {
	db *sql.DB
}

type findingScanner interface {
	Scan(dest ...any) error
}

const findingSelectColumns = `
	id, engagement_id, product_id, rule_id, title, severity, cvss_score, cve_id, cwe_id,
	file_path, line_number, col_number, code_snippet, description, impact, fix_suggestion,
	references_, hash_code, is_duplicate, duplicate_of, status, kanban_column, sla_deadline,
	sla_breached, risk_accepted, risk_accepted_by, risk_accepted_reason, risk_accepted_expiry,
	assigned_to, is_verified, verified_by, verified_at, created_at, updated_at, resolved_at,
	resolved_by, is_false_positive, fp_reason, stack, ai_triage_status, ai_triage_summary,
	agent_prompt, agent_prompt_generated_at, verification_status, verification_summary,
	verification_last_run_at
`

func NewFindingRepository(db *sql.DB) *FindingRepository {
	return &FindingRepository{db: db}
}

func scanFinding(scanner findingScanner) (models.Finding, error) {
	var f models.Finding
	err := scanner.Scan(
		&f.ID, &f.EngagementID, &f.ProductID, &f.RuleID, &f.Title, &f.Severity,
		&f.CVSSScore, &f.CVEID, &f.CWEID, &f.FilePath, &f.LineNumber, &f.ColNumber,
		&f.CodeSnippet, &f.Description, &f.Impact, &f.FixSuggestion, &f.References,
		&f.HashCode, &f.IsDuplicate, &f.DuplicateOf, &f.Status, &f.KanbanColumn,
		&f.SLADeadline, &f.SLABreached, &f.RiskAccepted, &f.RiskAcceptedBy,
		&f.RiskAcceptedReason, &f.RiskAcceptedExpiry, &f.AssignedTo, &f.IsVerified,
		&f.VerifiedBy, &f.VerifiedAt, &f.CreatedAt, &f.UpdatedAt, &f.ResolvedAt,
		&f.ResolvedBy, &f.IsFalsePositive, &f.FPReason, &f.Stack, &f.AITriageStatus,
		&f.AITriageSummary, &f.AgentPrompt, &f.AgentPromptAt, &f.VerificationStatus,
		&f.VerificationSummary, &f.VerificationLastRunAt,
	)
	f.Status = models.FindingStatus(&f)
	return f, err
}

func (r *FindingRepository) getIgnoredStatus(ctx context.Context, codeSnippet *string, defaultStatus string) string {
	return ignoredFindingStatus(ctx, r.db, codeSnippet, defaultStatus)
}

type findingQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func ignoredFindingStatus(ctx context.Context, db findingQueryer, codeSnippet *string, defaultStatus string) string {
	if codeSnippet == nil || *codeSnippet == "" {
		return defaultStatus
	}
	hash := ContentHash(*codeSnippet)
	var reason string
	err := db.QueryRowContext(ctx, "SELECT reason FROM ignored_findings WHERE content_hash = ? LIMIT 1", hash).Scan(&reason)
	if err == nil {
		switch reason {
		case "False Positive":
			return "false_positive"
		case "Accepted Risk", "Won't Fix":
			return "risk_accepted"
		}
	}
	return defaultStatus
}

func (r *FindingRepository) Create(ctx context.Context, f *models.Finding) (int64, error) {
	if f.Status == "" {
		f.Status = "open"
	}
	status := r.getIgnoredStatus(ctx, f.CodeSnippet, f.Status)
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO findings (engagement_id, product_id, rule_id, title, severity, cvss_score, cve_id, cwe_id, file_path, line_number, col_number, code_snippet, description, impact, fix_suggestion, references_, hash_code, status, kanban_column, stack)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.EngagementID, f.ProductID, f.RuleID, f.Title, f.Severity, f.CVSSScore, f.CVEID, f.CWEID, f.FilePath, f.LineNumber, f.ColNumber, f.CodeSnippet, f.Description, f.Impact, f.FixSuggestion, f.References, f.HashCode, status, f.KanbanColumn, f.Stack)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *FindingRepository) BulkCreate(ctx context.Context, findings []models.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings (engagement_id, product_id, rule_id, title, severity, cvss_score, cve_id, cwe_id, file_path, line_number, col_number, code_snippet, description, impact, fix_suggestion, references_, hash_code, status, kanban_column, stack)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, f := range findings {
		if f.Status == "" {
			f.Status = "open"
		}
		status := ignoredFindingStatus(ctx, tx, f.CodeSnippet, f.Status)
		_, err := stmt.ExecContext(ctx, f.EngagementID, f.ProductID, f.RuleID, f.Title, f.Severity, f.CVSSScore, f.CVEID, f.CWEID, f.FilePath, f.LineNumber, f.ColNumber, f.CodeSnippet, f.Description, f.Impact, f.FixSuggestion, f.References, f.HashCode, status, f.KanbanColumn, f.Stack)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *FindingRepository) Deduplicate(ctx context.Context, productID int64) error {
	// Simple deduplication logic marking older identical hash_codes as duplicates
	_, err := r.db.ExecContext(ctx, `
		UPDATE findings 
		SET is_duplicate = 1, duplicate_of = (
			SELECT MIN(f2.id) FROM findings f2 
			WHERE f2.hash_code = findings.hash_code 
			AND f2.product_id = findings.product_id 
			AND f2.id != findings.id
		)
		WHERE product_id = ? 
		AND id != (
			SELECT MIN(f3.id) FROM findings f3 
			WHERE f3.hash_code = findings.hash_code 
			AND f3.product_id = findings.product_id
		)
	`, productID)
	return err
}

func (r *FindingRepository) GetByID(ctx context.Context, id int64) (*models.Finding, error) {
	row := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT %s
		FROM findings WHERE id = ?
	`, findingSelectColumns), id)

	f, err := scanFinding(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("finding not found")
		}
		return nil, err
	}
	return &f, nil
}

func (r *FindingRepository) List(ctx context.Context, engagementID int64) ([]models.Finding, error) {
	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s
		FROM findings
		WHERE engagement_id = ?
		ORDER BY created_at DESC
	`, findingSelectColumns), engagementID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var findings []models.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	// Normalize: ensure no finding has an empty status
	for i := range findings {
		if findings[i].Status == "" {
			findings[i].Status = "open"
		}
	}
	return findings, rows.Err()
}

func (r *FindingRepository) ListByProductID(ctx context.Context, productID int64) ([]models.Finding, error) {
	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s
		FROM findings
		WHERE product_id = ?
		ORDER BY created_at DESC
	`, findingSelectColumns), productID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var findings []models.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	for i := range findings {
		if findings[i].Status == "" {
			findings[i].Status = "open"
		}
	}
	return findings, rows.Err()
}

func (r *FindingRepository) ListAll(ctx context.Context) ([]models.Finding, error) {
	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s
		FROM findings
		ORDER BY created_at DESC
	`, findingSelectColumns))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var findings []models.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	// Normalize: ensure no finding has an empty status
	for i := range findings {
		if findings[i].Status == "" {
			findings[i].Status = "open"
		}
	}
	return findings, rows.Err()
}

// EnsureSLA evaluates Findings and marks those past deadline as sla_breached
func (r *FindingRepository) EnsureSLA(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE findings 
		SET sla_breached = 1 
		WHERE sla_deadline IS NOT NULL 
		AND COALESCE(LOWER(status), 'open') NOT IN ('resolved', 'fixed', 'closed', 'mitigated', 'risk_accepted', 'accepted_risk', 'false_positive')
		AND CURRENT_TIMESTAMP > sla_deadline
	`)
	return err
}

func (r *FindingRepository) UpdateKanbanColumn(ctx context.Context, id int64, column string) error {
	switch column {
	case "backlog", "todo", "in_progress", "review", "done":
	default:
		return fmt.Errorf("invalid kanban column")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE findings SET kanban_column = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, column, id)
	return findingUpdateResult(res, err)
}

func (r *FindingRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	status, valid := models.NormalizeFindingStatus(status)
	if !valid {
		return fmt.Errorf("invalid finding status")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE findings SET status = ?,
 resolved_at = CASE WHEN ? IN ('resolved', 'closed', 'mitigated') THEN COALESCE(resolved_at, CURRENT_TIMESTAMP) ELSE NULL END,
 verification_status = NULL, verification_summary = NULL,
 is_verified = 0, verified_at = NULL, verified_by = NULL,
 is_false_positive = (? = 'false_positive'), risk_accepted = (? = 'risk_accepted'),
 kanban_column = CASE WHEN ? IN ('resolved', 'closed', 'mitigated', 'false_positive', 'risk_accepted') THEN 'done'
 WHEN kanban_column = 'done' THEN 'backlog' ELSE kanban_column END,
 updated_at = CURRENT_TIMESTAMP WHERE id = ?`, status, status, status, status, status, id)
	return findingUpdateResult(res, err)
}

func findingUpdateResult(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *FindingRepository) MarkAgentPromptGenerated(ctx context.Context, id int64, prompt string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE findings
		SET agent_prompt = ?,
		    agent_prompt_generated_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, prompt, id)
	return err
}

func (r *FindingRepository) MarkPendingVerification(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE findings
		SET status = 'pending_verification',
		    kanban_column = 'in_progress',
		    verification_status = 'running',
		    verification_summary = NULL,
		    verification_last_run_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id)
	return err
}

func (r *FindingRepository) MarkVerificationResult(ctx context.Context, id int64, fixed bool, summary string) error {
	if fixed {
		_, err := r.db.ExecContext(ctx, `
			UPDATE findings
			SET status = 'resolved',
			    kanban_column = 'done',
			    is_verified = 1,
			    verified_at = CURRENT_TIMESTAMP,
			    resolved_at = CURRENT_TIMESTAMP,
			    verification_status = 'fixed',
			    verification_summary = ?,
			    verification_last_run_at = CURRENT_TIMESTAMP,
			    verification_last_success_at = CURRENT_TIMESTAMP,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, summary, id)
		return err
	}

	_, err := r.db.ExecContext(ctx, `
		UPDATE findings
		SET status = 'verification_failed',
		    kanban_column = 'in_progress',
		    is_verified = 0,
		    verified_at = NULL,
		    resolved_at = NULL,
		    verification_status = 'not_fixed',
		    verification_summary = ?,
		    verification_last_run_at = CURRENT_TIMESTAMP,
		    verification_last_success_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, summary, id)
	return err
}

func (r *FindingRepository) UpdateAITriage(ctx context.Context, id int64, status, summary string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE findings SET ai_triage_status = ?, ai_triage_summary = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, status, summary, id)
	return err
}

// A failed scanner says nothing about whether the original finding was fixed.
func (r *FindingRepository) MarkVerificationError(ctx context.Context, id int64, previousStatus, summary string) error {
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
	}
	_, err := r.db.ExecContext(ctx, `UPDATE findings SET status = ?, verification_status = 'error', verification_summary = ?, verification_last_run_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, previousStatus, summary, id)
	return err
}
