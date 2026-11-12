package repositories

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// IgnoredFinding represents a suppressed vulnerability finding.
type IgnoredFinding struct {
	ID                 int64     `json:"id"`
	VulnID             string    `json:"vulnId"`
	RuleID             string    `json:"ruleId"`
	FilePath           string    `json:"filePath"`
	LineNumber         int       `json:"lineNumber,omitempty"`
	CodeSnippet        string    `json:"codeSnippet,omitempty"`
	ContentHash        string    `json:"contentHash"`
	VulnerabilityClass string    `json:"vulnerabilityClass,omitempty"`
	Reason             string    `json:"reason"`
	CreatedAt          time.Time `json:"timestamp"`
	CreatedBy          string    `json:"createdBy,omitempty"`
}

// IgnoreRepository manages the ignored_findings table.
type IgnoreRepository struct {
	db *sql.DB
}

// NewIgnoreRepository creates a new IgnoreRepository.
func NewIgnoreRepository(db *sql.DB) *IgnoreRepository {
	return &IgnoreRepository{db: db}
}

// ContentHash computes a stable hash from the trimmed code snippet.
// This matches SecureCoder's behavior: keyed on content hash of trimmed line text,
// so the suppression survives line number shifts.
func ContentHash(codeSnippet string) string {
	trimmed := strings.TrimSpace(codeSnippet)
	h := sha256.Sum256([]byte(trimmed))
	return fmt.Sprintf("%x", h[:])
}

// VulnID constructs a unique vulnerability identifier matching SecureCoder format.
func VulnID(filePath string, lineNumber int, ruleID string) string {
	return fmt.Sprintf("%s:%d:%s", filePath, lineNumber, ruleID)
}

// Create inserts a new ignored finding.
func (r *IgnoreRepository) Create(ctx context.Context, entry IgnoredFinding) (*IgnoredFinding, error) {
	// Compute content hash if not provided
	if entry.ContentHash == "" && entry.CodeSnippet != "" {
		entry.ContentHash = ContentHash(entry.CodeSnippet)
	}
	// Compute vuln ID if not provided
	if entry.VulnID == "" {
		entry.VulnID = VulnID(entry.FilePath, entry.LineNumber, entry.RuleID)
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO ignored_findings (vuln_id, rule_id, file_path, line_number, code_snippet, content_hash, vulnerability_class, reason, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(vuln_id) DO UPDATE SET
			reason = excluded.reason,
			code_snippet = excluded.code_snippet,
			content_hash = excluded.content_hash,
			created_at = CURRENT_TIMESTAMP
	`, entry.VulnID, entry.RuleID, entry.FilePath, entry.LineNumber, entry.CodeSnippet,
		entry.ContentHash, entry.VulnerabilityClass, entry.Reason, entry.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to create ignored finding: %w", err)
	}

	id, _ := result.LastInsertId()
	entry.ID = id
	entry.CreatedAt = time.Now()
	return &entry, nil
}

// List returns all ignored findings.
func (r *IgnoreRepository) List(ctx context.Context) ([]IgnoredFinding, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, vuln_id, rule_id, file_path, line_number, COALESCE(code_snippet,''), content_hash,
		       COALESCE(vulnerability_class,''), reason, created_at, COALESCE(created_by,'')
		FROM ignored_findings
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list ignored findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []IgnoredFinding
	for rows.Next() {
		var e IgnoredFinding
		if err := rows.Scan(&e.ID, &e.VulnID, &e.RuleID, &e.FilePath, &e.LineNumber,
			&e.CodeSnippet, &e.ContentHash, &e.VulnerabilityClass, &e.Reason,
			&e.CreatedAt, &e.CreatedBy); err != nil {
			return nil, fmt.Errorf("failed to scan ignored finding: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Delete removes a suppressed finding by vulnId.
func (r *IgnoreRepository) Delete(ctx context.Context, vulnID string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM ignored_findings WHERE vuln_id = ?`, vulnID)
	if err != nil {
		return fmt.Errorf("failed to delete ignored finding: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("ignored finding not found: %s", vulnID)
	}
	return nil
}

// ClearAll removes all suppressed findings.
func (r *IgnoreRepository) ClearAll(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM ignored_findings`)
	return err
}
