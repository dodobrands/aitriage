package repositories

import (
	"context"
	"database/sql"

	"github.com/dodobrands/aitriage/internal/models"
)

type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) List(ctx context.Context, entityType string, limit, offset int) ([]models.AuditLog, error) {
	query := `
		SELECT id, user_id, username, action, entity_type, entity_id, old_value, new_value, ip_address, user_agent, created_at
		FROM audit_log
	`
	var args []any
	if entityType != "" {
		query += " WHERE entity_type = ?"
		args = append(args, entityType)
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.UserID, &l.Username, &l.Action, &l.EntityType, &l.EntityID, &l.OldValue, &l.NewValue, &l.IPAddress, &l.UserAgent, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}
