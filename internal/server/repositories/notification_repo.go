package repositories

import (
	"context"
	"database/sql"

	"github.com/dodobrands/aitriage/internal/models"
)

type NotificationRepository struct {
	db *sql.DB
}

func NewNotificationRepository(db *sql.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

func (r *NotificationRepository) ListByUser(ctx context.Context, userID int64, unreadOnly bool) ([]models.Notification, error) {
	query := `SELECT id, user_id, title, body, type, is_read, link, created_at FROM notifications WHERE user_id = ?`
	if unreadOnly {
		query += ` AND is_read = 0`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var notifs []models.Notification
	for rows.Next() {
		var n models.Notification
		if err := rows.Scan(&n.ID, &n.UserID, &n.Title, &n.Body, &n.Type, &n.IsRead, &n.Link, &n.CreatedAt); err != nil {
			return nil, err
		}
		notifs = append(notifs, n)
	}
	return notifs, nil
}

func (r *NotificationRepository) MarkAsRead(ctx context.Context, id int64, userID int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (r *NotificationRepository) MarkAllAsRead(ctx context.Context, userID int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE notifications SET is_read = 1 WHERE user_id = ?`, userID)
	return err
}
