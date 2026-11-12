package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dodobrands/aitriage/internal/models"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, email, full_name, password_hash, global_role, is_active, avatar_url, created_at, updated_at, last_login 
		FROM users WHERE username = ?
	`, username)
	return scanUser(row)
}

func (r *UserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, email, full_name, password_hash, global_role, is_active, avatar_url, created_at, updated_at, last_login 
		FROM users WHERE id = ?
	`, id)
	return scanUser(row)
}

func (r *UserRepository) Create(ctx context.Context, u *models.User) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO users (username, email, full_name, password_hash, global_role, is_active, avatar_url)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, u.Username, u.Email, u.FullName, u.PasswordHash, u.GlobalRole, u.IsActive, u.AvatarURL)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *UserRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]models.User, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, email, full_name, password_hash, global_role, is_active, avatar_url, created_at, updated_at, last_login 
		FROM users 
		ORDER BY username ASC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, nil
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*models.User, error) {
	var u models.User
	err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.PasswordHash, &u.GlobalRole, &u.IsActive, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &u, nil
}
