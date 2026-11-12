package store

import (
	"context"
	"database/sql"
	"fmt"
)

func FindByName(ctx context.Context, db *sql.DB, name string) (*sql.Rows, error) {
	// ruleid: GO-SQLI
	return db.QueryContext(ctx, fmt.Sprintf(`SELECT id FROM users WHERE name = '%s'`, name))
}
