package store

import "database/sql"

func FindUser(db *sql.DB, id string) (*sql.Rows, error) {
	// ruleid: GO-SQLI
	return db.Query("SELECT * FROM users WHERE id = " + id)
}
