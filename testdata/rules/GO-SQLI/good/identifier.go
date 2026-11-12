package store

import "database/sql"

// The table name is concatenated; the value is a placeholder.
func ByID(db *sql.DB, tbl string, id int) *sql.Row {
	return db.QueryRow("SELECT value FROM "+tbl+" WHERE id = ?", id)
}

func Cast(db *sql.DB, typ string, v any) *sql.Row {
	return db.QueryRow("select $1::"+typ+"::text", v)
}
