package store

import (
	"database/sql"
	"fmt"
)

func FindUser(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE id = $1", id)
}

// The table name is an identifier; the value is still a parameter.
func Count(db *sql.DB, table string, id int) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s WHERE owner = $1", quote(table)), id)
}

func quote(s string) string { return `"` + s + `"` }

// A cache lookup with a concatenated key is not SQL.
func Lookup(c interface{ Get(string) string }, user string) string {
	return c.Get("user:" + user)
}
