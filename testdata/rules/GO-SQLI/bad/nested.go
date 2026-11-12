package store

import "database/sql"

func Search(db *sql.DB, table, name string) (*sql.Rows, error) {
	// ruleid: GO-SQLI
	return db.Query("SELECT * FROM " + table + " WHERE name = '" + name + "'")
}
