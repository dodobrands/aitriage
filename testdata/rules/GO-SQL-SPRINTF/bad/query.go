package store

import "fmt"

func ByName(name string) string {
	// ruleid: GO-SQL-SPRINTF
	query := fmt.Sprintf(`SELECT * FROM users WHERE name = '%s'`, name)
	return query
}
