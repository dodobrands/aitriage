package store

import (
	"fmt"
	"strconv"
)

func ByTable(table string) string {
	q := fmt.Sprintf("SELECT * FROM %s WHERE id = $1", strconv.Quote(table))
	return q
}

func Limit(n int) string {
	return fmt.Sprintf("SELECT id FROM jobs ORDER BY min(created_at) LIMIT %d", n)
}
