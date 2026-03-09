//go:build ignore

package safe

import "database/sql"

// MustConnect panics on failure — safe startup pattern.
func MustConnect(dsn string) *sql.DB {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		panic("database connection failed: " + err.Error())
	}
	return db
}
