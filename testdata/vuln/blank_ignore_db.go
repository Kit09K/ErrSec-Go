//go:build ignore

package vuln

import (
	"database/sql"
	"fmt"
)

// GetUserInsecure discards the database error with blank identifier.
// ErrSec MUST report: [HIGH] BLANK_IGNORE at db.Query()
func GetUserInsecure(db *sql.DB, id int) (*sql.Rows, error) {
	rows, _ := db.Query("SELECT * FROM users WHERE id = ?", id)
	return rows, nil
}

func CreateSessionInsecure(db *sql.DB, token string) {
	db.Exec("INSERT INTO sessions(token) VALUES(?)", token)
	fmt.Println("session created")
}
