//go:build ignore

package safe

import (
	"database/sql"
	"fmt"
)

// GetUserSafe correctly returns the error - ErrSec MUST NOT report an issue.
func GetUserSafe(db *sql.DB, id int) (*sql.Rows, error) {
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		return nil, fmt.Errorf("GetUserSafe: %w", err)
	}
	return rows, nil
}
