//go:build ignore

package vuln

import (
	"database/sql"
)

// WriteRecordInsecure hides a rollback error inside a deferred closure.
// ErrSec should report: [HIGH] BLANK_IGNORE at tx.Rollback() inside defer
func WriteRecordInsecure(db *sql.DB, name string) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback() // VULNERABLE: rollback error silently discarded
		}
	}()
	_, err = tx.Exec("INSERT INTO records(name) VALUES(?)", name)
	if err != nil {
		return err
	}
	return tx.Commit()
}
