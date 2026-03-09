//go:build ignore

// Ground truth: ISSUE EXPECTED — DEFER_IGNORE [HIGH]
package vuln

import "database/sql"

// CommitInsecure commits a transaction but discards the rollback error
// inside a deferred closure. ErrSec must detect this via defer-chain analysis.
func CommitInsecure(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() // line 17: DEFER_IGNORE [HIGH] — rollback error discarded
		}
	}()
	_, err = tx.Exec("INSERT INTO audit_log VALUES (NOW())")
	if err != nil {
		return err
	}
	return tx.Commit()
}
