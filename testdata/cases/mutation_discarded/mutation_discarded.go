// Package mutation_discarded tests MutationDiscarded in various forms.
//
// ErrSec expected findings:
//   SITE-1  err!=nil check  database/sql  NilAssignDiscard    line 26  discarded
//   SITE-2  err!=nil check  net/http      ContinueAfterError  line 41  discarded
//   SITE-3  blank           database/sql  StoreAndForget      line 55  discarded
//   SITE-4  err!=nil check  database/sql  ReassignToNil       line 67  discarded
package mutation_discarded

import (
	"database/sql"
	"net/http"
	"io"
)

// SITE-1: err checked, then explicitly set to nil (discard).
// Classic fail-open: programmer acknowledges error but suppresses it.
func NilAssignDiscard(db *sql.DB, id int) error {
	_, err := db.Exec("UPDATE users SET status='deleted' WHERE id=?", id)
	if err != nil {
		err = nil // MutationDiscarded — error dropped here
	}
	return err // returns nil even when Exec failed
}

// SITE-2: error checked, logged to stderr via blank assignment, execution continues.
// Fail-open: program continues after a failed HTTP call as if it succeeded.
func ContinueAfterError(client *http.Client, url string) []byte {
	resp, err := client.Get(url)
	if err != nil {
		_ = err // MutationDiscarded — flow continues past error
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body
}

// SITE-3: var err error declared but never written after assignment, then
// the call's error is stored to blank. Subsequent uses see unset err.
func StoreAndForget(db *sql.DB) {
	var results []int
	rows, _ := db.Query("SELECT id FROM flagged_users")
	// ^ SITE-3: Query error discarded — rows may be nil
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			_ = rows.Scan(&id)
			results = append(results, id)
		}
	}
	_ = results
}

// SITE-4: error reassigned to a new call, then that call's error is nil-assigned.
func ReassignToNil(db *sql.DB, a, b int) error {
	_, err := db.Exec("INSERT INTO log(a) VALUES(?)", a)
	if err != nil {
		// reassign: err now points to a new Exec's error
		_, err = db.Exec("INSERT INTO fallback_log(a) VALUES(?)", a)
		if err != nil {
			err = nil // MutationDiscarded — second attempt also silently dropped
		}
	}
	return err
}
