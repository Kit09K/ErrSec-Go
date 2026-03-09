// Package interprocedural tests inter-procedural analysis (FR-07).
//
// ErrSec expected behaviour:
//   After analysing helper(), its FunctionSummary records PropagatesError=true.
//   When analysing caller(), ErrSec looks up helper()'s summary and can
//   reason that the error from db.Exec propagates through helper() to caller().
//
// ErrSec expected findings:
//   SITE-1  blank           database/sql  helper       line 26  (internal blank)
//   SITE-2  err!=nil check  (via summary) callerOK     line 41  propagated
//   SITE-3  blank           (via summary) callerBad    line 51  discarded
package interprocedural

import (
	"database/sql"
	"fmt"
)

// helper: wraps a db.Exec and returns its error — PropagatesError=true.
// ErrSec stores FunctionSummary{PropagatesError: true} after analysing this.
func helper(db *sql.DB, query string, args ...any) error {
	_, err := db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("helper: %w", err)
	}
	return nil
}

// helperDiscard: wraps db.Exec but drops the error — DiscardsSomeError=true.
func helperDiscard(db *sql.DB, query string) {
	_, err := db.Exec(query)
	_ = err // SITE-1: discarded inside helper
}

// callerOK: calls helper() and properly handles the returned error.
// ErrSec uses helper()'s summary (PropagatesError=true) to understand
// that the original database error flows through helper() into callerOK().
func callerOK(db *sql.DB, id int) error {
	if err := helper(db, "DELETE FROM users WHERE id=?", id); err != nil {
		return err
	}
	return nil
}

// callerBad: calls helperDiscard() — the error is already gone inside helperDiscard.
// ErrSec uses helperDiscard()'s summary (DiscardsSomeError=true) and notes
// that any error from the underlying db.Exec is already lost before callerBad sees it.
func callerBad(db *sql.DB) {
	helperDiscard(db, "UPDATE stats SET requests=requests+1")
	// no check needed — helperDiscard never surfaces errors
}

// crossPackageSummary: calls a stdlib function whose summary may not be
// pre-computed — tests graceful handling of unknown callees.
func crossPackageSummary(db *sql.DB) error {
	return helper(db, "VACUUM")
}
