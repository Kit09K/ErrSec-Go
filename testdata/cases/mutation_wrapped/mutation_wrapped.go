// Package mutation_wrapped tests MutationWrapped detection.
//
// ErrSec expected findings:
//   SITE-1  err!=nil check  database/sql  WrapWithFmtErrorf   line 27  mutation: wrapped
//   SITE-2  err!=nil check  net/http      WrapChain           line 41  mutation: wrapped×2
//   SITE-3  blank           database/sql  WrapButDiscard      line 56  mutation: wrapped→discarded
package mutation_wrapped

import (
	"database/sql"
	"fmt"
	"net/http"
	"io"
)

// SITE-1: fmt.Errorf with %w wraps the error — ErrSec records MutationWrapped.
// This is good practice: context is added. Flow: err → wrapped → returned.
func WrapWithFmtErrorf(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		// MutationWrapped: fmt.Errorf uses err as %w argument
		return fmt.Errorf("delete user %d: %w", id, err)
	}
	return nil
}

// SITE-2: double-wrap chain — error wrapped twice before return.
// Flow: err → wrapped(1st fmt.Errorf) → wrapped(2nd fmt.Errorf) → returned.
// ErrSec should track the new error value after each wrap.
func WrapChain(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		err = fmt.Errorf("fetch %s: %w", url, err)     // wrap 1
		return fmt.Errorf("remote call failed: %w", err) // wrap 2
	}
	defer resp.Body.Close()
	if _, err = io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	return nil
}

// SITE-3: error is wrapped but then the wrapped error is discarded.
// Flow: err (blank) → MutationWrapped → MutationDiscarded.
// This is a fail-open despite wrapping: the final state is discard.
func WrapButDiscard(db *sql.DB, id int) {
	_, err := db.Exec("UPDATE users SET active=0 WHERE id=?", id)
	if err != nil {
		// wrap adds context but result is thrown away
		_ = fmt.Errorf("deactivate %d: %w", id, err)
	}
}
