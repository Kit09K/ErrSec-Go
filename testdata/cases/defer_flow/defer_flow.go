// Package defer_flow tests Smart CFG defer routing (FR-04).
//
// ErrSec expected behaviour:
//   SITE-1  err!=nil check  database/sql  DeferredRollback   line 33
//          Flow path MUST traverse the deferred Rollback block before exit,
//          because Smart CFG redirects return edges through defer chain.
//
//   SITE-2  blank identifier database/sql  DeferIgnoreClose  line 58
//          The deferred rows.Close() discards its error — ErrSec should
//          see MutationDiscarded inside the defer block.
package defer_flow

import (
	"database/sql"
	"fmt"
)

// SITE-1: Standard db transaction with deferred rollback.
// Smart CFG must route:
//   BeginTx → Exec → (defer Rollback runs before return) → Return
// Without defer routing, DFA would miss the Rollback block entirely.
func DeferredRollback(db *sql.DB, amount float64, fromID, toID int) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint — intentional: runs before every return

	_, err = tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, fromID)
	if err != nil {
		return fmt.Errorf("debit: %w", err) // defer Rollback runs here
	}

	_, err = tx.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toID)
	if err != nil {
		return fmt.Errorf("credit: %w", err) // defer Rollback runs here too
	}

	return tx.Commit()
}

// SITE-2: rows.Close() in defer — its error return is discarded.
// Smart CFG must include the defer block in the flow graph so that
// ErrSec can see that Close()'s error is a blank-identifier site.
func QueryWithDefer(db *sql.DB, query string) ([]string, error) {
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close() // SITE-2: Close error discarded inside defer
	}()

	var results []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// LIFO defer test: three defers — ErrSec must process them in reverse order.
// defer C runs first, then B, then A (last-in-first-out).
func MultiDefer(db *sql.DB) error {
	conn, err := db.Conn(nil)
	if err != nil {
		return err
	}
	defer conn.Close() // defer A — runs last

	tx, err := conn.BeginTx(nil, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // defer B — runs second
	defer func() {
		_ = tx.Commit() // defer C — runs first (LIFO)
	}()

	_, err = tx.Exec("INSERT INTO audit_log(event) VALUES(?)", "test")
	return err
}
