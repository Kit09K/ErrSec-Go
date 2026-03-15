// Package blank_db tests PatternBlank (blank identifier) on database/sql calls.
//
// ErrSec expected findings (3 sites, all RISK: HIGH):
//   SITE-1  blank identifier  database/sql  FetchUserByID     line 29
//   SITE-2  blank identifier  database/sql  ListUsers         line 38
//   SITE-3  blank identifier  database/sql  TransferFunds     line 48
//   SITE-4  (no finding)      SafeFetch — error properly checked and returned
package blank_db

import (
	"context"
	"database/sql"
)

// SITE-1: Scan() error assigned to blank identifier.
// Fail-open: if Scan fails (no rows / type mismatch), execution continues
// and the caller receives zero-value name/age as if the query succeeded.
func FetchUserByID(db *sql.DB, id int) (string, int) {
	var name string
	var age int
	_ = db.QueryRow("SELECT name, age FROM users WHERE id = ?", id).Scan(&name, &age)
	return name, age
}

// SITE-2: db.Exec returns (sql.Result, error); both elements discarded.
// Fail-open: DELETE may have failed silently — expired sessions stay alive.
func PurgeSessions(db *sql.DB) {
	_, _ = db.Exec("DELETE FROM sessions WHERE expired = 1")
}

// SITE-3: db.BeginTx error discarded — tx is nil when Begin fails,
// subsequent tx.Exec will panic (nil dereference = hard crash = availability loss).
func TransferFunds(db *sql.DB, from, to int, amount float64) {
	tx, _ := db.BeginTx(context.Background(), nil)
	tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, from) //nolint
	tx.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, to)   //nolint
	tx.Commit()                                                                      //nolint
}

// CORRECT: error is checked and propagated — ErrSec reports the check site
// but flow path shows propagated (no discard), so severity is informational only.
func SafeFetch(db *sql.DB, id int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM users WHERE id = ?", id).Scan(&name)
	if err != nil {
		return "", err
	}
	return name, nil
}
