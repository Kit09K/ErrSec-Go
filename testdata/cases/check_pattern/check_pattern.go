// Package check_pattern tests PatternCheck (err != nil conditional) in
// various scenarios: propagated, early-return, ignored branch.
//
// ErrSec expected findings:
//   SITE-1  err!=nil check  database/sql  PropagatedCheck   line 26  flow: propagated
//   SITE-2  err!=nil check  database/sql  IgnoredErrBranch  line 40  flow: discarded
//   SITE-3  err!=nil check  net/http      CheckThenContinue line 55  flow: discarded
//   SITE-4  err!=nil check  database/sql  DoubleCheck       line 68  flow: propagated
package check_pattern

import (
	"database/sql"
	"errors"
	"net/http"
)

// SITE-1: err != nil, then err returned — CORRECTLY propagated.
// Flow path: err from QueryRow → check site → return err (propagated).
// ErrSec reports this; mutation = "propagated" throughout — informational.
func PropagatedCheck(db *sql.DB, id int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM users WHERE id = ?", id).Scan(&name)
	if err != nil {
		return "", err
	}
	return name, nil
}

// SITE-2: err != nil check but the error branch sets err = nil before continuing.
// This is a subtle fail-open: the error is "acknowledged" but then discarded.
// Flow path: err from Exec → check site → err = nil (discarded) → continue.
func IgnoredErrBranch(db *sql.DB, userID int) {
	_, err := db.Exec("UPDATE users SET last_login = NOW() WHERE id = ?", userID)
	if err != nil {
		// "best effort" — silently clear the error
		err = nil //nolint
	}
	_ = err // suppress unused warning
}

// SITE-3: err != nil check, but the else-branch continues execution
// with data that was only valid if the call succeeded.
// Fail-open: if http.Get fails, resp is nil — the caller continues with nil resp.
func CheckThenContinue(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		// log and FALL THROUGH — this is the fail-open
		_ = err
	}
	if resp != nil {
		return resp.StatusCode
	}
	return 0
}

// SITE-4: err != nil followed by errors.Is check — double-check pattern.
// Both checks are reported; both show propagated flow (correct handling).
func DoubleCheck(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // not found is OK
		}
		return err
	}
	return nil
}
