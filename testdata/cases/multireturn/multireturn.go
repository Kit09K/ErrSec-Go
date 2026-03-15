// Package multireturn tests detection on multi-return call sites where
// the error is one of several return values (FR-03 tuple extraction).
//
// ErrSec expected findings:
//   SITE-1  blank identifier  database/sql  DiscardSecond   line 24  (err = second return)
//   SITE-2  blank identifier  net/http      DiscardSecond2  line 34  (err = second return)
//   SITE-3  blank identifier  database/sql  DiscardBoth     line 44  (both returns discarded)
//   SITE-4  err!=nil check    database/sql  CheckSecond     line 54  flow: propagated
package multireturn

import (
	"database/sql"
	"net/http"
	"io"
)

// SITE-1: first return (sql.Result) captured, error (second) discarded.
// *ssa.Extract for index=1 (error) has no referrers → PatternBlank.
func DiscardSecond(db *sql.DB) sql.Result {
	result, _ := db.Exec("INSERT INTO events(ts) VALUES(NOW())")
	return result
}

// SITE-2: *http.Response captured, error discarded.
func DiscardSecond2(url string) *http.Response {
	resp, _ := http.Get(url)
	return resp
}

// SITE-3: both returns discarded — db.Exec result AND error both blank.
// ErrSec must detect the error element even when ALL elements are blank.
func DiscardBoth(db *sql.DB) {
	_, _ = db.Exec("UPDATE counters SET val=val+1 WHERE name=?", "requests")
}

// SITE-4: error (second return) captured and checked — correct handling.
// ErrSec reports the check site; flow path shows propagated → return.
func CheckSecond(db *sql.DB) error {
	_, err := db.Exec("INSERT INTO events(ts) VALUES(NOW())")
	if err != nil {
		return err
	}
	return nil
}

// Edge case: function with 3 returns — error is the third element.
func ThreeReturns(db *sql.DB, id int) (string, int, error) {
	row := db.QueryRow("SELECT name, age FROM users WHERE id=?", id)
	var name string
	var age int
	err := row.Scan(&name, &age)
	return name, age, err // error properly returned — no finding expected
}
