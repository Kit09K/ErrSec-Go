//go:build ignore

// Ground truth: ISSUE EXPECTED — LOG_CONTINUE propagated through 2 function calls
package vuln

import (
	"database/sql"
	"log"
)

var globalDB *sql.DB

// openConnection wraps db.Open and propagates the error.
// ErrSec summary must mark ret[1] = TAINTED(HIGH).
func openConnection(dsn string) (*sql.DB, error) {
	return sql.Open("postgres", dsn)
}

// getDB calls openConnection — error propagated via IPA summary.
func getDB(dsn string) *sql.DB {
	db, err := openConnection(dsn) // line 20: SOURCE via IPA [HIGH]
	if err != nil {
		log.Printf("db connection failed: %v", err) // line 22: LOG
		// Falls through without returning — fail-open
	}
	return db // line 25: SINK — db may be nil
}

// UseDB calls getDB and uses the potentially-nil result.
func UseDB(dsn string) {
	db := getDB(dsn)
	db.Ping() // may panic if db is nil
}
