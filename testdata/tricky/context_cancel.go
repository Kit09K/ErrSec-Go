//go:build ignore

package tricky

import (
	"context"
	"database/sql"
	"errors"
	"log"
)

// QueryWithContext intentionally ignores context.Canceled.
// ErrSec will flag LOG_CONTINUE; developer should review.
func QueryWithContext(ctx context.Context, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.QueryContext(ctx, "SELECT 1")
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Printf("query cancelled: %v", err)
		} else {
			return nil, err
		}
	}
	return rows, nil
}
