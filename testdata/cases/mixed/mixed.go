// Package mixed combines multiple patterns in a single realistic file
// to test that ErrSec correctly identifies all sites independently.
//
// ErrSec expected findings (6 sites):
//   SITE-1  blank identifier  database/sql  Login          line 33  HIGH  discarded
//   SITE-2  err!=nil check    database/sql  Login          line 40  HIGH  propagated
//   SITE-3  blank identifier  crypto/       Login          line 50  HIGH  discarded
//   SITE-4  err!=nil check    net/http      FetchProfile   line 65  HIGH  discarded
//   SITE-5  blank identifier  fmt           AuditLog       line 79  LOW   discarded
//   SITE-6  err!=nil check    database/sql  DeleteAccount  line 91  HIGH  propagated
package mixed

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"net/http"
)

// Login: realistic authentication handler with multiple error sites.
//
// SITE-1: password hash load — blank identifier (fail-open: nil hash returned,
//         bcrypt.CompareHashAndPassword on nil would error and be ignored)
// SITE-2: session insert — err checked and propagated (correct)
// SITE-3: audit token generation — blank identifier on crypto/rand.Read
func Login(ctx context.Context, db *sql.DB, username, password string) (string, error) {
	// SITE-1: HIGH — hash lookup error discarded
	var hash []byte
	_ = db.QueryRowContext(ctx,
		"SELECT password_hash FROM users WHERE username=?", username,
	).Scan(&hash)
	// ^ fail-open: if QueryRow fails, hash is nil, all passwords "match"

	// SITE-2: HIGH — session insert error checked and returned
	sessionID := make([]byte, 16)
	_, err := db.ExecContext(ctx,
		"INSERT INTO sessions(token, username) VALUES(?,?)", sessionID, username,
	)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err) // propagated — correct
	}

	// SITE-3: HIGH — token entropy error discarded
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	// ^ fail-open: if Read fails, token bytes are zero → predictable session tokens

	return fmt.Sprintf("%x", token), nil
}

// FetchProfile: HTTP call with error check but discarded on fail-through.
//
// SITE-4: HIGH — err checked but execution continues with nil resp
func FetchProfile(client *http.Client, userID string) ([]byte, error) {
	url := "https://api.example.com/users/" + userID
	resp, err := client.Get(url)
	if err != nil {
		_ = err // SITE-4: discarded — execution falls through
	}
	if resp == nil {
		return nil, nil // returns nil,nil as if request succeeded with empty body
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// AuditLog: LOW risk — fmt.Fprintf error discarded.
//
// SITE-5: LOW — display error discarded (cosmetic impact only)
func AuditLog(w io.Writer, msg string) {
	_, _ = fmt.Fprintf(w, "[AUDIT] %s
", msg)
}

// DeleteAccount: correct error handling — should show propagated flow.
//
// SITE-6: HIGH — err checked; flow path shows wrapped → returned (correct)
func DeleteAccount(ctx context.Context, db *sql.DB, userID int) error {
	_, err := db.ExecContext(ctx, "DELETE FROM users WHERE id=?", userID)
	if err != nil {
		return fmt.Errorf("delete account %d: %w", userID, err)
	}
	return nil
}
