// Package classifier implements Stage 3: Source Classifier.
// It labels call sites with risk levels using a two-tier rule-based engine.
// Layer 3 — imports pkg/types, pkg/config, internal/loader.
package classifier

import (
	"strings"

	errtypes "github.com/errsec/errsec/pkg/types"
)

// ClassifierRule is a single entry in the risk classification rule table.
type ClassifierRule struct {
	// PkgPattern is a Go import-path prefix to match against.
	PkgPattern string
	// FuncPattern is an optional function/method name to match ("" = any function).
	FuncPattern string
	// Risk is the risk level assigned when this rule fires.
	Risk errtypes.RiskLevel
	// Reason is a human-readable explanation.
	Reason string
}

// BuiltinRules is the default rule table, evaluated in order.
// Rules are listed HIGH → LOW so the first match wins (highest risk).
var BuiltinRules = []ClassifierRule{

	// ── HIGH: Database ────────────────────────────────────────────────────
	{"database/sql", "", errtypes.HIGH, "SQL database I/O"},
	{"gorm.io/gorm", "", errtypes.HIGH, "ORM database layer"},
	{"go.mongodb.org/mongo-driver", "", errtypes.HIGH, "MongoDB driver"},
	{"github.com/go-redis", "", errtypes.HIGH, "Redis client"},
	{"github.com/jackc/pgx", "", errtypes.HIGH, "PostgreSQL driver (pgx)"},
	{"github.com/lib/pq", "", errtypes.HIGH, "PostgreSQL driver (pq)"},
	{"github.com/mattn/go-sqlite3", "", errtypes.HIGH, "SQLite driver"},

	// ── HIGH: Cryptography ────────────────────────────────────────────────
	{"crypto/", "", errtypes.HIGH, "Cryptographic operation"},
	{"golang.org/x/crypto", "", errtypes.HIGH, "Extended cryptography"},

	// ── HIGH: Network / RPC ──────────────────────────────────────────────
	{"net/http", "Do", errtypes.HIGH, "Outbound HTTP request"},
	{"net/http", "Get", errtypes.HIGH, "Outbound HTTP GET"},
	{"net/http", "Post", errtypes.HIGH, "Outbound HTTP POST"},
	{"net/http", "PostForm", errtypes.HIGH, "Outbound HTTP PostForm"},
	{"net/http", "ListenAndServe", errtypes.HIGH, "HTTP server start"},
	{"net/http", "ListenAndServeTLS", errtypes.HIGH, "HTTPS server start"},
	{"net/", "", errtypes.HIGH, "Network I/O"},
	{"google.golang.org/grpc", "", errtypes.HIGH, "gRPC remote call"},
	{"github.com/grpc-ecosystem", "", errtypes.HIGH, "gRPC ecosystem"},

	// ── HIGH: Authentication ──────────────────────────────────────────────
	{"github.com/golang-jwt", "", errtypes.HIGH, "JWT authentication"},
	{"golang.org/x/oauth2", "", errtypes.HIGH, "OAuth2 authentication"},

	// ── MEDIUM: File I/O ──────────────────────────────────────────────────
	{"os", "", errtypes.MEDIUM, "OS / file operation"},
	{"io", "", errtypes.MEDIUM, "Generic I/O"},
	{"io/ioutil", "", errtypes.MEDIUM, "I/O utility (deprecated but common)"},
	{"bufio", "", errtypes.MEDIUM, "Buffered I/O"},
	{"path/filepath", "", errtypes.MEDIUM, "File path operation"},

	// ── MEDIUM: Serialisation ─────────────────────────────────────────────
	{"encoding/json", "", errtypes.MEDIUM, "JSON serialisation"},
	{"encoding/xml", "", errtypes.MEDIUM, "XML serialisation"},
	{"encoding/gob", "", errtypes.MEDIUM, "Gob serialisation"},
	{"gopkg.in/yaml", "", errtypes.MEDIUM, "YAML parsing"},
	{"github.com/BurntSushi/toml", "", errtypes.MEDIUM, "TOML parsing"},

	// ── LOW: Logging ──────────────────────────────────────────────────────
	{"log", "", errtypes.LOW, "Log output"},
	{"fmt", "Fprintf", errtypes.LOW, "Formatted output to writer"},
	{"fmt", "Fprintln", errtypes.LOW, "Formatted output to writer"},
}

// matchRule checks if pkgPath + funcName matches rule.
func matchRule(rule ClassifierRule, pkgPath, funcName string) bool {
	if !strings.HasPrefix(pkgPath, rule.PkgPattern) {
		return false
	}
	if rule.FuncPattern == "" {
		return true
	}
	return rule.FuncPattern == funcName
}
