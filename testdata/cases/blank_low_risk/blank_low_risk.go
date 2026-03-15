// Package blank_low_risk tests PatternBlank on Display and Logging packages.
//
// ErrSec expected findings (3 sites, all RISK: LOW):
//   SITE-1  blank identifier  fmt           PrintReport    line 21
//   SITE-2  blank identifier  html/template RenderPage     line 33
//   SITE-3  blank identifier  log/slog      WriteAuditLog  line 44
//
// LOW risk: OWASP TechnicalImpact score for Display/Logging is LOW (avg ~1.25).
// Fail-open consequences are cosmetic (garbled output) not security-critical.
package blank_low_risk

import (
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"os"
)

// SITE-1: fmt.Fprintf error discarded.
// Impact: display output may be truncated — not a security issue.
func PrintReport(w io.Writer, data string) {
	_, _ = fmt.Fprintf(w, "Report: %s
", data)
}

// SITE-2: template.Execute error discarded.
// Impact: page may render empty — cosmetic, no confidentiality/integrity impact.
func RenderPage(w io.Writer, tmpl *template.Template, data any) {
	_ = tmpl.Execute(w, data)
}

// SITE-3: slog handler Write error discarded.
// Impact: log entry lost — reduces auditability but does not directly
// enable security bypass (logging failures != authentication bypass).
func WriteAuditLog(msg string, attrs ...slog.Attr) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// slog.Logger.Info does not return error — this tests that
	// ErrSec does NOT flag calls that have no error return.
	logger.Info(msg) // NOT a finding
	// Explicit discard of a hypothetical write:
	_, _ = fmt.Fprintln(os.Stderr, "[AUDIT]", msg)
}
