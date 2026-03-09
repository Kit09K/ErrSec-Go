// Package report implements Stage 5: Report Generator.
// It formats analysis results for human-readable text and JSON output.
// Layer 5 — imports pkg/types, pkg/config only.
package report

import (
	"io"
	"time"

	errtypes "github.com/errsec/errsec/pkg/types"
	"github.com/errsec/errsec/pkg/config"
)

// Result is the complete output of one ErrSec analysis run.
type Result struct {
	Version  string
	Target   string
	Issues   []*errtypes.Issue
	Stats    errtypes.Stats
	Duration time.Duration
	Cfg      *config.Config
}

// NewResult constructs a Result.
func NewResult(version, target string, issues []*errtypes.Issue, stats errtypes.Stats, dur time.Duration, cfg *config.Config) *Result {
	return &Result{
		Version:  version,
		Target:   target,
		Issues:   issues,
		Stats:    stats,
		Duration: dur,
		Cfg:      cfg,
	}
}

// HasIssuesAbove reports whether any issues have risk >= minRisk.
func (r *Result) HasIssuesAbove(minRisk errtypes.RiskLevel) bool {
	for _, iss := range r.Issues {
		if iss.Risk >= minRisk {
			return true
		}
	}
	return false
}

// Formatter is the interface for all report output formats.
type Formatter interface {
	Write(w io.Writer, result *Result) error
}

// NewFormatter returns the appropriate Formatter for the given format string.
func NewFormatter(format string) Formatter {
	switch format {
	case "json":
		return &JSONFormatter{}
	default:
		return &TextFormatter{}
	}
}
