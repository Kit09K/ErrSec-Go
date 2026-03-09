package report

import (
	"encoding/json"
	"io"

	errtypes "github.com/errsec/errsec/pkg/types"
)

// JSONFormatter writes a machine-readable JSON report.
type JSONFormatter struct{}

type jsonReport struct {
	ErrSecVersion string       `json:"errsec_version"`
	Target        string       `json:"target"`
	Stats         jsonStats    `json:"stats"`
	Issues        []jsonIssue  `json:"issues"`
}

type jsonStats struct {
	FunctionsAnalysed int   `json:"functions_analysed"`
	FunctionsSkipped  int   `json:"functions_skipped"`
	PackagesLoaded    int   `json:"packages_loaded"`
	DurationMs        int64 `json:"duration_ms"`
}

type jsonIssue struct {
	ID           int        `json:"id"`
	Pattern      string     `json:"pattern"`
	Risk         string     `json:"risk"`
	FuncName     string     `json:"func,omitempty"`
	File         string     `json:"file,omitempty"`
	Line         int        `json:"line,omitempty"`
	SourcePkg    string     `json:"source_pkg,omitempty"`
	SourceFunc   string     `json:"source_func,omitempty"`
	SourceReason string     `json:"source_reason,omitempty"`
	Path         []jsonStep `json:"path,omitempty"`
}

type jsonStep struct {
	Kind     string `json:"kind"`
	FuncName string `json:"func,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

func (f *JSONFormatter) Write(w io.Writer, r *Result) error {
	report := jsonReport{
		ErrSecVersion: version,
		Target:        r.Target,
		Stats: jsonStats{
			FunctionsAnalysed: r.Stats.FunctionsAnalysed,
			FunctionsSkipped:  r.Stats.FunctionsSkipped,
			PackagesLoaded:    r.Stats.PackagesLoaded,
			DurationMs:        r.Duration.Milliseconds(),
		},
	}

	for _, iss := range r.Issues {
		ji := jsonIssue{
			ID:           iss.ID,
			Pattern:      string(iss.Pattern),
			Risk:         iss.Risk.String(),
			FuncName:     iss.FuncName,
			File:         iss.File,
			Line:         iss.Line,
			SourcePkg:    iss.SourcePkg,
			SourceFunc:   iss.SourceFunc,
			SourceReason: iss.SourceReason,
		}
		for _, step := range iss.Path {
			ji.Path = append(ji.Path, jsonStep{
				Kind:     string(step.Kind),
				FuncName: step.FuncName,
				File:     step.File,
				Line:     step.Line,
				Detail:   step.Detail,
			})
		}
		report.Issues = append(report.Issues, ji)
	}

	if report.Issues == nil {
		report.Issues = []jsonIssue{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// riskFromIssue extracts risk string for JSON (helper).
func riskFromIssue(r errtypes.RiskLevel) string {
	return r.String()
}
