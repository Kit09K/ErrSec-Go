package report

import (
	"fmt"
	"io"
	"strings"

	errtypes "github.com/errsec/errsec/pkg/types"
)

const version = "0.1.0"

// TextFormatter writes a human-readable report to w.
type TextFormatter struct{}

func (f *TextFormatter) Write(w io.Writer, r *Result) error {
	sep := strings.Repeat("=", 67)
	thin := strings.Repeat("-", 67)

	// ── Header ────────────────────────────────────────────────────────────
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, " ErrSec  v%s\n", version)
	fmt.Fprintf(w, " Target  : %s\n", r.Target)
	fmt.Fprintf(w, " Analysed: %d functions   Skipped: %d (complexity cap)\n",
		r.Stats.FunctionsAnalysed, r.Stats.FunctionsSkipped)

	high, med, low := countByRisk(r.Issues)
	fmt.Fprintf(w, " Found   : %d issue(s)   [HIGH: %d  MEDIUM: %d  LOW: %d]\n",
		len(r.Issues), high, med, low)
	fmt.Fprintf(w, " Duration: %dms\n", r.Duration.Milliseconds())
	fmt.Fprintln(w, sep)

	if len(r.Issues) == 0 {
		fmt.Fprintln(w, " No issues found.")
		fmt.Fprintln(w, sep)
		return nil
	}

	// ── Issues ────────────────────────────────────────────────────────────
	for _, iss := range r.Issues {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "ISSUE #%d  %s\n", iss.ID, thin[:len(thin)-len(fmt.Sprintf("ISSUE #%d  ", iss.ID))])
		fmt.Fprintf(w, "  Pattern : %s\n", iss.Pattern)
		fmt.Fprintf(w, "  Risk    : %s", riskLabel(iss.Risk))
		if iss.SourcePkg != "" {
			fmt.Fprintf(w, "   (%s)", iss.SourcePkg)
		}
		fmt.Fprintln(w)
		if iss.FuncName != "" {
			fmt.Fprintf(w, "  Function: %s\n", iss.FuncName)
		}
		if iss.File != "" {
			fmt.Fprintf(w, "  Location: %s:%d\n", iss.File, iss.Line)
		}

		if iss.Pattern == errtypes.PatternUnanalysable {
			fmt.Fprintln(w, "  Note    : Function exceeded complexity cap — analysis incomplete.")
			continue
		}

		if len(iss.Path) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Data-Flow Trace:")
			for i, step := range iss.Path {
				prefix := "    |"
				if i == 0 {
					prefix = "    +"
				}
				loc := ""
				if step.File != "" {
					loc = fmt.Sprintf("%s:%d", shortFile(step.File), step.Line)
				}
				fmt.Fprintf(w, "  %s\n", prefix)
				fmt.Fprintf(w, "  +-- [%-7s] %-20s  %s\n", step.Kind, loc, step.Detail)
			}
		}

		fmt.Fprintln(w)
		fmt.Fprintf(w, "  Source  : %s\n", iss.SourceReason)
		fmt.Fprintln(w, "  Decision: USER REVIEW REQUIRED")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, " Summary: %d issue(s) detected   HIGH=%d  MEDIUM=%d  LOW=%d\n",
		len(r.Issues), high, med, low)
	fmt.Fprintln(w, sep)
	return nil
}

func countByRisk(issues []*errtypes.Issue) (high, med, low int) {
	for _, iss := range issues {
		switch iss.Risk {
		case errtypes.HIGH:
			high++
		case errtypes.MEDIUM:
			med++
		case errtypes.LOW:
			low++
		}
	}
	return
}

func riskLabel(r errtypes.RiskLevel) string {
	switch r {
	case errtypes.HIGH:
		return "HIGH"
	case errtypes.MEDIUM:
		return "MEDIUM"
	case errtypes.LOW:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// shortFile trims a file path to the last two components for readability.
func shortFile(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return strings.Join(parts[len(parts)-2:], "/")
}
