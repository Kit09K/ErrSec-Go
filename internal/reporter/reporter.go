// Package reporter converts []FlowFact into a human-readable Text Data-Flow Graph
// written to stdout (FR-09).
package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/errsec/errsec/internal/models"
)

const (
	doubleLine = "══════════════════════════════════════════════════════════════════"
	singleLine = "──────────────────────────────────────────────────────────────────"
)

// Report writes the Text DFG report for all flow facts to w (FR-09).
// Facts with no valid source position (File == "") are silently skipped —
// these are residual synthetic functions that slipped past the SSA filter.
func Report(w io.Writer, facts []*models.FlowFact) {
	// Filter out facts with no source position (safety net).
	var valid []*models.FlowFact
	for _, f := range facts {
		if f.Site != nil && f.Site.File != "" && f.Site.Line > 0 {
			valid = append(valid, f)
		}
	}

	if len(valid) == 0 {
		fmt.Fprintln(w, "ErrSec: no fail-open error-handling sites found.")
		return
	}

	var normal, complex []*models.FlowFact
	for _, f := range valid {
		if f.TooComplex {
			complex = append(complex, f)
		} else {
			normal = append(normal, f)
		}
	}

	fmt.Fprintf(w, "\nErrSec — Data-Flow Graph Report\n")
	fmt.Fprintf(w, "Sites found: %d  (unanalyzable: %d)\n\n", len(valid), len(complex))

	for i, fact := range normal {
		printFact(w, fact, i+1)
	}

	if len(complex) > 0 {
		fmt.Fprintf(w, "\n%s\n", singleLine)
		fmt.Fprintf(w, "UNANALYZABLE FUNCTIONS (jump conditions > %d)\n", 1000)
		fmt.Fprintf(w, "%s\n", singleLine)
		for _, fact := range complex {
			s := fact.Site
			fmt.Fprintf(w, "  [RISK: %s] %s  │  %s:%d:%d\n",
				fact.Risk, s.Func.RelString(nil), basename(s.File), s.Line, s.Col)
		}
		fmt.Fprintln(w)
	}
}

func printFact(w io.Writer, fact *models.FlowFact, index int) {
	s := fact.Site

	fmt.Fprintf(w, "%s\n", doubleLine)
	fmt.Fprintf(w, "[%d] RISK: %-4s │ pattern: %s\n", index, fact.Risk, s.Pattern)

	if s.SourcePkg != "" {
		fmt.Fprintf(w, "  Origin  : %s\n", s.SourcePkg)
	}

	fmt.Fprintf(w, "  Location: %s:%d:%d\n", s.File, s.Line, s.Col)

	if s.Func != nil {
		fmt.Fprintf(w, "  Function: %s\n", s.Func.RelString(nil))
	}

	if len(fact.FlowPath) > 0 {
		fmt.Fprintf(w, "%s\n", singleLine)
		fmt.Fprintf(w, "  Flow path:\n")
		for _, node := range fact.FlowPath {
			// Skip flow nodes that also have no position (synthetic ops).
			if node.File == "" {
				continue
			}
			instr := truncate(node.InstrText, 60)
			loc := fmt.Sprintf("  %s:%d", basename(node.File), node.Line)
			fmt.Fprintf(w, "    [B%-3d] %-62s  %-12s%s\n",
				node.BlockIndex, instr, node.Mutation, loc)
		}
	} else {
		fmt.Fprintf(w, "  Flow path: (empty – error value not observed in forward flow)\n")
	}

	fmt.Fprintf(w, "%s\n\n", doubleLine)
}

func basename(path string) string {
	// Handle both Unix and Windows separators.
	path = strings.ReplaceAll(path, "\\", "/")
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
