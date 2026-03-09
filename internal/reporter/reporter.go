// Package reporter converts []FlowFact into a human-readable Text Data-Flow Graph
// written to stdout (FR-09).
//
// Output format for each finding:
//
//   ══════════════════════════════════════════════════════════
//   [RISK: HIGH] fail-open site │ pattern: blank identifier
//   Origin : database/sql
//   Location: /path/to/file.go:42:8
//   Function: (*sql.DB).QueryRow
//   ──────────────────────────────────────────────────────────
//   Flow path:
//     [B0] t0 = db.QueryRow(...)  propagated   file.go:42
//     [B2] t1 = t0.1 :error       propagated   file.go:42
//     ...
//   ══════════════════════════════════════════════════════════
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
// Unanalyzable findings are reported separately at the end.
func Report(w io.Writer, facts []*models.FlowFact) {
	if len(facts) == 0 {
		fmt.Fprintln(w, "ErrSec: no fail-open error-handling sites found.")
		return
	}

	var normal, complex []*models.FlowFact
	for _, f := range facts {
		if f.TooComplex {
			complex = append(complex, f)
		} else {
			normal = append(normal, f)
		}
	}

	fmt.Fprintf(w, "\nErrSec — Data-Flow Graph Report\n")
	fmt.Fprintf(w, "Sites found: %d  (unanalyzable: %d)\n\n", len(facts), len(complex))

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

// printFact formats one FlowFact as a Text DFG entry.
func printFact(w io.Writer, fact *models.FlowFact, index int) {
	s := fact.Site

	fmt.Fprintf(w, "%s\n", doubleLine)
	fmt.Fprintf(w, "[%d] RISK: %-4s │ pattern: %s\n", index, fact.Risk, s.Pattern)

	// Origin
	if s.SourcePkg != "" {
		fmt.Fprintf(w, "  Origin  : %s\n", s.SourcePkg)
	}

	// Location
	fmt.Fprintf(w, "  Location: %s:%d:%d\n", s.File, s.Line, s.Col)

	// Function
	if s.Func != nil {
		fmt.Fprintf(w, "  Function: %s\n", s.Func.RelString(nil))
	}

	// Flow path
	if len(fact.FlowPath) > 0 {
		fmt.Fprintf(w, "%s\n", singleLine)
		fmt.Fprintf(w, "  Flow path:\n")
		for _, node := range fact.FlowPath {
			instr := truncate(node.InstrText, 60)
			loc := ""
			if node.File != "" {
				loc = fmt.Sprintf("  %s:%d", basename(node.File), node.Line)
			}
			fmt.Fprintf(w, "    [B%-3d] %-62s  %-12s%s\n",
				node.BlockIndex, instr, node.Mutation, loc)
		}
	} else {
		fmt.Fprintf(w, "  Flow path: (empty – error value not observed in forward flow)\n")
	}

	fmt.Fprintf(w, "%s\n\n", doubleLine)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func basename(path string) string {
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
