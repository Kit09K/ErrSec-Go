// Package complexity_capper counts jump-condition instructions (If instructions)
// in a function and enforces the safety cap N=1000 (FR-08).
//
// Functions exceeding the cap are marked "unanalyzable" so DFA terminates
// immediately, preventing path explosion on deeply branching code.
package complexity_capper

import (
	"golang.org/x/tools/go/ssa"
)

// Cap is the maximum number of jump conditions allowed before DFA is aborted.
const Cap = 1000

// Count returns the total number of If (conditional branch) instructions in fn.
// Each If instruction corresponds to one jump condition (one binary decision point).
func Count(fn *ssa.Function) int {
	count := 0
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if _, ok := instr.(*ssa.If); ok {
				count++
			}
		}
	}
	return count
}

// ExceedsCap returns true if fn's jump-condition count exceeds Cap.
func ExceedsCap(fn *ssa.Function) bool {
	return Count(fn) > Cap
}
