// Package defer_handler simulates Go's defer execution semantics within the CFG.
// In Go, deferred calls run in LIFO order before the function returns or panics.
// This package identifies defer blocks in an SSA function so that smart_cfg can
// redirect return/panic edges through them, reflecting actual execution order (FR-04).
package defer_handler

import (
	"golang.org/x/tools/go/ssa"
)

// DeferBlock holds the basic block that contains a defer instruction and the
// SSA defer instruction itself.
type DeferBlock struct {
	Block *ssa.BasicBlock
	Instr *ssa.Defer
}

// CollectDefers returns all defer instructions in fn, in the order they appear
// across basic blocks.  The caller (smart_cfg) reverses the list to implement
// LIFO defer execution semantics.
func CollectDefers(fn *ssa.Function) []DeferBlock {
	var defers []DeferBlock
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if d, ok := instr.(*ssa.Defer); ok {
				defers = append(defers, DeferBlock{Block: block, Instr: d})
			}
		}
	}
	return defers
}

// HasDefers returns true if fn contains at least one defer instruction.
func HasDefers(fn *ssa.Function) bool {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if _, ok := instr.(*ssa.Defer); ok {
				return true
			}
		}
	}
	return false
}

// DeferChain returns the defer blocks in LIFO execution order (last deferred
// runs first).  The returned slice may be empty when fn has no defers.
func DeferChain(fn *ssa.Function) []DeferBlock {
	defers := CollectDefers(fn)
	// Reverse for LIFO order
	for i, j := 0, len(defers)-1; i < j; i, j = i+1, j-1 {
		defers[i], defers[j] = defers[j], defers[i]
	}
	return defers
}
