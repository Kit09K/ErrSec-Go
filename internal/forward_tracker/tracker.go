// Package forward_tracker implements forward data-flow tracking of an error value
// through the basic blocks of a Smart CFG (FR-06).
package forward_tracker

import (
	"fmt"
	"go/token"

	"github.com/errsec/errsec/internal/models"
	"github.com/errsec/errsec/internal/mutation_tracker"
	"github.com/errsec/errsec/internal/smart_cfg"
	"golang.org/x/tools/go/ssa"
)

// Tracker performs forward DFA for a single error value.
type Tracker struct {
	cfg        *smart_cfg.SmartCFG
	fset       *token.FileSet
	errVal     ssa.Value
	// sourceAddr is the alloc pointer that errVal was loaded from, or nil.
	//
	// In Go SSA, when a variable is assigned more than once the compiler
	// promotes it to an alloc+store+load pattern:
	//   t0 = new *error   (Alloc)
	//   *t0 = t2          (Store initial value)
	//   t6 = *t0          (UnOp load) ← errVal
	//
	// A subsequent "err = nil" compiles to Store(*t0, nil), not Store(t6, nil).
	// Without tracking t0 we would never see the nil-store → discard undetected.
	sourceAddr ssa.Value
}

// New creates a Tracker for errVal on the given Smart CFG.
// It automatically detects the alloc address if errVal is a load (UnOp *).
func New(cfg *smart_cfg.SmartCFG, fset *token.FileSet, errVal ssa.Value) *Tracker {
	t := &Tracker{cfg: cfg, fset: fset, errVal: errVal}
	// Detect alloc alias: if errVal is a pointer dereference (UnOp with Op=*)
	// record the base address so we can detect Store(nil, addr) later.
	if load, ok := errVal.(*ssa.UnOp); ok && load.Op == '*' {
		t.sourceAddr = load.X
	}
	return t
}

// Track runs BFS forward from startBlock, recording how errVal is used/mutated.
//
// Two special cases are handled beyond plain operand matching:
//  1. Alloc alias: Store(nil, sourceAddr) → MutationDiscarded even though
//     errVal (the loaded value) is not directly in the Store operands.
//  2. Fall-through discard: for PatternCheck, if the "true" branch of an
//     err != nil check reaches the end of a block without returning or panicking,
//     the error was silently dropped (fail-open by fall-through).
func (t *Tracker) Track(startBlock *ssa.BasicBlock) []models.FlowNode {
	type workItem struct {
		block   *ssa.BasicBlock
		tracked ssa.Value
	}

	var path []models.FlowNode
	visited := make(map[*ssa.BasicBlock]bool)
	queue := []workItem{{block: startBlock, tracked: t.errVal}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if visited[item.block] {
			continue
		}
		visited[item.block] = true
		currentVal := item.tracked

		for _, instr := range item.block.Instrs {
			// Check both direct value use and alloc-alias nil-store.
			directUse := instrUsesValue(instr, currentVal)
			aliasDiscard := t.isAliasNilStore(instr)

			if !directUse && !aliasDiscard {
				continue
			}

			var mut models.MutationType
			if aliasDiscard {
				// Store(nil, sourceAddr) regardless of whether errVal is an operand.
				mut = models.MutationDiscarded
			} else {
				mut = mutation_tracker.Inspect(instr, currentVal)
			}

			pos := t.fset.Position(instr.Pos())
			node := models.FlowNode{
				BlockIndex: item.block.Index,
				InstrText:  fmt.Sprintf("%s", instr),
				Mutation:   mut,
				File:       pos.Filename,
				Line:       pos.Line,
				Col:        pos.Column,
			}
			path = append(path, node)

			// After wrap/reassign, switch to tracking the new error value.
			if mut == models.MutationWrapped || mut == models.MutationReassigned {
				if call, ok := instr.(ssa.CallInstruction); ok {
					if v := call.Value(); v != nil {
						currentVal = v
					}
				}
			}
		}

		// Enqueue Smart CFG successors.
		for _, succ := range t.cfg.SuccessorsOf(item.block) {
			if !visited[succ] {
				queue = append(queue, workItem{block: succ, tracked: currentVal})
			}
		}
	}

	return path
}

// TrackBranch performs a branch-aware track for PatternCheck sites.
//
// For "if err != nil { … }" the SSA true-branch (Succs[0]) is the
// error-handling block. If that block does not terminate (return/panic)
// and no discard was already recorded, the error silently falls through —
// a fail-open by omission. We append a synthetic MutationDiscarded node
// to make this visible in the report.
//
// errorBranch is Succs[0] for NEQ conditions, Succs[1] for EQL.
func (t *Tracker) TrackBranch(startBlock *ssa.BasicBlock, ifInstr *ssa.If, isNEQ bool) []models.FlowNode {
	path := t.Track(startBlock)

	// Determine which successor is the "error is not nil" branch.
	var errBranch *ssa.BasicBlock
	if len(startBlock.Succs) >= 2 {
		if isNEQ {
			errBranch = startBlock.Succs[0] // true-branch for !=
		} else {
			errBranch = startBlock.Succs[1] // false-branch for ==
		}
	}

	// Check if any path node already records a discard.
	for _, n := range path {
		if n.Mutation == models.MutationDiscarded {
			return path // already detected; no synthetic node needed
		}
	}

	// If the error branch falls through (no return/panic → not properly handled)
	// append a synthetic node to mark this as a discard.
	if errBranch != nil && blockFallsThrough(errBranch) {
		pos := t.fset.Position(errBranch.Instrs[0].Pos())
		path = append(path, models.FlowNode{
			BlockIndex: errBranch.Index,
			InstrText:  "error branch falls through (no return/panic)",
			Mutation:   models.MutationDiscarded,
			File:       pos.Filename,
			Line:       pos.Line,
			Col:        pos.Column,
		})
	}

	return path
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// isAliasNilStore returns true when instr is a Store of nil to sourceAddr.
// This detects the "err = nil" pattern when err is alloc-promoted:
//   *alloc = nil:error  ← operands are (alloc, nil), errVal (loaded value) is NOT here
func (t *Tracker) isAliasNilStore(instr ssa.Instruction) bool {
	if t.sourceAddr == nil {
		return false
	}
	store, ok := instr.(*ssa.Store)
	if !ok {
		return false
	}
	if store.Addr != t.sourceAddr {
		return false
	}
	c, ok := store.Val.(*ssa.Const)
	return ok && c.IsNil()
}

// instrUsesValue returns true if instr directly references v as an operand.
func instrUsesValue(instr ssa.Instruction, v ssa.Value) bool {
	for _, op := range instr.Operands(nil) {
		if op != nil && *op == v {
			return true
		}
	}
	return false
}

// blockFallsThrough returns true when block does NOT terminate with
// Return or Panic — meaning execution continues to a merge point
// without explicitly propagating or handling the error.
func blockFallsThrough(block *ssa.BasicBlock) bool {
	if len(block.Instrs) == 0 {
		return true
	}
	switch block.Instrs[len(block.Instrs)-1].(type) {
	case *ssa.Return, *ssa.Panic:
		return false
	default:
		return true
	}
}
