// Package smart_cfg constructs a Smart CFG from an SSA function.
//
// A Smart CFG differs from the raw SSA CFG in one important respect (FR-04):
// edges that exit via Return or Panic are redirected to pass through the defer
// chain (in LIFO order) before leaving the function.  This faithfully models
// Go's "deferred calls run before return/panic" semantics so that the DFA can
// observe error mutations that occur inside deferred closures.
package smart_cfg

import (
	"github.com/errsec/errsec/internal/defer_handler"
	"golang.org/x/tools/go/ssa"
)

// EdgeKind classifies a CFG edge.
type EdgeKind int

const (
	EdgeNormal  EdgeKind = iota // ordinary successor edge
	EdgeDefer                   // synthetic edge through a defer block
	EdgeReturn                  // edge leaving the function after defers
	EdgePanic                   // edge for panic (after defers)
)

// Edge represents a directed edge in the Smart CFG.
type Edge struct {
	From *ssa.BasicBlock
	To   *ssa.BasicBlock
	Kind EdgeKind
}

// SmartCFG is the enhanced control-flow graph for a single SSA function.
type SmartCFG struct {
	Func       *ssa.Function
	Blocks     []*ssa.BasicBlock
	Edges      []Edge
	// Successors maps each block to its Smart CFG successors (including defer routing).
	Successors map[*ssa.BasicBlock][]*ssa.BasicBlock
	// DeferChain is the ordered list of defer blocks (LIFO execution order).
	DeferChain []defer_handler.DeferBlock
}

// Build constructs the Smart CFG for fn.
func Build(fn *ssa.Function) *SmartCFG {
	if fn.Blocks == nil {
		return &SmartCFG{Func: fn, Successors: make(map[*ssa.BasicBlock][]*ssa.BasicBlock)}
	}

	chain := defer_handler.DeferChain(fn)
	cfg := &SmartCFG{
		Func:       fn,
		Blocks:     fn.Blocks,
		Successors: make(map[*ssa.BasicBlock][]*ssa.BasicBlock),
		DeferChain: chain,
	}

	// Collect the set of defer blocks for quick lookup.
	deferBlockSet := make(map[*ssa.BasicBlock]bool)
	for _, db := range chain {
		deferBlockSet[db.Block] = true
	}

	for _, block := range fn.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}
		last := block.Instrs[len(block.Instrs)-1]

		switch last.(type) {
		case *ssa.Return:
			// Redirect Return through defer chain then to a virtual exit.
			succs := deferSuccessors(block, chain, EdgeReturn)
			cfg.Successors[block] = succs
			for _, s := range succs {
				cfg.Edges = append(cfg.Edges, Edge{From: block, To: s, Kind: EdgeDefer})
			}

		case *ssa.Panic:
			// Redirect Panic through defer chain.
			succs := deferSuccessors(block, chain, EdgePanic)
			cfg.Successors[block] = succs
			for _, s := range succs {
				cfg.Edges = append(cfg.Edges, Edge{From: block, To: s, Kind: EdgeDefer})
			}

		default:
			// Normal edges – use SSA successors directly.
			for _, succ := range block.Succs {
				cfg.Successors[block] = append(cfg.Successors[block], succ)
				cfg.Edges = append(cfg.Edges, Edge{From: block, To: succ, Kind: EdgeNormal})
			}
		}
	}

	return cfg
}

// deferSuccessors returns the first defer block (if any), otherwise the blocks
// already listed as successors in the SSA (or nil indicating function exit).
// In LIFO order, the first element of chain runs first.
func deferSuccessors(from *ssa.BasicBlock, chain []defer_handler.DeferBlock, _ EdgeKind) []*ssa.BasicBlock {
	if len(chain) == 0 {
		// No defers – return original successors (which may be empty for Return/Panic).
		return from.Succs
	}
	// Route through the first (outermost in LIFO) defer block.
	return []*ssa.BasicBlock{chain[0].Block}
}

// Successors returns the Smart CFG successors of block (after defer routing).
func (c *SmartCFG) SuccessorsOf(block *ssa.BasicBlock) []*ssa.BasicBlock {
	return c.Successors[block]
}
