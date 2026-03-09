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
	cfg    *smart_cfg.SmartCFG
	fset   *token.FileSet
	errVal ssa.Value
}

// New creates a Tracker for errVal on the given Smart CFG.
func New(cfg *smart_cfg.SmartCFG, fset *token.FileSet, errVal ssa.Value) *Tracker {
	return &Tracker{cfg: cfg, fset: fset, errVal: errVal}
}

// Track runs the forward DFA starting at startBlock and returns the sequence of
// FlowNodes describing how errVal propagates through the program.
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
			if !instrUsesValue(instr, currentVal) {
				continue
			}

			mut := mutation_tracker.Inspect(instr, currentVal)
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

			// After wrapping/reassignment, track the new error value.
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

// instrUsesValue returns true if instr directly references v as an operand.
func instrUsesValue(instr ssa.Instruction, v ssa.Value) bool {
	for _, op := range instr.Operands(nil) {
		if op != nil && *op == v {
			return true
		}
	}
	return false
}
