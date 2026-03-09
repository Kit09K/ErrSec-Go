package smartcfg

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"

	"github.com/errsec/errsec/internal/loader"
)

// Builder constructs a Smart CFG for a given SSA function.
type Builder struct {
	nextID int
	fset   *token.FileSet
}

// NewBuilder creates a new Smart CFG Builder.
func NewBuilder(fset *token.FileSet) *Builder {
	return &Builder{fset: fset}
}

// Build constructs and returns the Smart CFG for fn.
// The construction order is:
//  1. Wrap each SSA BasicBlock into an SCFGNode.
//  2. Connect edges, annotating error nil-checks.
//  3. Collect deferred calls.
//  4. Synthesise the LIFO defer chain before the exit node.
//  5. Rewire return/panic blocks to the defer chain head.
func (b *Builder) Build(fn *ssa.Function) *SCFG {
	if fn == nil || len(fn.Blocks) == 0 {
		return &SCFG{Func: fn, BlockToNode: map[int]*SCFGNode{}}
	}

	b.nextID = 0
	graph := &SCFG{
		Func:        fn,
		BlockToNode: make(map[int]*SCFGNode, len(fn.Blocks)),
	}

	// ── Step 1: create one SCFGNode per SSA BasicBlock ───────────────────
	for _, blk := range fn.Blocks {
		node := &SCFGNode{
			ID:       b.allocID(),
			Kind:     KindNormal,
			Block:    blk,
			Instrs:   blk.Instrs,
			FuncName: fn.Name(),
		}
		graph.Nodes = append(graph.Nodes, node)
		graph.BlockToNode[blk.Index] = node
	}

	// ── Step 2: create the synthetic exit node ────────────────────────────
	exitNode := &SCFGNode{
		ID:       b.allocID(),
		Kind:     KindExit,
		FuncName: fn.Name(),
	}
	graph.ExitNode = exitNode
	graph.Nodes = append(graph.Nodes, exitNode)

	// ── Step 3: connect edges between normal blocks ───────────────────────
	for _, blk := range fn.Blocks {
		srcNode := graph.BlockToNode[blk.Index]
		last := blk.Instrs[len(blk.Instrs)-1]

		switch term := last.(type) {
		case *ssa.If:
			// Annotate true/false edges with branch condition.
			trueCond, falseCond := b.buildBranchConds(term)
			if len(blk.Succs) >= 2 {
				trueNode := graph.BlockToNode[blk.Succs[0].Index]
				falseNode := graph.BlockToNode[blk.Succs[1].Index]
				srcNode.addSucc(trueNode, trueCond)
				srcNode.addSucc(falseNode, falseCond)
			}
		case *ssa.Jump:
			if len(blk.Succs) == 1 {
				dst := graph.BlockToNode[blk.Succs[0].Index]
				srcNode.addSucc(dst, nil)
			}
		case *ssa.Return:
			// Will be rewired to defer chain in step 5; temporarily point to exit.
			srcNode.addSucc(exitNode, nil)
		case *ssa.Panic:
			// Panic also flows through the defer chain.
			srcNode.addSucc(exitNode, nil)
		default:
			// For other terminators (RunDefers, etc.) connect to successors.
			for _, succ := range blk.Succs {
				dst := graph.BlockToNode[succ.Index]
				srcNode.addSucc(dst, nil)
			}
		}
	}

	// ── Step 4: collect defers in source order ────────────────────────────
	var deferInstrs []*ssa.Defer
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			if d, ok := instr.(*ssa.Defer); ok {
				deferInstrs = append(deferInstrs, d)
			}
		}
	}

	// ── Step 5: synthesise LIFO defer chain ──────────────────────────────
	// Build synthetic nodes in reverse order so the first defer runs last.
	if len(deferInstrs) > 0 {
		b.synthesiseDeferChain(fn, graph, deferInstrs, exitNode)
	}

	return graph
}

// allocID returns the next unique node ID.
func (b *Builder) allocID() int {
	id := b.nextID
	b.nextID++
	return id
}

// buildBranchConds inspects an ssa.If instruction and returns annotated
// BranchCond for the true and false branches.
// Returns (nil, nil) if the condition is not an error nil-check.
func (b *Builder) buildBranchConds(ifInstr *ssa.If) (trueCond, falseCond *BranchCond) {
	cond := ifInstr.Cond
	binop, ok := cond.(*ssa.BinOp)
	if !ok {
		return nil, nil
	}
	if binop.Op != token.NEQ && binop.Op != token.EQL {
		return nil, nil
	}

	// Identify which operand is the error value and which is nil.
	var errVal ssa.Value
	if isErrorType(binop.X.Type()) && isNilConst(binop.Y) {
		errVal = binop.X
	} else if isErrorType(binop.Y.Type()) && isNilConst(binop.X) {
		errVal = binop.Y
	}
	if errVal == nil {
		return nil, nil
	}

	// err != nil => true branch is the error path
	// err == nil => false branch is the error path
	trueIsErr := binop.Op == token.NEQ

	trueCond = &BranchCond{Value: errVal, IsNilCheck: true, TrueIsErr: trueIsErr}
	falseCond = &BranchCond{Value: errVal, IsNilCheck: true, TrueIsErr: !trueIsErr}
	return trueCond, falseCond
}

// synthesiseDeferChain inserts synthetic KindDefer nodes in LIFO order
// (last defer runs first) between return/panic blocks and the exit node.
func (b *Builder) synthesiseDeferChain(
	fn *ssa.Function,
	graph *SCFG,
	deferInstrs []*ssa.Defer,
	exitNode *SCFGNode,
) {
	// Create one synthetic node per defer, in reverse source order.
	// deferInstrs[n-1] is the last defer added, so it runs first.
	deferNodes := make([]*SCFGNode, len(deferInstrs))
	for i, d := range deferInstrs {
		// Reverse index: last defer in source order = index 0 in execution order.
		exIdx := len(deferInstrs) - 1 - i
		dn := &SCFGNode{
			ID:         b.allocID(),
			Kind:       KindDefer,
			DeferInstr: d,
			Instrs:     []ssa.Instruction{d},
			FuncName:   fn.Name(),
		}
		deferNodes[exIdx] = dn
		graph.Nodes = append(graph.Nodes, dn)
	}

	// Chain: deferNodes[0] -> deferNodes[1] -> ... -> deferNodes[n-1] -> exitNode
	for i, dn := range deferNodes {
		if i < len(deferNodes)-1 {
			dn.addSucc(deferNodes[i+1], nil)
		} else {
			dn.addSucc(exitNode, nil)
		}
	}

	firstDeferNode := deferNodes[0] // entry point of the defer chain

	// Rewire all return and panic nodes: instead of going to exitNode, go to
	// the first defer node.
	for _, blk := range fn.Blocks {
		last := blk.Instrs[len(blk.Instrs)-1]
		switch last.(type) {
		case *ssa.Return, *ssa.Panic:
			srcNode := graph.BlockToNode[blk.Index]
			for _, edge := range srcNode.Succs {
				if edge.To == exitNode {
					edge.To = firstDeferNode
					// Update preds: remove exitNode's pred entry, add firstDeferNode's.
					removePred(exitNode, edge)
					firstDeferNode.Preds = append(firstDeferNode.Preds, edge)
				}
			}
		}
	}
}

// removePred removes a specific edge from node's Preds slice.
func removePred(node *SCFGNode, edge *SCFGEdge) {
	for i, p := range node.Preds {
		if p == edge {
			node.Preds = append(node.Preds[:i], node.Preds[i+1:]...)
			return
		}
	}
}

// ── Type helpers ─────────────────────────────────────────────────────────────

// isErrorType reports whether t is the built-in error interface.
func isErrorType(t types.Type) bool {
	return loader.IsErrorType(t)
}

// isNilConst reports whether v is the untyped nil constant.
func isNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	if !ok {
		return false
	}
	return c.Value == nil // untyped nil in ssa is represented as a Const with nil Value
}
