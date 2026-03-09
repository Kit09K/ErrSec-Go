// Package smartcfg implements Stage 2: Smart CFG Builder.
// It wraps SSA basic blocks into SCFGNodes and injects synthetic nodes
// for defer chains, panic edges, and annotates branch conditions.
// Layer 2 — imports pkg/types, pkg/config, internal/loader.
package smartcfg

import (
	"fmt"

	"golang.org/x/tools/go/ssa"
)

// NodeKind classifies the role of an SCFGNode in the control-flow graph.
type NodeKind uint8

const (
	// KindNormal: a regular basic block from SSA.
	KindNormal NodeKind = iota
	// KindDefer: synthetic node representing one deferred function execution.
	KindDefer
	// KindPanicEntry: entry point of a panic-unwinding path.
	KindPanicEntry
	// KindRecover: block containing a recover() call.
	KindRecover
	// KindExit: the unique function exit node (normal and panic paths converge here).
	KindExit
)

func (k NodeKind) String() string {
	switch k {
	case KindNormal:
		return "NORMAL"
	case KindDefer:
		return "DEFER"
	case KindPanicEntry:
		return "PANIC_ENTRY"
	case KindRecover:
		return "RECOVER"
	case KindExit:
		return "EXIT"
	default:
		return "UNKNOWN"
	}
}

// BranchCond annotates an SCFGEdge with the predicate governing the branch.
// It is only set when the source block ends with an ssa.If instruction that
// tests an error-typed value.
type BranchCond struct {
	// Value is the SSA value being tested (the error variable).
	Value ssa.Value
	// IsNilCheck is true when the condition is of the form v == nil or v != nil.
	IsNilCheck bool
	// TrueIsErr is true when the true-branch is the error path (v != nil).
	TrueIsErr bool
}

// SCFGEdge is a directed edge in the Smart CFG.
type SCFGEdge struct {
	From *SCFGNode
	To   *SCFGNode
	// Cond is non-nil for conditional branches involving error checks.
	Cond *BranchCond
}

// SCFGNode is a node in the Smart Control Flow Graph.
// It wraps an SSA BasicBlock (or is synthetic for defer/exit nodes).
type SCFGNode struct {
	// ID is a unique identifier within the function's SCFG.
	ID int
	// Kind classifies the node's role.
	Kind NodeKind
	// Block is the underlying SSA block (nil for synthetic nodes).
	Block *ssa.BasicBlock
	// Instrs is the ordered list of SSA instructions in this node.
	// For synthetic nodes it may contain the single deferred call instruction.
	Instrs []ssa.Instruction
	// Succs are the outgoing edges from this node.
	Succs []*SCFGEdge
	// Preds are the incoming edges to this node.
	Preds []*SCFGEdge
	// DeferInstr is the defer instruction this synthetic node represents (KindDefer).
	DeferInstr *ssa.Defer
	// FuncName is the name of the enclosing function (for reporting).
	FuncName string
}

// String returns a short description of the node for debugging.
func (n *SCFGNode) String() string {
	if n.Block != nil {
		return fmt.Sprintf("SCFGNode{id=%d kind=%s block=%d}", n.ID, n.Kind, n.Block.Index)
	}
	return fmt.Sprintf("SCFGNode{id=%d kind=%s synthetic}", n.ID, n.Kind)
}

// addSucc adds a successor edge from n to target, optionally with a condition.
func (n *SCFGNode) addSucc(target *SCFGNode, cond *BranchCond) {
	edge := &SCFGEdge{From: n, To: target, Cond: cond}
	n.Succs = append(n.Succs, edge)
	target.Preds = append(target.Preds, edge)
}

// SCFG is the Smart Control Flow Graph for a single function.
type SCFG struct {
	// Func is the SSA function this graph models.
	Func *ssa.Function
	// Nodes is the list of all nodes in entry-first order.
	Nodes []*SCFGNode
	// BlockToNode maps SSA block index to SCFGNode (for normal blocks only).
	BlockToNode map[int]*SCFGNode
	// ExitNode is the unique exit node for this function.
	ExitNode *SCFGNode
}

// Entry returns the entry node (always Nodes[0]).
func (g *SCFG) Entry() *SCFGNode {
	if len(g.Nodes) == 0 {
		return nil
	}
	return g.Nodes[0]
}
