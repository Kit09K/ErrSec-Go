// Package models defines shared data types used across ErrSec pipeline stages.
package models

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// PatternType identifies the kind of fail-open error pattern detected.
type PatternType int

const (
	// PatternCheck is an explicit err != nil conditional check.
	PatternCheck PatternType = iota
	// PatternBlank is a blank-identifier assignment discarding an error return value.
	PatternBlank
)

func (p PatternType) String() string {
	switch p {
	case PatternCheck:
		return "err!=nil check"
	case PatternBlank:
		return "blank identifier"
	default:
		return "unknown"
	}
}

// RiskLevel is the OWASP-derived risk classification of an error source.
type RiskLevel int

const (
	RiskLow  RiskLevel = iota // Display, Logging – OWASP severity LOW/NOTE
	RiskHigh                  // DB, Auth, Network – OWASP severity HIGH/CRITICAL
)

func (r RiskLevel) String() string {
	if r == RiskHigh {
		return "HIGH"
	}
	return "LOW"
}

// ErrorSite is a location in code where an error value is checked or silently discarded.
type ErrorSite struct {
	Func       *ssa.Function
	Instr      ssa.Instruction
	Pattern    PatternType
	ErrValue   ssa.Value          // SSA value of error type
	SourceCall ssa.CallInstruction // call that produced ErrValue (nil if indirect)
	SourcePkg  string             // import path of the callee's package
	Pos        token.Pos
	File       string
	Line       int
	Col        int
}

// MutationType describes what happened to an error value at a DFA flow node.
type MutationType int

const (
	MutationNone       MutationType = iota // error propagated unchanged
	MutationWrapped                        // errors.Wrap / fmt.Errorf applied
	MutationReassigned                     // reassigned to a different error value
	MutationDiscarded                      // set to nil or dropped
)

func (m MutationType) String() string {
	switch m {
	case MutationNone:
		return "propagated"
	case MutationWrapped:
		return "wrapped"
	case MutationReassigned:
		return "reassigned"
	case MutationDiscarded:
		return "discarded"
	default:
		return "unknown"
	}
}

// FlowNode is a single step in the error value's data-flow path.
type FlowNode struct {
	BlockIndex int
	InstrText  string
	Mutation   MutationType
	File       string
	Line       int
	Col        int
}

// FlowFact is the complete DFA result for a single ErrorSite.
type FlowFact struct {
	Site       *ErrorSite
	Risk       RiskLevel
	FlowPath   []FlowNode
	TooComplex bool // function exceeded complexity cap N=1000
}

// FunctionSummary stores inter-procedural analysis results for a function.
type FunctionSummary struct {
	FuncName          string
	PropagatesError   bool
	DiscardsSomeError bool
}
