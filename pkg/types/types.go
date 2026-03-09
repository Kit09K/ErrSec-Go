// Package types defines all shared types used across the ErrSec pipeline.
// It is Layer 0 and must never import any other internal package.
package types

import "fmt"

// ErrorState represents the abstract state of an error value at a given
// program point in the DFA lattice.
// Ordering: TAINTED > HANDLED > CLEAN  (higher = more concerning)
type ErrorState uint8

const (
	CLEAN   ErrorState = iota
	HANDLED
	TAINTED
)

func (s ErrorState) String() string {
	switch s {
	case CLEAN:
		return "CLEAN"
	case HANDLED:
		return "HANDLED"
	case TAINTED:
		return "TAINTED"
	default:
		return "UNKNOWN"
	}
}

// Join returns the join (least upper bound) of two states in the lattice.
func Join(a, b ErrorState) ErrorState {
	if a > b {
		return a
	}
	return b
}

// RiskLevel represents the security risk associated with an error source.
type RiskLevel uint8

const (
	UNKNOWN RiskLevel = iota
	LOW
	MEDIUM
	HIGH
)

func (r RiskLevel) String() string {
	switch r {
	case UNKNOWN:
		return "UNKNOWN"
	case LOW:
		return "LOW"
	case MEDIUM:
		return "MEDIUM"
	case HIGH:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

func ParseRiskLevel(s string) (RiskLevel, error) {
	switch s {
	case "LOW":
		return LOW, nil
	case "MEDIUM":
		return MEDIUM, nil
	case "HIGH":
		return HIGH, nil
	case "UNKNOWN":
		return UNKNOWN, nil
	default:
		return UNKNOWN, fmt.Errorf("unknown risk level: %q (valid: LOW, MEDIUM, HIGH)", s)
	}
}

// FailOpenPattern identifies the type of fail-open vulnerability detected.
type FailOpenPattern string

const (
	PatternBlankIgnore  FailOpenPattern = "BLANK_IGNORE"
	PatternLogContinue  FailOpenPattern = "LOG_CONTINUE"
	PatternDeferIgnore  FailOpenPattern = "DEFER_IGNORE"
	PatternUnanalysable FailOpenPattern = "UNANALYSABLE"
)

// StepKind classifies each step in an error propagation trace.
type StepKind string

const (
	StepSource StepKind = "SOURCE"
	StepAssign StepKind = "ASSIGN"
	StepPhi    StepKind = "PHI"
	StepCheck  StepKind = "CHECK"
	StepLog    StepKind = "LOG"
	StepCall   StepKind = "CALL"
	StepReturn StepKind = "RETURN"
	StepSink   StepKind = "SINK"
)

// PathStep is one node in the data-flow trace from error source to sink.
type PathStep struct {
	Kind     StepKind
	FuncName string
	File     string
	Line     int
	Detail   string
}

func (p PathStep) String() string {
	return fmt.Sprintf("[%s] %s:%d  %s", p.Kind, p.File, p.Line, p.Detail)
}

// Issue represents a single detected fail-open vulnerability.
type Issue struct {
	ID           int
	Pattern      FailOpenPattern
	Risk         RiskLevel
	PkgPath      string
	FuncName     string
	File         string
	Line         int
	SourcePkg    string
	SourceFunc   string
	SourceReason string
	Path         []PathStep
}

func (i *Issue) String() string {
	return fmt.Sprintf("ISSUE#%d [%s] %s at %s:%d", i.ID, i.Risk, i.Pattern, i.File, i.Line)
}

// Stats holds summary statistics for a completed analysis run.
type Stats struct {
	FunctionsAnalysed int
	FunctionsSkipped  int
	PackagesLoaded    int
	DurationMs        int64
}
