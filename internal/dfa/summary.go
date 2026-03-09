package dfa

import (
	"sync"

	"golang.org/x/tools/go/ssa"

	errtypes "github.com/errsec/errsec/pkg/types"
)

// FunctionSummary describes what a function does to error values.
// It is the inter-procedural contract consumed by callers.
type FunctionSummary struct {
	Func *ssa.Function
	// ReturnTaint[i] is true if return position i may carry a tainted error.
	ReturnTaint []bool
	// MaxReturnRisk is the highest risk level of any tainted return.
	MaxReturnRisk errtypes.RiskLevel
	// Stable is true once the summary has reached a fixed-point.
	Stable bool
}

// SummaryStore is a thread-safe cache of function summaries.
// It also implements the classifier.SummaryStore interface.
type SummaryStore struct {
	mu    sync.RWMutex
	cache map[*ssa.Function]*FunctionSummary
}

// NewSummaryStore creates an empty store.
func NewSummaryStore() *SummaryStore {
	return &SummaryStore{cache: make(map[*ssa.Function]*FunctionSummary)}
}

// Get returns the summary for fn, or nil if not yet computed.
func (s *SummaryStore) Get(fn *ssa.Function) *FunctionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cache[fn]
}

// Set stores or updates the summary for fn.
func (s *SummaryStore) Set(fn *ssa.Function, sum *FunctionSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[fn] = sum
}

// MaxReturnRisk implements the classifier.SummaryStore interface.
// Returns the maximum risk level among all tainted returns of fn.
func (s *SummaryStore) MaxReturnRisk(fn *ssa.Function) errtypes.RiskLevel {
	sum := s.Get(fn)
	if sum == nil {
		return errtypes.UNKNOWN
	}
	return sum.MaxReturnRisk
}

// Equal reports whether two summaries are identical (used for fixed-point detection).
func summaryEqual(a, b *FunctionSummary) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.MaxReturnRisk != b.MaxReturnRisk {
		return false
	}
	if len(a.ReturnTaint) != len(b.ReturnTaint) {
		return false
	}
	for i := range a.ReturnTaint {
		if a.ReturnTaint[i] != b.ReturnTaint[i] {
			return false
		}
	}
	return true
}
