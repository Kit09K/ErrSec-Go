// Package summary_store stores and retrieves FunctionSummary records for
// inter-procedural analysis (FR-07).
//
// Summaries are written after each function's DFA completes and are consulted
// during analysis of callers to model cross-function error propagation.
package summary_store

import (
	"sync"

	"github.com/errsec/errsec/internal/models"
)

// Store is a concurrent map from fully-qualified function names to their summaries.
type Store struct {
	mu      sync.RWMutex
	entries map[string]*models.FunctionSummary
}

// New returns an empty Store.
func New() *Store {
	return &Store{entries: make(map[string]*models.FunctionSummary)}
}

// Set stores summary for funcName, overwriting any existing entry.
func (s *Store) Set(funcName string, summary *models.FunctionSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[funcName] = summary
}

// Get retrieves the summary for funcName. Returns nil if not found.
func (s *Store) Get(funcName string) *models.FunctionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries[funcName]
}

// All returns a copy of all stored summaries.
func (s *Store) All() map[string]*models.FunctionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*models.FunctionSummary, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out
}
