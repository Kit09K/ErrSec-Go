// Package dfa implements Stage 4: Data Flow Analysis Engine.
// Layer 4 — imports pkg/types, pkg/config, internal/loader,
//            internal/smartcfg, internal/classifier.
package dfa

import (
	"golang.org/x/tools/go/ssa"

	errtypes "github.com/errsec/errsec/pkg/types"
	"github.com/errsec/errsec/internal/classifier"
)

// TaintMeta carries the origin and accumulated path of a tainted error value.
type TaintMeta struct {
	Source *classifier.ClassifiedSource
	Path   []errtypes.PathStep
}

// withStep returns a new TaintMeta with step appended.
func (m *TaintMeta) withStep(step errtypes.PathStep) *TaintMeta {
	newPath := make([]errtypes.PathStep, len(m.Path)+1)
	copy(newPath, m.Path)
	newPath[len(m.Path)] = step
	return &TaintMeta{Source: m.Source, Path: newPath}
}

// Env is the abstract environment mapping SSA values to ErrorStates.
// It is the per-program-point 'memory' of the analysis.
// Environments are logically immutable; Clone before modifying.
type Env struct {
	states map[ssa.Value]errtypes.ErrorState
	meta   map[ssa.Value]*TaintMeta
	// inErrBranch records which error values are inside an error-check branch
	// (i.e., we are on the true-side of 'if err != nil').
	inErrBranch map[ssa.Value]bool
}

// NewEnv creates an empty abstract environment.
func NewEnv() *Env {
	return &Env{
		states:      make(map[ssa.Value]errtypes.ErrorState),
		meta:        make(map[ssa.Value]*TaintMeta),
		inErrBranch: make(map[ssa.Value]bool),
	}
}

// Get returns the state of v, defaulting to CLEAN.
func (e *Env) Get(v ssa.Value) errtypes.ErrorState {
	if v == nil {
		return errtypes.CLEAN
	}
	s, ok := e.states[v]
	if !ok {
		return errtypes.CLEAN
	}
	return s
}

// Set assigns a state to v.
func (e *Env) Set(v ssa.Value, s errtypes.ErrorState) {
	if v == nil {
		return
	}
	e.states[v] = s
	if s != errtypes.TAINTED {
		delete(e.meta, v)
	}
}

// SetTainted marks v as TAINTED and stores its metadata.
func (e *Env) SetTainted(v ssa.Value, m *TaintMeta) {
	if v == nil {
		return
	}
	e.states[v] = errtypes.TAINTED
	e.meta[v] = m
}

// Meta returns the taint metadata for v (nil if v is not TAINTED).
func (e *Env) Meta(v ssa.Value) *TaintMeta {
	if v == nil {
		return nil
	}
	return e.meta[v]
}

// SetInErrBranch records that v is currently inside an error-check branch.
func (e *Env) SetInErrBranch(v ssa.Value, val bool) {
	if v == nil {
		return
	}
	e.inErrBranch[v] = val
}

// IsInErrBranch reports whether v is inside an error-check branch.
func (e *Env) IsInErrBranch(v ssa.Value) bool {
	if v == nil {
		return false
	}
	return e.inErrBranch[v]
}

// Clone returns a deep copy of the environment.
func (e *Env) Clone() *Env {
	n := &Env{
		states:      make(map[ssa.Value]errtypes.ErrorState, len(e.states)),
		meta:        make(map[ssa.Value]*TaintMeta, len(e.meta)),
		inErrBranch: make(map[ssa.Value]bool, len(e.inErrBranch)),
	}
	for k, v := range e.states {
		n.states[k] = v
	}
	for k, v := range e.meta {
		n.meta[k] = v
	}
	for k, v := range e.inErrBranch {
		n.inErrBranch[k] = v
	}
	return n
}

// Join returns the lattice join (least upper bound) of e and other.
// For each value: join uses TAINTED > HANDLED > CLEAN.
func (e *Env) Join(other *Env) *Env {
	result := e.Clone()
	for val, os := range other.states {
		es := result.Get(val)
		joined := errtypes.Join(es, os)
		result.states[val] = joined
		// Prefer meta from the more-tainted side.
		if joined == errtypes.TAINTED {
			if result.meta[val] == nil && other.meta[val] != nil {
				result.meta[val] = other.meta[val]
			}
		}
	}
	for val, v := range other.inErrBranch {
		if v {
			result.inErrBranch[val] = true
		}
	}
	return result
}

// Equals reports whether e and other are identical (used for fixed-point check).
func (e *Env) Equals(other *Env) bool {
	if other == nil {
		return len(e.states) == 0
	}
	if len(e.states) != len(other.states) {
		return false
	}
	for k, v := range e.states {
		if other.states[k] != v {
			return false
		}
	}
	return true
}
