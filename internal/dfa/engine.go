// Package dfa orchestrates the forward data-flow analysis (DFA) for a single
// ErrorSite (FR-06, FR-07, FR-08).
package dfa

import (
	"go/token"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/complexity_capper"
	"github.com/errsec/errsec/internal/forward_tracker"
	"github.com/errsec/errsec/internal/models"
	"github.com/errsec/errsec/internal/smart_cfg"
	"github.com/errsec/errsec/internal/summary_store"
	"golang.org/x/tools/go/ssa"
)

// Engine runs the DFA stage of the ErrSec pipeline.
type Engine struct {
	fset  *token.FileSet
	clf   *classifier.Classifier
	store *summary_store.Store
}

// New creates a DFA Engine.
func New(fset *token.FileSet, clf *classifier.Classifier, store *summary_store.Store) *Engine {
	return &Engine{fset: fset, clf: clf, store: store}
}

// Analyze runs the full DFA pipeline for site and returns the FlowFact result.
func (e *Engine) Analyze(site *models.ErrorSite) *models.FlowFact {
	fn := site.Func

	// ── Step 1: Complexity cap (FR-08) ──────────────────────────────────────
	if complexity_capper.ExceedsCap(fn) {
		result := &models.FlowFact{
			Site:       site,
			Risk:       e.clf.Classify(site).Risk,
			TooComplex: true,
		}
		e.recordSummary(site, result)
		return result
	}

	// ── Step 2: Risk classification (FR-05) ─────────────────────────────────
	cr := e.clf.Classify(site)

	// ── Step 3: Build Smart CFG (FR-04) ─────────────────────────────────────
	cfg := smart_cfg.Build(fn)

	// ── Step 4: Forward DFA (FR-06) ─────────────────────────────────────────
	startBlock := blockOf(site.Instr)
	var flowPath []models.FlowNode
	if startBlock != nil {
		tracker := forward_tracker.New(cfg, e.fset, site.ErrValue)
		flowPath = tracker.Track(startBlock)
	}

	result := &models.FlowFact{
		Site:     site,
		Risk:     cr.Risk,
		FlowPath: flowPath,
	}

	// ── Step 5: Store function summary (FR-07) ───────────────────────────────
	e.recordSummary(site, result)

	return result
}

// recordSummary derives and persists a FunctionSummary from the DFA result.
func (e *Engine) recordSummary(site *models.ErrorSite, fact *models.FlowFact) {
	if site.Func == nil {
		return
	}
	name := site.Func.RelString(nil)

	existing := e.store.Get(name)
	sum := &models.FunctionSummary{FuncName: name}
	if existing != nil {
		*sum = *existing
	}

	switch site.Pattern {
	case models.PatternBlank:
		sum.DiscardsSomeError = true
	case models.PatternCheck:
		propagates := true
		for _, node := range fact.FlowPath {
			if node.Mutation == models.MutationDiscarded {
				sum.DiscardsSomeError = true
				propagates = false
				break
			}
		}
		if propagates {
			sum.PropagatesError = true
		}
	}

	e.store.Set(name, sum)
}

// blockOf returns the basic block containing instr, or nil.
func blockOf(instr ssa.Instruction) *ssa.BasicBlock {
	return instr.Block()
}
