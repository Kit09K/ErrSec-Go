// Package analyzer orchestrates the complete ErrSec 3-stage analysis pipeline
// and exposes a public API for CLI and library consumers (FR-11).
//
// Scope:
//   ErrSec analyses ONLY the packages explicitly named in path.
//   Stdlib, vendor, and transitive dependencies are used for type resolution
//   only — their functions are never passed to pattern_matcher or DFA.
package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/dfa"
	"github.com/errsec/errsec/internal/loader"
	"github.com/errsec/errsec/internal/models"
	"github.com/errsec/errsec/internal/pattern_matcher"
	"github.com/errsec/errsec/internal/reporter"
	"github.com/errsec/errsec/internal/rule_engine"
	"github.com/errsec/errsec/internal/ssa_builder"
	"github.com/errsec/errsec/internal/summary_store"
)

// Result is the public output type returned by Run.
type Result struct {
	Facts []*models.FlowFact
}

// Options configures an analysis run.
type Options struct {
	RulesPath string  // path to risk_rules.json; empty = use bundled default
	Output    io.Writer // destination for Text DFG report; nil = os.Stdout
}

// Run executes the full ErrSec pipeline on the Go source at path.
func Run(path string, opts Options) (*Result, error) {
	if opts.Output == nil {
		opts.Output = os.Stdout
	}
	rulesPath := opts.RulesPath
	if rulesPath == "" {
		rulesPath = defaultRulesPath()
	}

	// ── Stage 1: Target Identification ───────────────────────────────────────

	loaded, err := loader.Load(path)
	if err != nil {
		return nil, fmt.Errorf("analyzer: load: %w", err)
	}

	// Build SSA — SSAPkgs contains only the root packages; prog has the full
	// transitive closure for type resolution but is not walked directly.
	ssaResult := ssa_builder.Build(loaded.Pkgs)

	// AllFunctions walks SSAPkgs.Members only (never ssautil.AllFunctions(prog)).
	allFuncs := ssa_builder.AllFunctions(ssaResult)

	var sites []*models.ErrorSite
	for _, fn := range allFuncs {
		found := pattern_matcher.FindPatterns(fn, loaded.Fset)
		sites = append(sites, found...)
	}

	if len(sites) == 0 {
		fmt.Fprintln(opts.Output, "ErrSec: no error-handling patterns found.")
		return &Result{}, nil
	}

	// ── Stage 2: Core Analysis Engine ────────────────────────────────────────

	engine, err := rule_engine.Load(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("analyzer: rule engine: %w", err)
	}

	clf := classifier.New(engine)
	store := summary_store.New()
	dfaEngine := dfa.New(loaded.Fset, clf, store)

	var facts []*models.FlowFact
	for _, site := range sites {
		fact := dfaEngine.Analyze(site)
		facts = append(facts, fact)
	}

	// ── Stage 3: Reporting ────────────────────────────────────────────────────
	reporter.Report(opts.Output, facts)

	return &Result{Facts: facts}, nil
}

func defaultRulesPath() string {
	exe, err := os.Executable()
	if err == nil {
		c := filepath.Join(filepath.Dir(exe), "..", "rules", "risk_rules.json")
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	_, file, _, ok := runtime.Caller(0)
	if ok {
		c := filepath.Join(filepath.Dir(file), "..", "rules", "risk_rules.json")
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return filepath.Join("rules", "risk_rules.json")
}
