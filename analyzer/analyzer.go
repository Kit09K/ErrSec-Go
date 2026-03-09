// Package analyzer orchestrates the complete ErrSec 3-stage analysis pipeline
// and exposes a public API for CLI and library consumers (FR-11).
//
// Pipeline:
//   Stage 1 – Target Identification  : Load → SSA → PatternMatch
//   Stage 2 – Core Analysis Engine   : SmartCFG + Classify + DFA
//   Stage 3 – Reporting              : Text DFG → stdout
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
	// RulesPath is the path to risk_rules.json.
	// If empty, the default bundled rules are used.
	RulesPath string
	// Output is the writer for the text DFG report.  Defaults to os.Stdout.
	Output io.Writer
}

// Run executes the full ErrSec pipeline on the Go source at path and writes
// the Text DFG report to opts.Output (or stdout).
// It is safe to call Run concurrently from multiple goroutines.
func Run(path string, opts Options) (*Result, error) {
	if opts.Output == nil {
		opts.Output = os.Stdout
	}
	rulesPath := opts.RulesPath
	if rulesPath == "" {
		rulesPath = defaultRulesPath()
	}

	// ── Stage 1: Target Identification ───────────────────────────────────────

	// 1a. Load packages
	loaded, err := loader.Load(path)
	if err != nil {
		return nil, fmt.Errorf("analyzer: load: %w", err)
	}

	// 1b. Build SSA
	ssaResult := ssa_builder.Build(loaded.Pkgs)
	allFuncs := ssa_builder.AllFunctions(ssaResult)

	// 1c. Pattern matching – collect all ErrorSites across all functions
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

	// Load OWASP rule engine
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

// defaultRulesPath locates the bundled risk_rules.json relative to this source file.
func defaultRulesPath() string {
	// Try executable-relative path first (installed binary)
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "..", "rules", "risk_rules.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Fall back to source-relative path (go run / development)
	_, file, _, ok := runtime.Caller(0)
	if ok {
		candidate := filepath.Join(filepath.Dir(file), "..", "rules", "risk_rules.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Last resort: CWD-relative
	return filepath.Join("rules", "risk_rules.json")
}
