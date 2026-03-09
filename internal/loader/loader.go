// Package loader implements Stage 1 of the ErrSec pipeline:
// loading Go packages and constructing SSA representations.
// Layer 1 — imports pkg/types, pkg/config, and x/tools.
package loader

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	errtypes "github.com/errsec/errsec/pkg/types"
	"github.com/errsec/errsec/pkg/config"
)

// loadMode is the set of package facts needed by all downstream stages.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedTypes |
	packages.NeedTypesSizes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedDeps

// Result is the output of the Loader stage.
type Result struct {
	// Prog is the fully built SSA program.
	Prog *ssa.Program
	// Packages are the SSA packages corresponding to the requested patterns.
	Packages []*ssa.Package
	// Functions is the flat list of all functions (including closures/anon funcs).
	Functions []*ssa.Function
	// Fset is the shared token.FileSet for position information.
	Fset *token.FileSet
	// TypesPkgs is the raw types.Package list (used by classifier for import paths).
	TypesPkgs []*types.Package

	stats errtypes.Stats
}

// Stats returns the loader statistics.
func (r *Result) Stats() errtypes.Stats {
	return r.stats
}

// Load parses and type-checks the Go packages matching patterns, then
// builds an SSA program and collects all functions including closures.
func Load(cfg *config.Config, patterns []string) (*Result, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("loader: no patterns specified")
	}

	fset := token.NewFileSet()
	pkgCfg := &packages.Config{
		Mode:  loadMode,
		Tests: false,
		Dir:   cfg.WorkDir,
		Fset:  fset,
	}

	pkgs, err := packages.Load(pkgCfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loader: packages.Load: %w", err)
	}

	// Fail fast on type errors — static analysis on broken code produces
	// misleading results.
	var errCount int
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			fmt.Printf("errsec: package error in %s: %v\n", pkg.PkgPath, e)
			errCount++
		}
	})
	if errCount > 0 {
		return nil, fmt.Errorf("loader: %d package error(s) — fix type errors before running errsec", errCount)
	}

	// Build SSA.
	// InstantiateGenerics ensures generic function instances are included (Go 1.18+).
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	// Collect all functions, recursing into anonymous functions.
	var funcs []*ssa.Function
	var typesPkgs []*types.Package
	for _, sp := range ssaPkgs {
		if sp == nil {
			continue
		}
		typesPkgs = append(typesPkgs, sp.Pkg.Pkg)
		for _, mem := range sp.Members {
			if fn, ok := mem.(*ssa.Function); ok {
				collectFunctions(fn, &funcs)
			}
		}
	}

	return &Result{
		Prog:      prog,
		Packages:  ssaPkgs,
		Functions: funcs,
		Fset:      fset,
		TypesPkgs: typesPkgs,
		stats: errtypes.Stats{
			PackagesLoaded: len(ssaPkgs),
		},
	}, nil
}

// collectFunctions recursively gathers fn and all of its anonymous children.
func collectFunctions(fn *ssa.Function, out *[]*ssa.Function) {
	if fn == nil {
		return
	}
	*out = append(*out, fn)
	for _, anon := range fn.AnonFuncs {
		collectFunctions(anon, out)
	}
}

// IsErrorType reports whether t is or implements the built-in error interface.
func IsErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	// Unwrap pointer and named types.
	named, ok := t.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	_ = named
	// The error interface has exactly one method: Error() string.
	// We use types.Implements against the standard error interface.
	errIface := types.Universe.Lookup("error")
	if errIface == nil {
		return false
	}
	errType, ok := errIface.Type().(*types.Named)
	if !ok {
		return false
	}
	iface, ok := errType.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return types.Implements(t, iface) || types.Implements(types.NewPointer(t), iface)
}

// ReturnsError reports whether sig has at least one error-typed return value.
func ReturnsError(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	res := sig.Results()
	for i := 0; i < res.Len(); i++ {
		if IsErrorType(res.At(i).Type()) {
			return true
		}
	}
	return false
}

// ErrorReturnIndices returns the indices of error-typed values in a tuple.
func ErrorReturnIndices(t *types.Tuple) []int {
	var indices []int
	if t == nil {
		return indices
	}
	for i := 0; i < t.Len(); i++ {
		if IsErrorType(t.At(i).Type()) {
			indices = append(indices, i)
		}
	}
	return indices
}
