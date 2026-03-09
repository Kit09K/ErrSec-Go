// Package ssa_builder converts loaded Go packages into SSA form (FR-02).
package ssa_builder

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// SSAResult holds the built SSA program and the per-package representations.
type SSAResult struct {
	Prog    *ssa.Program
	SSAPkgs []*ssa.Package
}

// Build converts loaded packages into SSA form and triggers a full program build.
func Build(pkgs []*packages.Package) *SSAResult {
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.SanityCheckFunctions)
	prog.Build()
	return &SSAResult{Prog: prog, SSAPkgs: ssaPkgs}
}

// AllFunctions returns every non-nil SSA function reachable from the given packages,
// including anonymous functions and method implementations.
func AllFunctions(r *SSAResult) []*ssa.Function {
	seen := make(map[*ssa.Function]bool)
	var fns []*ssa.Function

	var visit func(*ssa.Function)
	visit = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		fns = append(fns, fn)
		for _, anon := range fn.AnonFuncs {
			visit(anon)
		}
	}

	for _, pkg := range r.SSAPkgs {
		if pkg == nil {
			continue
		}
		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				visit(fn)
			}
		}
	}

	// ssautil.AllFunctions captures methods and synthetic wrappers
	for fn := range ssautil.AllFunctions(r.Prog) {
		visit(fn)
	}

	return fns
}
