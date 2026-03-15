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
	// SSAPkgs contains ONLY the packages directly requested by the user.
	// Transitive imports are built into Prog for type resolution but are
	// NOT present in SSAPkgs and therefore never scanned for patterns.
	SSAPkgs []*ssa.Package
}

// Build converts the user-supplied packages into SSA form.
//
// ssautil.AllPackages builds the entire transitive import closure into Prog
// so that type information is complete across all packages. However SSAPkgs
// contains only the root packages the user explicitly asked for — stdlib,
// vendor, and dependencies are reachable through Prog.Packages but are not
// in SSAPkgs and will never be walked by AllFunctions.
func Build(pkgs []*packages.Package) *SSAResult {
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.SanityCheckFunctions)
	prog.Build()
	return &SSAResult{Prog: prog, SSAPkgs: ssaPkgs}
}

// AllFunctions returns every SSA function that belongs to the user's target
// packages, including methods, closures, and anonymous functions.
//
// Key design: we iterate r.SSAPkgs.Members directly instead of calling
// ssautil.AllFunctions(r.Prog). The latter returns ALL functions in the
// entire program (stdlib, vendor, dependencies) which is the root cause of
// spurious findings from unrelated packages. By walking only r.SSAPkgs we
// are guaranteed to stay within the user's own code.
//
// Anonymous/closure functions are collected recursively via fn.AnonFuncs —
// they belong to the same package as their enclosing function even though
// they have no independent *ssa.Package (fn.Package() == nil for closures).
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
		// Closures and anonymous functions are nested inside fn.
		// They have no independent package but belong to the same scope.
		for _, anon := range fn.AnonFuncs {
			visit(anon)
		}
	}

	// Walk only the root (user-requested) packages.
	// pkg.Members contains every top-level symbol: functions, types, vars, consts.
	// Methods declared on types in this package are also stored as Members.
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

	return fns
}
