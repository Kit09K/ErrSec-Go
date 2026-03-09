// Package pattern_matcher scans SSA instructions for the two fail-open error-handling patterns:
//   1. err != nil check (PatternCheck) – FR-03
//   2. blank identifier discarding an error return (PatternBlank) – FR-03
package pattern_matcher

import (
	"go/token"
	"go/types"

	"github.com/errsec/errsec/internal/models"
	"golang.org/x/tools/go/ssa"
)

// FindPatterns scans fn for all ErrorSite instances matching either pattern.
func FindPatterns(fn *ssa.Function, fset *token.FileSet) []*models.ErrorSite {
	if fn.Blocks == nil {
		return nil
	}

	var sites []*models.ErrorSite

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// ── Pattern 1: err != nil check ──────────────────────────────────
			if ifInstr, ok := instr.(*ssa.If); ok {
				if site := matchCheckPattern(fn, ifInstr, fset); site != nil {
					sites = append(sites, site)
				}
				continue
			}

			// ── Pattern 2: blank identifier (discarded error) ─────────────────
			// A call whose result (or extracted tuple element) of error type has
			// no referrers is treated as a blank-identifier discard.
			if call, ok := instr.(ssa.CallInstruction); ok {
				if site := matchBlankPattern(fn, call, fset); site != nil {
					sites = append(sites, site)
				}
			}
		}
	}

	return sites
}

// ─── Pattern 1 helpers ────────────────────────────────────────────────────────

// matchCheckPattern returns an ErrorSite if ifInstr's condition is a comparison
// of an error value to nil (err != nil  or  err == nil).
func matchCheckPattern(fn *ssa.Function, ifInstr *ssa.If, fset *token.FileSet) *models.ErrorSite {
	binop, ok := ifInstr.Cond.(*ssa.BinOp)
	if !ok {
		return nil
	}
	if binop.Op != token.NEQ && binop.Op != token.EQL {
		return nil
	}

	var errVal ssa.Value
	switch {
	case isErrorType(binop.X.Type()) && isNilConst(binop.Y):
		errVal = binop.X
	case isErrorType(binop.Y.Type()) && isNilConst(binop.X):
		errVal = binop.Y
	default:
		return nil
	}

	pos := fset.Position(ifInstr.Pos())
	return &models.ErrorSite{
		Func:       fn,
		Instr:      ifInstr,
		Pattern:    models.PatternCheck,
		ErrValue:   errVal,
		SourceCall: findSourceCall(errVal),
		SourcePkg:  sourcePackage(errVal),
		Pos:        ifInstr.Pos(),
		File:       pos.Filename,
		Line:       pos.Line,
		Col:        pos.Column,
	}
}

// ─── Pattern 2 helpers ────────────────────────────────────────────────────────

// matchBlankPattern returns an ErrorSite when call produces an error-typed value
// that is never used (i.e. no referrers, equivalent to blank identifier).
func matchBlankPattern(fn *ssa.Function, call ssa.CallInstruction, fset *token.FileSet) *models.ErrorSite {
	val := call.Value()
	if val == nil {
		return nil
	}

	var discardedErr ssa.Value

	switch t := val.Type().(type) {
	case *types.Tuple:
		// Multi-return: look for an error-typed element whose Extract has no referrers.
		for i := 0; i < t.Len(); i++ {
			if isErrorType(t.At(i).Type()) {
				ext := findExtract(val, i)
				if ext == nil || len(*ext.Referrers()) == 0 {
					// error element is discarded
					if ext != nil {
						discardedErr = ext
					} else {
						discardedErr = val
					}
					break
				}
			}
		}
	default:
		// Single return of error type with no referrers.
		if isErrorType(val.Type()) && len(*val.Referrers()) == 0 {
			discardedErr = val
		}
	}

	if discardedErr == nil {
		return nil
	}

	pos := fset.Position(call.Pos())
	return &models.ErrorSite{
		Func:       fn,
		Instr:      call,
		Pattern:    models.PatternBlank,
		ErrValue:   discardedErr,
		SourceCall: call,
		SourcePkg:  callPackage(call),
		Pos:        call.Pos(),
		File:       pos.Filename,
		Line:       pos.Line,
		Col:        pos.Column,
	}
}

// ─── Utility ─────────────────────────────────────────────────────────────────

// isErrorType returns true if t is the built-in error interface.
func isErrorType(t types.Type) bool {
	iface, ok := t.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	if iface.NumMethods() != 1 {
		return false
	}
	m := iface.Method(0)
	if m.Name() != "Error" {
		return false
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok {
		return false
	}
	return sig.Params().Len() == 0 && sig.Results().Len() == 1
}

// isNilConst returns true if v is a nil constant.
func isNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	if !ok {
		return false
	}
	return c.IsNil()
}

// findExtract locates the *ssa.Extract instruction for element index i of tuple val.
func findExtract(tuple ssa.Value, index int) *ssa.Extract {
	refs := tuple.Referrers()
	if refs == nil {
		return nil
	}
	for _, ref := range *refs {
		if ext, ok := ref.(*ssa.Extract); ok && ext.Index == index {
			return ext
		}
	}
	return nil
}

// findSourceCall traces an error value back to its originating call instruction.
func findSourceCall(v ssa.Value) ssa.CallInstruction {
	switch x := v.(type) {
	case ssa.CallInstruction:
		return x
	case *ssa.Extract:
		if call, ok := x.Tuple.(ssa.CallInstruction); ok {
			return call
		}
	}
	return nil
}

// sourcePackage returns the import path of the package that owns the callee of v's source call.
func sourcePackage(v ssa.Value) string {
	call := findSourceCall(v)
	if call == nil {
		return ""
	}
	return callPackage(call)
}

// callPackage returns the import path of the package owning the callee of call.
func callPackage(call ssa.CallInstruction) string {
	cc := call.Common()
	if cc.IsInvoke() {
		return ""
	}
	fn, ok := cc.Value.(*ssa.Function)
	if !ok || fn.Package() == nil {
		return ""
	}
	pkg := fn.Package().Pkg
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}
