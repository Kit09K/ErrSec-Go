// Package pattern_matcher scans SSA instructions for two fail-open error patterns:
//   1. err != nil check  (PatternCheck) – FR-03
//   2. blank identifier  (PatternBlank) – FR-03
//
// Scope note: this package only sees functions that AllFunctions() already
// filtered to the user's target packages.  No stdlib / vendor guards are needed here.
package pattern_matcher

import (
	"go/token"
	"go/types"

	"github.com/errsec/errsec/internal/models"
	"golang.org/x/tools/go/ssa"
)

// FindPatterns scans fn for all ErrorSite instances matching either pattern.
//
// Important: *ssa.If (terminator) has Pos() == token.NoPos by design in go/ssa.
// Position for a check site is taken from the *ssa.BinOp condition instead.
// Do NOT guard on instr.Pos() here — it would silently drop all PatternCheck sites.
func FindPatterns(fn *ssa.Function, fset *token.FileSet) []*models.ErrorSite {
	if fn.Blocks == nil {
		return nil
	}

	var sites []*models.ErrorSite

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			switch v := instr.(type) {

			// ── Pattern 1: err != nil check ──────────────────────────────
			// *ssa.If.Pos() == token.NoPos (SSA design: terminators have no pos).
			// Position is resolved from the BinOp condition operand.
			case *ssa.If:
				if site := matchCheckPattern(fn, v, fset); site != nil {
					sites = append(sites, site)
				}

			// ── Pattern 2: blank identifier ───────────────────────────────
			// ssa.CallInstruction.Pos() carries the call-expression position.
			default:
				if call, ok := instr.(ssa.CallInstruction); ok {
					if site := matchBlankPattern(fn, call, fset); site != nil {
						sites = append(sites, site)
					}
				}
			}
		}
	}

	return sites
}

// ─── Pattern 1 ────────────────────────────────────────────────────────────────

// matchCheckPattern returns an ErrorSite when ifInstr's condition is a
// comparison of an error value against nil (err != nil  or  err == nil).
//
// Source position is taken from binop.Pos() because *ssa.If has no own position.
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

	// Use the BinOp's position — it corresponds to the "!=" or "==" token
	// in the original source, which is exactly where the check occurs.
	pos := fset.Position(binop.Pos())

	return &models.ErrorSite{
		Func:       fn,
		Instr:      ifInstr,
		Pattern:    models.PatternCheck,
		ErrValue:   errVal,
		SourceCall: findSourceCall(errVal),
		SourcePkg:  sourcePackage(errVal),
		Pos:        binop.Pos(),
		File:       pos.Filename,
		Line:       pos.Line,
		Col:        pos.Column,
	}
}

// ─── Pattern 2 ────────────────────────────────────────────────────────────────

// matchBlankPattern returns an ErrorSite when call produces an error-typed
// value that has no referrers (equivalent to blank-identifier assignment).
func matchBlankPattern(fn *ssa.Function, call ssa.CallInstruction, fset *token.FileSet) *models.ErrorSite {
	val := call.Value()
	if val == nil {
		return nil
	}

	var discardedErr ssa.Value

	switch t := val.Type().(type) {
	case *types.Tuple:
		// Multi-return: find the error-typed element whose Extract has no referrers.
		for i := 0; i < t.Len(); i++ {
			if isErrorType(t.At(i).Type()) {
				ext := findExtract(val, i)
				if ext == nil || len(*ext.Referrers()) == 0 {
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

// ─── Utilities ────────────────────────────────────────────────────────────────

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
	return ok && sig.Params().Len() == 0 && sig.Results().Len() == 1
}

func isNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.IsNil()
}

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

func sourcePackage(v ssa.Value) string {
	call := findSourceCall(v)
	if call == nil {
		return ""
	}
	return callPackage(call)
}

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
