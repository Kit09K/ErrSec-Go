// Package mutation_tracker identifies mutations of an error value at SSA instructions.
//
// A mutation is any operation that changes the semantic identity of an error
// variable: wrapping it with context (fmt.Errorf, errors.Wrap), reassigning it
// to a completely different error value, or discarding it by assigning nil.
package mutation_tracker

import (
	"go/types"
	"strings"

	"github.com/errsec/errsec/internal/models"
	"golang.org/x/tools/go/ssa"
)

// Inspect examines instr with respect to the tracked error value errVal and
// returns the mutation type that occurred, if any.
func Inspect(instr ssa.Instruction, errVal ssa.Value) models.MutationType {
	switch v := instr.(type) {
	case *ssa.Store:
		// Store to an alloca'd error variable
		if v.Val == errVal {
			return models.MutationNone // same value stored: propagation
		}
		// A nil constant stored to what was the error address: discard
		if isNilConst(v.Val) {
			return models.MutationDiscarded
		}

	case ssa.CallInstruction:
		// Check if this call wraps the error (fmt.Errorf, errors.Wrap, errors.Wrapf, etc.)
		if isWrappingCall(v) && callUsesValue(v, errVal) {
			return models.MutationWrapped
		}
		// Check if the error value flows into a call that produces a new error (reassign)
		if callUsesValue(v, errVal) && callReturnsError(v) {
			return models.MutationReassigned
		}

	case *ssa.Phi:
		// Phi nodes indicate merge points; if none of the incoming values is our errVal,
		// the error has been reassigned on some path.
		for _, edge := range v.Edges {
			if edge == errVal {
				return models.MutationNone
			}
		}
		if isErrorType(v.Type()) {
			return models.MutationReassigned
		}
	}

	return models.MutationNone
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func isNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.IsNil()
}

func isErrorType(t types.Type) bool {
	iface, ok := t.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	if iface.NumMethods() != 1 {
		return false
	}
	m := iface.Method(0)
	sig, ok := m.Type().(*types.Signature)
	return ok && m.Name() == "Error" &&
		sig.Params().Len() == 0 && sig.Results().Len() == 1
}

// isWrappingCall returns true for calls to known error-wrapping functions.
func isWrappingCall(call ssa.CallInstruction) bool {
	cc := call.Common()
	if cc.IsInvoke() {
		return false
	}
	fn, ok := cc.Value.(*ssa.Function)
	if !ok || fn.Package() == nil {
		return false
	}
	pkg := fn.Package().Pkg.Path()
	name := fn.Name()
	switch {
	case pkg == "fmt" && name == "Errorf":
		return true
	case pkg == "errors" && (name == "Wrap" || name == "Wrapf" || name == "WithMessage" || name == "WithStack"):
		return true
	case strings.HasSuffix(pkg, "github.com/pkg/errors") && (name == "Wrap" || name == "Wrapf"):
		return true
	}
	return false
}

// callUsesValue returns true if errVal appears in the call's argument list.
func callUsesValue(call ssa.CallInstruction, errVal ssa.Value) bool {
	for _, arg := range call.Common().Args {
		if arg == errVal {
			return true
		}
	}
	return false
}

// callReturnsError returns true if the call returns at least one error value.
func callReturnsError(call ssa.CallInstruction) bool {
	val := call.Value()
	if val == nil {
		return false
	}
	switch t := val.Type().(type) {
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if isErrorType(t.At(i).Type()) {
				return true
			}
		}
	default:
		return isErrorType(val.Type())
	}
	return false
}
