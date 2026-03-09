package dfa

import (
	"go/token"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/smartcfg"
	"github.com/errsec/errsec/internal/loader"
	errtypes "github.com/errsec/errsec/pkg/types"
)

// ── Pattern: BLANK_IGNORE ─────────────────────────────────────────────────────

// detectBlankIgnore checks whether a call instruction's error return value is
// never referenced (i.e., discarded with _).
// In SSA, a blank-identifier discard means the value is extracted but has
// zero Referrers.
func detectBlankIgnore(
	call ssa.CallInstruction,
	src *classifier.ClassifiedSource,
	fset *token.FileSet,
) *errtypes.Issue {
	if src == nil {
		return nil
	}

	// In SSA, when a multi-value call is assigned, each result is extracted
	// via *ssa.Extract. Check each Extract for the error position.
	var errExtracts []ssa.Value

	// The call's Value() gives us the *ssa.Call (which is itself a Value).
	// Extract instructions refer back to it.
	callVal, ok := call.(ssa.Value)
	if !ok {
		return nil
	}

	// Scan referrers of the call value for Extract instructions at error positions.
	if refs := callVal.Referrers(); refs != nil {
		for _, ref := range *refs {
			extract, ok := ref.(*ssa.Extract)
			if !ok {
				continue
			}
			// Is this extract at an error-typed position?
			if loader.IsErrorType(extract.Type()) {
				errExtracts = append(errExtracts, extract)
			}
		}
	} else {
		// Single-return call: the call itself may be error-typed.
		if loader.IsErrorType(callVal.Type()) {
			errExtracts = append(errExtracts, callVal)
		}
	}

	for _, ev := range errExtracts {
		refs := ev.Referrers()
		if refs == nil || len(*refs) == 0 {
			// No referrers → error value is discarded (blank identifier).
			pos := fset.Position(call.Pos())
			return &errtypes.Issue{
				Pattern:      errtypes.PatternBlankIgnore,
				Risk:         src.Risk,
				PkgPath:      src.PkgPath,
				FuncName:     funcNameFromInstr(call),
				File:         pos.Filename,
				Line:         pos.Line,
				SourcePkg:    src.PkgPath,
				SourceFunc:   src.FuncName,
				SourceReason: src.Reason,
				Path: []errtypes.PathStep{
					{
						Kind:     errtypes.StepSource,
						FuncName: funcNameFromInstr(call),
						File:     pos.Filename,
						Line:     pos.Line,
						Detail:   src.FuncName + "() error return discarded with _",
					},
					{
						Kind:     errtypes.StepSink,
						FuncName: funcNameFromInstr(call),
						File:     pos.Filename,
						Line:     pos.Line,
						Detail:   "error value has no referrers — blank identifier ignore",
					},
				},
			}
		}
	}
	return nil
}

// ── Pattern: LOG_CONTINUE ─────────────────────────────────────────────────────

// detectLogContinue checks whether an error-check branch (if err != nil)
// terminates only with a log call and falls through to the non-error path.
func detectLogContinue(
	node *smartcfg.SCFGNode,
	env *Env,
	edge *smartcfg.SCFGEdge,
	fset *token.FileSet,
) *errtypes.Issue {
	if edge == nil || edge.Cond == nil {
		return nil
	}
	if !edge.Cond.TrueIsErr {
		return nil // This is the non-error branch.
	}
	errVal := edge.Cond.Value
	if env.Get(errVal) != errtypes.TAINTED {
		return nil
	}

	// Walk the error-branch node: is it safely terminated?
	errNode := edge.To
	if isSafelyTerminated(errNode) {
		return nil // error is returned / panicked — safe.
	}

	// Collect log calls in the error branch for the trace.
	logSteps := collectLogSteps(errNode, fset)

	// Build the issue.
	meta := env.Meta(errVal)
	if meta == nil {
		return nil
	}

	sourcePos := fset.Position(node.Instrs[0].Pos())
	errPos := fset.Position(errNode.Instrs[0].Pos())

	path := make([]errtypes.PathStep, len(meta.Path))
	copy(path, meta.Path)

	path = append(path, errtypes.PathStep{
		Kind:     errtypes.StepCheck,
		FuncName: node.FuncName,
		File:     sourcePos.Filename,
		Line:     sourcePos.Line,
		Detail:   "if err != nil — entering error branch",
	})
	path = append(path, logSteps...)
	path = append(path, errtypes.PathStep{
		Kind:     errtypes.StepSink,
		FuncName: node.FuncName,
		File:     errPos.Filename,
		Line:     errPos.Line,
		Detail:   "execution falls through — error not propagated (fail-open)",
	})

	return &errtypes.Issue{
		Pattern:      errtypes.PatternLogContinue,
		Risk:         meta.Source.Risk,
		PkgPath:      meta.Source.PkgPath,
		FuncName:     node.FuncName,
		File:         sourcePos.Filename,
		Line:         sourcePos.Line,
		SourcePkg:    meta.Source.PkgPath,
		SourceFunc:   meta.Source.FuncName,
		SourceReason: meta.Source.Reason,
		Path:         path,
	}
}

// isSafelyTerminated reports whether node terminates via return, panic, or os.Exit.
func isSafelyTerminated(node *smartcfg.SCFGNode) bool {
	if node == nil || len(node.Instrs) == 0 {
		return false
	}
	for _, instr := range node.Instrs {
		switch instr.(type) {
		case *ssa.Return, *ssa.Panic:
			return true
		case ssa.CallInstruction:
			call := instr.(ssa.CallInstruction)
			callee := call.Common().StaticCallee()
			if callee != nil {
				// os.Exit
				if callee.Name() == "Exit" {
					if pkg := callee.Package(); pkg != nil {
						if pkg.Pkg.Path() == "os" {
							return true
						}
					}
				}
			}
		}
	}
	// Recursively check unique successors (if the error branch is a single chain).
	if len(node.Succs) == 1 {
		return isSafelyTerminated(node.Succs[0].To)
	}
	return false
}

// collectLogSteps scans an error-branch node for log/fmt calls and returns
// PathSteps for them.
func collectLogSteps(node *smartcfg.SCFGNode, fset *token.FileSet) []errtypes.PathStep {
	var steps []errtypes.PathStep
	if node == nil {
		return steps
	}
	for _, instr := range node.Instrs {
		call, ok := instr.(ssa.CallInstruction)
		if !ok {
			continue
		}
		callee := call.Common().StaticCallee()
		if callee == nil {
			continue
		}
		pkg := callee.Package()
		if pkg == nil {
			continue
		}
		pkgPath := pkg.Pkg.Path()
		if strings.HasPrefix(pkgPath, "log") || strings.HasPrefix(pkgPath, "fmt") {
			pos := fset.Position(instr.Pos())
			steps = append(steps, errtypes.PathStep{
				Kind:     errtypes.StepLog,
				FuncName: node.FuncName,
				File:     pos.Filename,
				Line:     pos.Line,
				Detail:   pkgPath + "." + callee.Name() + "(err) — log only",
			})
		}
	}
	return steps
}

// funcNameFromInstr extracts the enclosing function name from an instruction.
func funcNameFromInstr(instr ssa.Instruction) string {
	if instr == nil {
		return ""
	}
	blk := instr.Block()
	if blk == nil {
		return ""
	}
	return blk.Parent().Name()
}
