package dfa

import (
	"go/token"

	"golang.org/x/tools/go/ssa"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/loader"
	"github.com/errsec/errsec/internal/smartcfg"
	"github.com/errsec/errsec/pkg/config"
	errtypes "github.com/errsec/errsec/pkg/types"
)

// Engine performs forward, path-sensitive taint analysis over a Smart CFG.
type Engine struct {
	cfg        *config.Config
	classifier *classifier.Classifier
	summaries  *SummaryStore
	fset       *token.FileSet
	issues     []*errtypes.Issue
	skipped    bool
}

// NewEngine creates a new DFA Engine.
func NewEngine(
	cfg *config.Config,
	cls *classifier.Classifier,
	summaries *SummaryStore,
	fset *token.FileSet,
) *Engine {
	return &Engine{cfg: cfg, classifier: cls, summaries: summaries, fset: fset}
}

// AnalyseFunction runs the forward worklist DFA and returns detected issues.
// Returns (issues, skipped) where skipped is true if the complexity cap fired.
func (e *Engine) AnalyseFunction(fn *ssa.Function, graph *smartcfg.SCFG) ([]*errtypes.Issue, bool) {
	e.issues = nil
	e.skipped = false

	if graph == nil || graph.Entry() == nil {
		return nil, false
	}

	// Pre-pass: detect BLANK_IGNORE by inspecting call sites directly.
	for _, node := range graph.Nodes {
		for _, instr := range node.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			src := e.classifier.Classify(call)
			if src == nil {
				continue
			}
			if issue := detectBlankIgnore(call, src, e.fset); issue != nil {
				issue.FuncName = fn.Name()
				e.issues = append(e.issues, issue)
			}
		}
	}

	// Forward worklist DFA.
	entry := graph.Entry()
	inState := make(map[*smartcfg.SCFGNode]*Env)
	inState[entry] = NewEnv()

	worklist := []*smartcfg.SCFGNode{entry}
	visits := make(map[*smartcfg.SCFGNode]int)

	for len(worklist) > 0 {
		node := worklist[0]
		worklist = worklist[1:]

		visits[node]++
		if visits[node] > e.cfg.BranchCap {
			e.skipped = true
			pos := e.nodePos(node)
			e.issues = append(e.issues, &errtypes.Issue{
				Pattern:  errtypes.PatternUnanalysable,
				Risk:     errtypes.UNKNOWN,
				FuncName: fn.Name(),
				File:     pos.Filename,
				Line:     pos.Line,
			})
			return e.issues, true
		}

		env := inState[node]
		if env == nil {
			env = NewEnv()
		}

		for _, instr := range node.Instrs {
			env = e.transfer(env, instr, node)
		}

		// Check LOG_CONTINUE at each outgoing edge.
		for _, edge := range node.Succs {
			if edge.Cond != nil && edge.Cond.TrueIsErr {
				if issue := detectLogContinue(node, env, edge, e.fset); issue != nil {
					issue.FuncName = fn.Name()
					e.issues = append(e.issues, issue)
				}
			}

			succEnv := e.forkOnBranch(env, edge.Cond)
			old := inState[edge.To]
			var merged *Env
			if old == nil {
				merged = succEnv
			} else {
				merged = old.Join(succEnv)
			}
			if !merged.Equals(old) {
				inState[edge.To] = merged
				worklist = append(worklist, edge.To)
			}
		}
	}

	return e.issues, false
}

// ExtractSummary builds a FunctionSummary from the DFA final environments.
func (e *Engine) ExtractSummary(fn *ssa.Function, graph *smartcfg.SCFG, finalEnvs map[*smartcfg.SCFGNode]*Env) *FunctionSummary {
	sig := fn.Signature
	nRet := sig.Results().Len()
	returnTaint := make([]bool, nRet)
	maxRisk := errtypes.UNKNOWN

	for _, blk := range fn.Blocks {
		last := blk.Instrs[len(blk.Instrs)-1]
		ret, ok := last.(*ssa.Return)
		if !ok {
			continue
		}
		node := graph.BlockToNode[blk.Index]
		env := finalEnvs[node]
		if env == nil {
			continue
		}
		for i, val := range ret.Results {
			if i >= nRet {
				break
			}
			if !loader.IsErrorType(val.Type()) {
				continue
			}
			if env.Get(val) == errtypes.TAINTED {
				returnTaint[i] = true
				if meta := env.Meta(val); meta != nil && meta.Source.Risk > maxRisk {
					maxRisk = meta.Source.Risk
				}
			}
		}
	}

	return &FunctionSummary{
		Func:          fn,
		ReturnTaint:   returnTaint,
		MaxReturnRisk: maxRisk,
		Stable:        true,
	}
}

// transfer applies one SSA instruction to env and returns the updated env.
func (e *Engine) transfer(env *Env, instr ssa.Instruction, node *smartcfg.SCFGNode) *Env {
	env = env.Clone()

	switch v := instr.(type) {
	case ssa.CallInstruction:
		src := e.classifier.Classify(v)
		e.processCallResults(env, v, src, node)

	case *ssa.Phi:
		if loader.IsErrorType(v.Type()) {
			var merged errtypes.ErrorState = errtypes.CLEAN
			var bestMeta *TaintMeta
			for _, edge := range v.Edges {
				st := env.Get(edge)
				merged = errtypes.Join(merged, st)
				if st == errtypes.TAINTED && bestMeta == nil {
					bestMeta = env.Meta(edge)
				}
			}
			env.Set(v, merged)
			if merged == errtypes.TAINTED && bestMeta != nil {
				pos := e.fset.Position(v.Pos())
				env.SetTainted(v, bestMeta.withStep(errtypes.PathStep{
					Kind:     errtypes.StepPhi,
					FuncName: node.FuncName,
					File:     pos.Filename,
					Line:     pos.Line,
					Detail:   "phi-node: error joins from multiple control-flow paths",
				}))
			}
		}

	case *ssa.Return:
		for _, val := range v.Results {
			if loader.IsErrorType(val.Type()) && env.Get(val) == errtypes.TAINTED {
				env.Set(val, errtypes.HANDLED)
			}
		}

	case *ssa.Panic:
		if env.Get(v.X) == errtypes.TAINTED {
			env.Set(v.X, errtypes.HANDLED)
		}

	case *ssa.MakeInterface:
		if loader.IsErrorType(v.Type()) {
			propagateTaintSingle(env, v, v.X, e.fset, node)
		}

	case *ssa.UnOp:
		if loader.IsErrorType(v.Type()) {
			propagateTaintSingle(env, v, v.X, e.fset, node)
		}

	case *ssa.Store:
		if loader.IsErrorType(v.Val.Type()) && env.Get(v.Val) == errtypes.TAINTED {
			if meta := env.Meta(v.Val); meta != nil {
				pos := e.fset.Position(v.Pos())
				env.SetTainted(v.Addr, meta.withStep(errtypes.PathStep{
					Kind:     errtypes.StepAssign,
					FuncName: node.FuncName,
					File:     pos.Filename,
					Line:     pos.Line,
					Detail:   "tainted error stored to variable",
				}))
			}
		}
	}

	return env
}

// processCallResults updates the env for the results of a call instruction.
func (e *Engine) processCallResults(env *Env, call ssa.CallInstruction, src *classifier.ClassifiedSource, node *smartcfg.SCFGNode) {
	callVal, ok := call.(ssa.Value)
	if !ok {
		return
	}
	pos := e.fset.Position(call.Pos())

	if src != nil {
		if refs := callVal.Referrers(); refs != nil {
			for _, ref := range *refs {
				extract, ok := ref.(*ssa.Extract)
				if !ok {
					continue
				}
				if loader.IsErrorType(extract.Type()) {
					env.SetTainted(extract, &TaintMeta{
						Source: src,
						Path: []errtypes.PathStep{{
							Kind:     errtypes.StepSource,
							FuncName: node.FuncName,
							File:     pos.Filename,
							Line:     pos.Line,
							Detail:   src.PkgPath + "." + src.FuncName + "() — " + src.Reason,
						}},
					})
				}
			}
		} else if loader.IsErrorType(callVal.Type()) {
			env.SetTainted(callVal, &TaintMeta{
				Source: src,
				Path: []errtypes.PathStep{{
					Kind:     errtypes.StepSource,
					FuncName: node.FuncName,
					File:     pos.Filename,
					Line:     pos.Line,
					Detail:   src.PkgPath + "." + src.FuncName + "() — " + src.Reason,
				}},
			})
		}
		return
	}

	// Tier-2: apply callee summary.
	callee := call.Common().StaticCallee()
	if callee == nil {
		return
	}
	sum := e.summaries.Get(callee)
	if sum == nil || !sum.Stable {
		return
	}

	if refs := callVal.Referrers(); refs != nil {
		for _, ref := range *refs {
			extract, ok := ref.(*ssa.Extract)
			if !ok {
				continue
			}
			if extract.Index < len(sum.ReturnTaint) && sum.ReturnTaint[extract.Index] {
				if loader.IsErrorType(extract.Type()) {
					env.SetTainted(extract, &TaintMeta{
						Source: &classifier.ClassifiedSource{
							Risk:   sum.MaxReturnRisk,
							Reason: "propagated from " + callee.Name(),
						},
						Path: []errtypes.PathStep{{
							Kind:     errtypes.StepCall,
							FuncName: node.FuncName,
							File:     pos.Filename,
							Line:     pos.Line,
							Detail:   "call to " + callee.Name() + " — tainted return",
						}},
					})
				}
			}
		}
	}
}

// forkOnBranch refines env based on the branch condition annotation.
func (e *Engine) forkOnBranch(env *Env, cond *smartcfg.BranchCond) *Env {
	if cond == nil || !cond.IsNilCheck {
		return env
	}
	forked := env.Clone()
	if cond.TrueIsErr {
		forked.SetInErrBranch(cond.Value, true)
	} else {
		if forked.Get(cond.Value) == errtypes.TAINTED {
			forked.Set(cond.Value, errtypes.CLEAN)
		}
	}
	return forked
}

func (e *Engine) nodePos(node *smartcfg.SCFGNode) token.Position {
	if node == nil || len(node.Instrs) == 0 {
		return token.Position{}
	}
	return e.fset.Position(node.Instrs[0].Pos())
}

func propagateTaintSingle(env *Env, dst ssa.Value, src ssa.Value, fset *token.FileSet, node *smartcfg.SCFGNode) {
	if env.Get(src) != errtypes.TAINTED {
		return
	}
	meta := env.Meta(src)
	if meta == nil {
		return
	}
	pos := fset.Position(dst.Pos())
	env.SetTainted(dst, meta.withStep(errtypes.PathStep{
		Kind:     errtypes.StepAssign,
		FuncName: node.FuncName,
		File:     pos.Filename,
		Line:     pos.Line,
		Detail:   "taint propagated via assignment",
	}))
}

// Keep compiler happy for unused import.
