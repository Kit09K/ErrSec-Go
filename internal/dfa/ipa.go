package dfa

import (
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/ssa"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/smartcfg"
	"github.com/errsec/errsec/pkg/config"
	errtypes "github.com/errsec/errsec/pkg/types"
)

const maxSCCIterations = 20

// IPAEngine orchestrates inter-procedural analysis.
type IPAEngine struct {
	cfg        *config.Config
	classifier *classifier.Classifier
	summaries  *SummaryStore
	cfgBuilder *smartcfg.Builder
	fset       *token.FileSet
	allIssues  []*errtypes.Issue
	stats      errtypes.Stats
}

// NewIPAEngine creates an inter-procedural analysis engine.
func NewIPAEngine(
	cfg *config.Config,
	cls *classifier.Classifier,
	summaries *SummaryStore,
	fset *token.FileSet,
) *IPAEngine {
	return &IPAEngine{
		cfg:        cfg,
		classifier: cls,
		summaries:  summaries,
		cfgBuilder: smartcfg.NewBuilder(fset),
		fset:       fset,
	}
}

// Analyse runs the full IPA pipeline.
func (ipa *IPAEngine) Analyse(prog *ssa.Program, funcs []*ssa.Function) ([]*errtypes.Issue, errtypes.Stats) {
	// Build call graph using Rapid Type Analysis.
	var roots []*ssa.Function
	for _, fn := range funcs {
		if fn.Name() == "main" || fn.Name() == "init" {
			roots = append(roots, fn)
		}
	}
	if len(roots) == 0 {
		roots = funcs
	}

	var cg *callgraph.Graph
	if len(roots) > 0 {
		rtaResult := rta.Analyze(roots, true)
		cg = rtaResult.CallGraph
	}

	order := ipa.computeBottomUpOrder(cg, funcs)

	// Initialise all summaries to bottom.
	for _, fn := range order {
		nRet := fn.Signature.Results().Len()
		ipa.summaries.Set(fn, &FunctionSummary{
			Func:          fn,
			ReturnTaint:   make([]bool, nRet),
			MaxReturnRisk: errtypes.UNKNOWN,
			Stable:        false,
		})
	}

	// Bottom-up fixed-point iteration.
	for iter := 0; iter < maxSCCIterations; iter++ {
		changed := false
		for _, fn := range order {
			if len(fn.Blocks) == 0 {
				continue
			}
			graph := ipa.cfgBuilder.Build(fn)
			dfaEngine := NewEngine(ipa.cfg, ipa.classifier, ipa.summaries, ipa.fset)
			issues, skipped := dfaEngine.AnalyseFunction(fn, graph)

			if iter == 0 {
				ipa.allIssues = append(ipa.allIssues, issues...)
				if skipped {
					ipa.stats.FunctionsSkipped++
				} else {
					ipa.stats.FunctionsAnalysed++
				}
			}

			finalEnvs := ipa.runDFAForSummary(fn, graph)
			newSum := dfaEngine.ExtractSummary(fn, graph, finalEnvs)

			old := ipa.summaries.Get(fn)
			if !summaryEqual(old, newSum) {
				newSum.Stable = true
				ipa.summaries.Set(fn, newSum)
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	return ipa.allIssues, ipa.stats
}

// runDFAForSummary runs DFA and returns the per-node final environments.
func (ipa *IPAEngine) runDFAForSummary(fn *ssa.Function, graph *smartcfg.SCFG) map[*smartcfg.SCFGNode]*Env {
	if graph == nil || graph.Entry() == nil {
		return nil
	}

	entry := graph.Entry()
	inState := make(map[*smartcfg.SCFGNode]*Env)
	inState[entry] = NewEnv()

	worklist := []*smartcfg.SCFGNode{entry}
	visits := make(map[*smartcfg.SCFGNode]int)
	dfaEngine := NewEngine(ipa.cfg, ipa.classifier, ipa.summaries, ipa.fset)

	for len(worklist) > 0 {
		node := worklist[0]
		worklist = worklist[1:]

		visits[node]++
		if visits[node] > ipa.cfg.BranchCap {
			break
		}

		env := inState[node]
		if env == nil {
			env = NewEnv()
		}

		for _, instr := range node.Instrs {
			env = dfaEngine.transfer(env, instr, node)
		}

		for _, edge := range node.Succs {
			succEnv := dfaEngine.forkOnBranch(env, edge.Cond)
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

	return inState
}

// computeBottomUpOrder returns functions in reverse DFS post-order (callees first).
func (ipa *IPAEngine) computeBottomUpOrder(cg *callgraph.Graph, allFuncs []*ssa.Function) []*ssa.Function {
	if cg == nil {
		return allFuncs
	}

	visited := make(map[*ssa.Function]bool)
	var postOrder []*ssa.Function

	var dfs func(node *callgraph.Node)
	dfs = func(node *callgraph.Node) {
		if node == nil || node.Func == nil {
			return
		}
		fn := node.Func
		if visited[fn] {
			return
		}
		visited[fn] = true
		for _, edge := range node.Out {
			dfs(edge.Callee)
		}
		postOrder = append(postOrder, fn)
	}

	dfs(cg.Root)

	for _, fn := range allFuncs {
		if !visited[fn] && len(fn.Blocks) > 0 {
			postOrder = append(postOrder, fn)
		}
	}

	// Reverse: callees first = bottom-up.
	for i, j := 0, len(postOrder)-1; i < j; i, j = i+1, j-1 {
		postOrder[i], postOrder[j] = postOrder[j], postOrder[i]
	}

	return postOrder
}

// deduplicateIssues removes duplicate issues by file+line+pattern key.
func deduplicateIssues(issues []*errtypes.Issue) []*errtypes.Issue {
	seen := make(map[string]bool)
	var out []*errtypes.Issue
	for _, iss := range issues {
		key := iss.File + iss.FuncName + string(iss.Pattern)
		if !seen[key] {
			seen[key] = true
			out = append(out, iss)
		}
	}
	return out
}

// AssignIDs assigns sequential IDs to issues, filtering by minimum risk.
func AssignIDs(issues []*errtypes.Issue, minRisk errtypes.RiskLevel) []*errtypes.Issue {
	var out []*errtypes.Issue
	id := 1
	for _, iss := range deduplicateIssues(issues) {
		if iss.Risk >= minRisk {
			iss.ID = id
			id++
			out = append(out, iss)
		}
	}
	return out
}

// Ensure loader is used (for errorReturnCount).
