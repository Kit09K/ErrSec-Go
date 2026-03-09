package classifier

import (
	"go/types"

	"golang.org/x/tools/go/ssa"

	"github.com/errsec/errsec/internal/loader"
	"github.com/errsec/errsec/pkg/config"
	errtypes "github.com/errsec/errsec/pkg/types"
)

// ClassifiedSource is the result of successfully classifying a call site.
type ClassifiedSource struct {
	// Call is the SSA call instruction.
	Call ssa.CallInstruction
	// Risk is the assigned risk level.
	Risk errtypes.RiskLevel
	// Reason is the human-readable classification rationale.
	Reason string
	// PkgPath is the import path of the callee's package.
	PkgPath string
	// FuncName is the name of the callee function.
	FuncName string
	// ErrorReturnIdx is the index of the error return value in the call's result tuple.
	ErrorReturnIdx int
}

// SummaryStore is a minimal interface the classifier uses to look up
// callee function summaries for Tier-2 (transitive) risk inheritance.
// The actual implementation lives in the dfa package; this interface
// breaks the import cycle.
type SummaryStore interface {
	MaxReturnRisk(fn *ssa.Function) errtypes.RiskLevel
}

// Classifier performs rule-based classification of call sites.
type Classifier struct {
	rules         []ClassifierRule
	summaryStore  SummaryStore // may be nil for first-pass classification
}

// New creates a new Classifier with the built-in rules plus any extra rules
// from the config. extraRules are appended after the built-in HIGH rules.
func New(cfg *config.Config, store SummaryStore) *Classifier {
	rules := make([]ClassifierRule, len(BuiltinRules))
	copy(rules, BuiltinRules)

	// Append user-defined rules from errsec.yaml.
	for _, r := range cfg.ExtraRules {
		risk := r.Risk
		if risk == errtypes.UNKNOWN {
			// Parse risk from string field (set during config loading).
			parsed, err := errtypes.ParseRiskLevel(r.RiskStr)
			if err == nil {
				risk = parsed
			}
		}
		rules = append(rules, ClassifierRule{
			PkgPattern:  r.Pkg,
			FuncPattern: r.Func,
			Risk:        risk,
			Reason:      r.Reason,
		})
	}

	return &Classifier{rules: rules, summaryStore: store}
}

// Classify attempts to classify a call site. It returns a *ClassifiedSource
// if the call returns an error and the callee matches a rule, otherwise nil.
//
// Tier 1: direct rule match against PkgPattern + FuncPattern.
// Tier 2: transitive risk from callee's own function summary.
func (c *Classifier) Classify(call ssa.CallInstruction) *ClassifiedSource {
	// Only consider calls that actually return an error.
	if !c.callReturnsError(call) {
		return nil
	}

	callee := call.Common().StaticCallee()
	if callee == nil {
		// Indirect call — cannot classify reliably without type analysis.
		// Conservative: return nil (won't over-report).
		return nil
	}

	pkg := callee.Package()
	if pkg == nil {
		return nil
	}
	pkgPath := pkg.Pkg.Path()
	fnName := stripReceiverPrefix(callee.Name())

	// ── Tier 1: direct rule match ─────────────────────────────────────────
	for _, rule := range c.rules {
		if matchRule(rule, pkgPath, fnName) {
			idx := c.firstErrorReturnIdx(call)
			return &ClassifiedSource{
				Call:           call,
				Risk:           rule.Risk,
				Reason:         rule.Reason,
				PkgPath:        pkgPath,
				FuncName:       fnName,
				ErrorReturnIdx: idx,
			}
		}
	}

	// ── Tier 2: transitive risk from callee summary ───────────────────────
	if c.summaryStore != nil {
		risk := c.summaryStore.MaxReturnRisk(callee)
		if risk > errtypes.UNKNOWN {
			idx := c.firstErrorReturnIdx(call)
			return &ClassifiedSource{
				Call:           call,
				Risk:           risk,
				Reason:         "transitive from callee " + callee.Name(),
				PkgPath:        pkgPath,
				FuncName:       fnName,
				ErrorReturnIdx: idx,
			}
		}
	}

	return nil
}

// callReturnsError reports whether the call instruction has an error-typed result.
func (c *Classifier) callReturnsError(call ssa.CallInstruction) bool {
	sig, ok := call.Common().Value.Type().Underlying().(*types.Signature)
	if !ok {
		return false
	}
	return loader.ReturnsError(sig)
}

// firstErrorReturnIdx returns the index of the first error-typed return value.
func (c *Classifier) firstErrorReturnIdx(call ssa.CallInstruction) int {
	sig, ok := call.Common().Value.Type().Underlying().(*types.Signature)
	if !ok {
		return -1
	}
	indices := loader.ErrorReturnIndices(sig.Results())
	if len(indices) == 0 {
		return -1
	}
	return indices[0]
}

// stripReceiverPrefix strips the (*T). or (T). receiver prefix from a method name.
// e.g. "(*UserRepo).GetByID" -> "GetByID"
func stripReceiverPrefix(name string) string {
	for i, ch := range name {
		if ch == ')' && i+1 < len(name) && name[i+1] == '.' {
			return name[i+2:]
		}
	}
	return name
}
