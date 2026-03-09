package dfa

import (
	"testing"

	errtypes "github.com/errsec/errsec/pkg/types"
)

func TestSummaryStore(t *testing.T) {
	store := NewSummaryStore()
	if store == nil {
		t.Fatal("NewSummaryStore returned nil")
	}

	// Get on empty store returns nil.
	if got := store.Get(nil); got != nil {
		t.Errorf("Get(nil) on empty store = %v, want nil", got)
	}
}

func TestSummaryEqual(t *testing.T) {
	a := &FunctionSummary{ReturnTaint: []bool{true}, MaxReturnRisk: errtypes.HIGH, Stable: true}
	b := &FunctionSummary{ReturnTaint: []bool{true}, MaxReturnRisk: errtypes.HIGH, Stable: true}
	c := &FunctionSummary{ReturnTaint: []bool{false}, MaxReturnRisk: errtypes.LOW, Stable: true}

	if !summaryEqual(a, b) {
		t.Error("identical summaries should be equal")
	}
	if summaryEqual(a, c) {
		t.Error("different summaries should not be equal")
	}
	if !summaryEqual(nil, nil) {
		t.Error("nil == nil should be true")
	}
	if summaryEqual(a, nil) {
		t.Error("non-nil != nil should be false")
	}
}

func TestAssignIDs(t *testing.T) {
	issues := []*errtypes.Issue{
		{Pattern: errtypes.PatternBlankIgnore, Risk: errtypes.HIGH},
		{Pattern: errtypes.PatternLogContinue, Risk: errtypes.MEDIUM},
		{Pattern: errtypes.PatternLogContinue, Risk: errtypes.LOW},
	}

	filtered := AssignIDs(issues, errtypes.MEDIUM)
	if len(filtered) != 2 {
		t.Errorf("AssignIDs(minRisk=MEDIUM) returned %d issues, want 2", len(filtered))
	}
	for i, iss := range filtered {
		if iss.ID != i+1 {
			t.Errorf("issue %d has ID %d, want %d", i, iss.ID, i+1)
		}
	}
}
