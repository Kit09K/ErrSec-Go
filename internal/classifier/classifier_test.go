package classifier

import (
	"testing"

	errtypes "github.com/errsec/errsec/pkg/types"
)

func TestMatchRule(t *testing.T) {
	tests := []struct {
		rule    ClassifierRule
		pkgPath string
		fnName  string
		want    bool
	}{
		{ClassifierRule{"database/sql", "", errtypes.HIGH, ""}, "database/sql", "Query", true},
		{ClassifierRule{"database/sql", "", errtypes.HIGH, ""}, "database/sql", "Exec", true},
		{ClassifierRule{"database/sql", "Query", errtypes.HIGH, ""}, "database/sql", "Query", true},
		{ClassifierRule{"database/sql", "Query", errtypes.HIGH, ""}, "database/sql", "Exec", false},
		{ClassifierRule{"crypto/", "", errtypes.HIGH, ""}, "crypto/tls", "Dial", true},
		{ClassifierRule{"net/http", "Get", errtypes.HIGH, ""}, "net/http", "Get", true},
		{ClassifierRule{"net/http", "Get", errtypes.HIGH, ""}, "net/http", "Post", false},
		{ClassifierRule{"log", "", errtypes.LOW, ""}, "log", "Printf", true},
		{ClassifierRule{"log", "", errtypes.LOW, ""}, "fmt", "Printf", false},
	}

	for _, tt := range tests {
		got := matchRule(tt.rule, tt.pkgPath, tt.fnName)
		if got != tt.want {
			t.Errorf("matchRule(%q, %q, %q) = %v, want %v",
				tt.rule.PkgPattern, tt.pkgPath, tt.fnName, got, tt.want)
		}
	}
}

func TestBuiltinRulesOrdering(t *testing.T) {
	// Verify that all HIGH rules come before LOW rules in the built-in table.
	// This is important because we use first-match semantics.
	seenNonHigh := false
	for _, rule := range BuiltinRules {
		if rule.Risk < errtypes.HIGH {
			seenNonHigh = true
		}
		if seenNonHigh && rule.Risk == errtypes.HIGH {
			t.Errorf("HIGH rule %q appears after a lower-risk rule — reorder BuiltinRules", rule.PkgPattern)
		}
	}
}

func TestStripReceiverPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"(*UserRepo).GetByID", "GetByID"},
		{"(UserRepo).Save", "Save"},
		{"Query", "Query"},
		{"", ""},
	}
	for _, tt := range tests {
		got := stripReceiverPrefix(tt.input)
		if got != tt.want {
			t.Errorf("stripReceiverPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
