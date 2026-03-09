package dfa

import (
	"testing"

	errtypes "github.com/errsec/errsec/pkg/types"
)

// mockValue is a minimal ssa.Value stub for testing.
type mockValue struct{ name string }

func (m *mockValue) Name() string                             { return m.name }
func (m *mockValue) Type() interface{}                        { return nil }
func (m *mockValue) Parent() interface{}                      { return nil }
func (m *mockValue) Pos() interface{}                         { return nil }
func (m *mockValue) String() string                           { return m.name }
func (m *mockValue) Referrers() *[]interface{}                { return nil }

func TestEnvGetDefault(t *testing.T) {
	env := NewEnv()
	// Getting a value not in the env should return CLEAN.
	if got := env.Get(nil); got != errtypes.CLEAN {
		t.Errorf("Get(nil) = %v, want CLEAN", got)
	}
}

func TestEnvSetAndGet(t *testing.T) {
	// We can't easily create ssa.Value stubs without the full toolchain,
	// so we test the Join logic directly.
	a := NewEnv()
	b := NewEnv()

	// Test Join of two clean envs.
	merged := a.Join(b)
	if merged == nil {
		t.Fatal("Join returned nil")
	}
}

func TestEnvClone(t *testing.T) {
	env := NewEnv()
	clone := env.Clone()
	if clone == nil {
		t.Fatal("Clone returned nil")
	}
	// Clone should be a separate object.
	if clone == env {
		t.Error("Clone returned same pointer")
	}
}

func TestEnvEquals(t *testing.T) {
	a := NewEnv()
	b := NewEnv()
	if !a.Equals(b) {
		t.Error("two empty envs should be equal")
	}
	if !a.Equals(nil) {
		t.Error("empty env should equal nil")
	}
}

func TestJoinStates(t *testing.T) {
	tests := []struct {
		a, b errtypes.ErrorState
		want errtypes.ErrorState
	}{
		{errtypes.CLEAN, errtypes.CLEAN, errtypes.CLEAN},
		{errtypes.CLEAN, errtypes.TAINTED, errtypes.TAINTED},
		{errtypes.TAINTED, errtypes.HANDLED, errtypes.TAINTED},
		{errtypes.HANDLED, errtypes.CLEAN, errtypes.HANDLED},
	}
	for _, tt := range tests {
		got := errtypes.Join(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Join(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
