package types

import "testing"

func TestJoin(t *testing.T) {
	tests := []struct {
		a, b ErrorState
		want ErrorState
	}{
		{CLEAN, CLEAN, CLEAN},
		{CLEAN, TAINTED, TAINTED},
		{TAINTED, CLEAN, TAINTED},
		{HANDLED, TAINTED, TAINTED},
		{HANDLED, CLEAN, HANDLED},
		{TAINTED, TAINTED, TAINTED},
	}
	for _, tt := range tests {
		got := Join(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Join(%s, %s) = %s, want %s", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestRiskLevelOrdering(t *testing.T) {
	if !(UNKNOWN < LOW && LOW < MEDIUM && MEDIUM < HIGH) {
		t.Error("risk level ordering violated: must be UNKNOWN < LOW < MEDIUM < HIGH")
	}
}

func TestParseRiskLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    RiskLevel
		wantErr bool
	}{
		{"LOW", LOW, false},
		{"MEDIUM", MEDIUM, false},
		{"HIGH", HIGH, false},
		{"UNKNOWN", UNKNOWN, false},
		{"bad", UNKNOWN, true},
		{"", UNKNOWN, true},
	}
	for _, tt := range tests {
		got, err := ParseRiskLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseRiskLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseRiskLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestErrorStateString(t *testing.T) {
	if CLEAN.String() != "CLEAN" {
		t.Errorf("CLEAN.String() = %q", CLEAN.String())
	}
	if HANDLED.String() != "HANDLED" {
		t.Errorf("HANDLED.String() = %q", HANDLED.String())
	}
	if TAINTED.String() != "TAINTED" {
		t.Errorf("TAINTED.String() = %q", TAINTED.String())
	}
}
