package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	errtypes "github.com/errsec/errsec/pkg/types"
	"github.com/errsec/errsec/pkg/config"
)

func makeTestResult() *Result {
	return NewResult("0.1.0", "./...",
		[]*errtypes.Issue{
			{
				ID:           1,
				Pattern:      errtypes.PatternBlankIgnore,
				Risk:         errtypes.HIGH,
				FuncName:     "GetUser",
				File:         "/project/repo/user.go",
				Line:         42,
				SourcePkg:    "database/sql",
				SourceFunc:   "Query",
				SourceReason: "SQL database I/O",
				Path: []errtypes.PathStep{
					{Kind: errtypes.StepSource, File: "user.go", Line: 42, Detail: "db.Query() error discarded"},
					{Kind: errtypes.StepSink, File: "user.go", Line: 42, Detail: "blank identifier ignore"},
				},
			},
		},
		errtypes.Stats{FunctionsAnalysed: 10, FunctionsSkipped: 1},
		150*time.Millisecond,
		config.Default(),
	)
}

func TestTextFormatterNoIssues(t *testing.T) {
	r := NewResult("0.1.0", "./...",
		nil,
		errtypes.Stats{FunctionsAnalysed: 5},
		10*time.Millisecond,
		config.Default(),
	)
	var buf bytes.Buffer
	f := &TextFormatter{}
	if err := f.Write(&buf, r); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "No issues found") {
		t.Errorf("expected 'No issues found' in output, got:\n%s", output)
	}
}

func TestTextFormatterWithIssue(t *testing.T) {
	r := makeTestResult()
	var buf bytes.Buffer
	f := &TextFormatter{}
	if err := f.Write(&buf, r); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	output := buf.String()
	checks := []string{"ISSUE #1", "BLANK_IGNORE", "HIGH", "GetUser", "database/sql"}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in text output, not found in:\n%s", check, output)
		}
	}
}

func TestJSONFormatterWithIssue(t *testing.T) {
	r := makeTestResult()
	var buf bytes.Buffer
	f := &JSONFormatter{}
	if err := f.Write(&buf, r); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	output := buf.String()
	checks := []string{`"pattern"`, `"BLANK_IGNORE"`, `"risk"`, `"HIGH"`, `"errsec_version"`, `"issues"`}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in JSON output, not found", check)
		}
	}
}

func TestHasIssuesAbove(t *testing.T) {
	r := makeTestResult()
	if !r.HasIssuesAbove(errtypes.HIGH) {
		t.Error("HasIssuesAbove(HIGH) should be true")
	}
	if r.HasIssuesAbove(errtypes.HIGH + 1) {
		t.Error("HasIssuesAbove(above HIGH) should be false")
	}
}

func TestNewFormatter(t *testing.T) {
	if _, ok := NewFormatter("json").(*JSONFormatter); !ok {
		t.Error("NewFormatter('json') should return *JSONFormatter")
	}
	if _, ok := NewFormatter("text").(*TextFormatter); !ok {
		t.Error("NewFormatter('text') should return *TextFormatter")
	}
	if _, ok := NewFormatter("unknown").(*TextFormatter); !ok {
		t.Error("NewFormatter('unknown') should default to *TextFormatter")
	}
}
