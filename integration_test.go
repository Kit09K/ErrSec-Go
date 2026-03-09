//go:build integration

// Integration tests for ErrSec — run with: go test -tags integration ./...
// These tests require the full Go toolchain and network access for go/packages.
package errsec_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/dfa"
	"github.com/errsec/errsec/internal/loader"
	"github.com/errsec/errsec/pkg/config"
	errtypes "github.com/errsec/errsec/pkg/types"
)

type wantIssue struct {
	pattern errtypes.FailOpenPattern
	risk    errtypes.RiskLevel
	file    string // basename only
}

type testCase struct {
	name       string
	file       string
	wantIssues []wantIssue
}

var testCases = []testCase{
	{
		name: "blank ignore on db.Query",
		file: "testdata/vuln/blank_ignore_db.go",
		wantIssues: []wantIssue{
			{pattern: errtypes.PatternBlankIgnore, risk: errtypes.HIGH, file: "blank_ignore_db.go"},
		},
	},
	{
		name: "log-continue on os.ReadFile",
		file: "testdata/vuln/log_continue_file.go",
		wantIssues: []wantIssue{
			{pattern: errtypes.PatternLogContinue, risk: errtypes.MEDIUM, file: "log_continue_file.go"},
		},
	},
	{
		name:       "safe: correctly returned error",
		file:       "testdata/safe/return_error.go",
		wantIssues: nil, // no issues expected
	},
}

func TestIntegrationSuite(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.file); os.IsNotExist(err) {
				t.Skipf("testdata file not found: %s", tc.file)
			}

			cfg := config.Default()
			cfg.WorkDir = "."
			cfg.BranchCap = 1000
			cfg.Timeout = 30 * time.Second

			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()
			_ = ctx

			loaded, err := loader.Load(cfg, []string{tc.file})
			if err != nil {
				t.Fatalf("loader: %v", err)
			}

			summaryStore := dfa.NewSummaryStore()
			cls := classifier.New(cfg, summaryStore)
			ipaEngine := dfa.NewIPAEngine(cfg, cls, summaryStore, loaded.Fset)
			issues, _ := ipaEngine.Analyse(loaded.Prog, loaded.Functions)
			filtered := dfa.AssignIDs(issues, errtypes.UNKNOWN)

			if len(tc.wantIssues) == 0 {
				if len(filtered) > 0 {
					t.Errorf("expected no issues, got %d:", len(filtered))
					for _, iss := range filtered {
						t.Errorf("  %s", iss)
					}
				}
				return
			}

			for _, want := range tc.wantIssues {
				found := false
				for _, got := range filtered {
					if got.Pattern == want.pattern &&
						got.Risk == want.risk &&
						strings.HasSuffix(got.File, want.file) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected issue %s[%s] in %s — not found",
						want.pattern, want.risk, want.file)
				}
			}
		})
	}
}

// TestLoadSingle verifies the loader handles a single file without panicking.
func TestLoadSingle(t *testing.T) {
	f := "testdata/vuln/blank_ignore_db.go"
	if _, err := os.Stat(f); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}
	cfg := config.Default()
	cfg.WorkDir = filepath.Dir(f)
	_, err := loader.Load(cfg, []string{f})
	if err != nil {
		t.Logf("load error (expected for single-file without module): %v", err)
	}
}
