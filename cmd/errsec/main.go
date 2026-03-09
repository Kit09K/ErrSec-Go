// Command errsec is the ErrSec static analysis CLI.
// It runs the full 5-stage pipeline and reports fail-open vulnerabilities.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/errsec/errsec/internal/classifier"
	"github.com/errsec/errsec/internal/dfa"
	"github.com/errsec/errsec/internal/loader"
	"github.com/errsec/errsec/internal/report"
	"github.com/errsec/errsec/pkg/config"
	errtypes "github.com/errsec/errsec/pkg/types"
)

const (
	toolVersion = "0.1.0"

	exitOK      = 0 // no issues at/above threshold
	exitIssues  = 1 // issues found
	exitError   = 2 // analysis error
	exitTimeout = 3 // timeout
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := config.Default()

	// ── Flags ─────────────────────────────────────────────────────────────
	var (
		formatFlag  = flag.String("format", "text", "Output format: text|json")
		riskFlag    = flag.String("risk", "LOW", "Minimum risk level: LOW|MEDIUM|HIGH")
		capFlag     = flag.Int("cap", 1000, "Branch complexity cap per function")
		configFlag  = flag.String("config", "", "Path to errsec.yaml config file")
		workersFlag = flag.Int("workers", runtime.NumCPU(), "Number of parallel workers")
		timeoutFlag = flag.String("timeout", "5m", "Analysis timeout (e.g. 30s, 5m)")
		verboseFlag = flag.Bool("v", false, "Verbose: log per-function progress")
		versionFlag = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Printf("errsec v%s\n", toolVersion)
		return exitOK
	}

	patterns := flag.Args()
	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "errsec: no package pattern specified")
		fmt.Fprintln(os.Stderr, "usage: errsec [flags] <pattern> [patterns...]")
		fmt.Fprintln(os.Stderr, "example: errsec ./...")
		return exitError
	}

	// Parse risk level.
	minRisk, err := errtypes.ParseRiskLevel(*riskFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "errsec: -risk: %v\n", err)
		return exitError
	}

	// Parse timeout.
	timeout, err := time.ParseDuration(*timeoutFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "errsec: -timeout: %v\n", err)
		return exitError
	}

	cfg.Patterns = patterns
	cfg.Format = *formatFlag
	cfg.MinRisk = minRisk
	cfg.BranchCap = *capFlag
	cfg.NumWorkers = *workersFlag
	cfg.Timeout = timeout
	cfg.Verbose = *verboseFlag
	cfg.WorkDir = "."

	// Load optional YAML config.
	configPath := *configFlag
	if configPath == "" {
		if _, err := os.Stat("errsec.yaml"); err == nil {
			configPath = "errsec.yaml"
		}
	}
	if configPath != "" {
		if err := classifier.LoadYAMLConfig(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "errsec: config: %v\n", err)
			return exitError
		}
	}

	// ── Run analysis ──────────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, code := runAnalysis(ctx, cfg)
	if code != exitOK && result == nil {
		return code
	}

	// ── Write report ──────────────────────────────────────────────────────
	formatter := report.NewFormatter(cfg.Format)
	if err := formatter.Write(os.Stdout, result); err != nil {
		fmt.Fprintf(os.Stderr, "errsec: report: %v\n", err)
		return exitError
	}

	if result.HasIssuesAbove(cfg.MinRisk) {
		return exitIssues
	}
	return exitOK
}

// runAnalysis executes the five-stage pipeline and returns a Result.
func runAnalysis(ctx context.Context, cfg *config.Config) (*report.Result, int) {
	start := time.Now()
	target := cfg.Patterns[0]
	if len(cfg.Patterns) > 1 {
		target = fmt.Sprintf("%s (+%d more)", cfg.Patterns[0], len(cfg.Patterns)-1)
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "errsec: loading packages: %v\n", cfg.Patterns)
	}

	// ── Stage 1: Load & IR Builder ────────────────────────────────────────
	loadResult, err := loader.Load(cfg, cfg.Patterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "errsec: load: %v\n", err)
		return nil, exitError
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "errsec: loaded %d packages, %d functions\n",
			loadResult.Stats().PackagesLoaded, len(loadResult.Functions))
	}

	// Check context before heavy analysis.
	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "errsec: timeout during loading")
		return nil, exitTimeout
	default:
	}

	// ── Stage 3: Source Classifier (initialised before DFA) ───────────────
	summaryStore := dfa.NewSummaryStore()
	cls := classifier.New(cfg, summaryStore)

	// ── Stage 4: IPA + DFA Engine ─────────────────────────────────────────
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "errsec: starting inter-procedural analysis...\n")
	}

	ipaEngine := dfa.NewIPAEngine(cfg, cls, summaryStore, loadResult.Fset)
	issues, stats := ipaEngine.Analyse(loadResult.Prog, loadResult.Functions)
	stats.PackagesLoaded = loadResult.Stats().PackagesLoaded

	// Assign IDs and filter by minimum risk.
	filteredIssues := dfa.AssignIDs(issues, cfg.MinRisk)

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "errsec: analysis complete: %d issue(s) found\n", len(filteredIssues))
	}

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "errsec: timeout during analysis")
		return nil, exitTimeout
	default:
	}

	// ── Stage 5: Build result ─────────────────────────────────────────────
	result := report.NewResult(
		toolVersion,
		target,
		filteredIssues,
		stats,
		time.Since(start),
		cfg,
	)

	return result, exitOK
}
