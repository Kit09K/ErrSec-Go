// Command errsec is the CLI entry point for the ErrSec static analysis tool.
//
// Usage:
//
//	errsec <path> [--rules <rules.json>]
//
// path may be:
//   - A directory containing a Go package  (e.g.  ./cmd/server)
//   - A single .go source file             (e.g.  ./main.go)
//   - A Go import path                     (e.g.  github.com/foo/bar)
//
// Flags:
//
//	--rules   path to a custom risk_rules.json (default: bundled rules)
//	--help    print this usage message
package main

import (
	"fmt"
	"os"

	"github.com/errsec/errsec/analyzer"
)

const usage = `ErrSec — Path-Sensitive Static Analysis for Fail-Open Vulnerabilities in Go

Usage:
  errsec <path> [--rules <rules.json>]

Arguments:
  <path>          Go file (.go), package directory, or import path to analyse.

Flags:
  --rules <file>  Custom risk_rules.json path (default: bundled rules).
  --help          Show this message.

Examples:
  errsec ./main.go
  errsec ./pkg/auth/...
  errsec github.com/myorg/myapp/cmd/server
`

func main() {
	args := os.Args[1:]

	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(usage)
		os.Exit(0)
	}

	path := args[0]
	rulesPath := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--rules":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "errsec: --rules requires an argument")
				os.Exit(1)
			}
			rulesPath = args[i+1]
			i++
		default:
			fmt.Fprintf(os.Stderr, "errsec: unknown flag %q\n", args[i])
			os.Exit(1)
		}
	}

	opts := analyzer.Options{
		RulesPath: rulesPath,
		Output:    os.Stdout,
	}

	if _, err := analyzer.Run(path, opts); err != nil {
		fmt.Fprintf(os.Stderr, "errsec: %v\n", err)
		os.Exit(1)
	}
}
