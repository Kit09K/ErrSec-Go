# ErrSec

**Path-Sensitive Static Analysis for Detecting Fail-Open Vulnerabilities in Go Error Handling**

[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ErrSec is a command-line static analysis tool that detects fail-open vulnerabilities
in Go programs — situations where a program encounters an error but continues
execution in an unsafe state.

## Installation

```bash
go install github.com/errsec/errsec/cmd/errsec@latest
```

Or build from source:

```bash
git clone https://github.com/errsec/errsec
cd errsec
make build
```

## Usage

```
errsec [flags] <pattern>

Flags:
  -format  string   Output format: text|json  (default: text)
  -risk    string   Minimum risk level: LOW|MEDIUM|HIGH  (default: LOW)
  -cap     int      Branch complexity cap per function  (default: 1000)
  -config  string   Path to errsec.yaml config file
  -workers int      Parallel workers  (default: NumCPU)
  -timeout string   Analysis timeout  (default: 5m)
  -v               Verbose output
  -version         Print version

Exit codes:
  0  No issues at or above threshold
  1  Issues found
  2  Analysis error
  3  Timeout
```

## Examples

```bash
# Analyse entire module
errsec ./...

# Report HIGH-risk issues only
errsec -risk HIGH ./...

# JSON output for CI/CD
errsec -format json ./... | jq '.issues | length'

# Analyse a single package
errsec ./internal/repository/...
```

## Detected Patterns

| Pattern | Description | Risk Level |
|---------|-------------|------------|
| `BLANK_IGNORE` | Error discarded with `_` | Source-dependent |
| `LOG_CONTINUE` | Error logged but execution falls through | Source-dependent |
| `DEFER_IGNORE` | Error discarded inside a deferred function | Source-dependent |

## Configuration (errsec.yaml)

```yaml
rules:
  - pkg: "github.com/myorg/mydb"
    func: ""
    risk: HIGH
    reason: "Internal database wrapper"

settings:
  branch_cap: 2000
  min_risk: MEDIUM
```

## Architecture

ErrSec runs a five-stage analysis pipeline:

```
Go Source → [Stage 1: Loader & SSA] → [Stage 2: Smart CFG] →
[Stage 3: Classifier] → [Stage 4: DFA + IPA] → [Stage 5: Report]
```

### Package Structure

```
errsec/
  cmd/errsec/          # CLI entry point (Layer 6)
  internal/
    loader/            # Stage 1: SSA construction (Layer 1)
    smartcfg/          # Stage 2: Smart CFG with defer/panic (Layer 2)
    classifier/        # Stage 3: Rule-based risk classification (Layer 3)
    dfa/               # Stage 4: Forward taint DFA + IPA (Layer 4)
    report/            # Stage 5: Text/JSON report generation (Layer 5)
  pkg/
    types/             # Shared types (Layer 0)
    config/            # Configuration struct (Layer 0)
```

## Running Tests

```bash
# Unit tests (no Go toolchain invocation needed)
go test ./pkg/... ./internal/...

# Integration tests (requires Go toolchain + buildable target)
go test -tags integration ./...

# With coverage
make test-cover
```

## Limitations (v0.1)

- Sequential analysis only — goroutine/channel taint not tracked
- Static analysis cannot detect runtime-input-dependent errors
- Complexity cap (default 1000) may leave very large functions unanalysed
- Indirect calls via interface variables conservatively unclassified
- Reflect-based error construction not tracked

## References

- Aho et al. (2014). *Compilers: Principles, Techniques, and Tools*
- Cousot & Cousot (1977). *Abstract Interpretation*
- OWASP: Improper Error Handling
- golang.org/x/tools/go/ssa documentation
