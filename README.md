# ErrSec

**Path-Sensitive Static Analysis for Detecting Fail-Open Vulnerabilities in Go Error Handling**

Computer Science · College of Computing · Khon Kaen University · 2026  
663380007-9 Kittayot Muttakit | 663380247-9 Asek Panyawong  
Advisor: Asst. Prof. Chitsutha Soomlek, Ph.D.

---

## Overview

ErrSec is a static analysis tool that detects *fail-open* vulnerabilities caused by incorrect error handling in Go programs.  It performs **path-sensitive, inter-procedural forward data-flow analysis (DFA)** on Go SSA (Static Single Assignment) form and classifies risk levels using the **OWASP Risk Rating Methodology**.

### What is a Fail-Open Vulnerability?

A fail-open vulnerability occurs when an error is silently ignored and program execution continues as if no error occurred.  In security-critical code (authentication, database, network), this can allow an attacker to bypass checks entirely.

---

## Architecture — 3-Stage Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1: Target Identification                                  │
│  ─────────────────────────────                                   │
│  CLI path  →  Loader (go/packages)  →  SSA Builder              │
│           →  Pattern Matcher  →  []ErrorSite                     │
├─────────────────────────────────────────────────────────────────┤
│  Stage 2: Core Analysis Engine  (per ErrorSite)                  │
│  ──────────────────────────────────────────────                  │
│  Smart CFG (defer-aware)  +  OWASP Classifier  +  Forward DFA   │
│  Mutation Tracker  +  Complexity Cap (N=1000)                    │
│  Function Summary Store  →  []FlowFact                           │
├─────────────────────────────────────────────────────────────────┤
│  Stage 3: Reporting                                              │
│  ──────────────────                                              │
│  []FlowFact  →  Text DFG Report  →  stdout                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Risk Classification — OWASP Risk Rating Methodology

Risk is computed per error-source category using the formula:

```
Risk = Likelihood × Impact

Likelihood = avg(SkillLevel, Motive, Opportunity, Size,
                 EaseOfDiscovery, EaseOfExploit, Awareness, IntrusionDetection)

TechnicalImpact = avg(LossOfConfidentiality, LossOfIntegrity,
                      LossOfAvailability, LossOfAccountability)
```

Scale: `0 – <3 = LOW` | `3 – <6 = MEDIUM` | `6 – 9 = HIGH`

OWASP Severity Matrix:

| Impact \ Likelihood | LOW    | MEDIUM | HIGH     |
|---------------------|--------|--------|----------|
| **HIGH**            | MEDIUM | HIGH   | CRITICAL |
| **MEDIUM**          | LOW    | MEDIUM | HIGH     |
| **LOW**             | NOTE   | LOW    | LOW      |

ErrSec mapping: `CRITICAL / HIGH → RiskHigh` | `MEDIUM / LOW / NOTE → RiskLow`

Pre-configured categories (extensible via `rules/risk_rules.json`, NFR-08):

| Category | Risk  | Example packages                            |
|----------|-------|---------------------------------------------|
| DB       | HIGH  | `database/sql`, `gorm.io/gorm`, `pgx`      |
| Auth     | HIGH  | `crypto/`, `golang.org/x/crypto`, JWT libs  |
| Network  | HIGH  | `net/http`, `net/`, `google.golang.org/grpc`|
| Display  | LOW   | `fmt`, `html/template`, `text/template`     |
| Logging  | LOW   | `log`, `log/slog`, `go.uber.org/zap`        |

---

## Installation

```bash
git clone https://github.com/errsec/errsec
cd errsec
go get golang.org/x/tools@latest  
go mod tidy
go build ./cmd/errsec
```

Requires **Go 1.21+** (NFR-04).  No external database or internet connection needed (NFR-03).

---

## Usage

```bash
# Analyse a single file
errsec ./main.go

# Analyse a package directory
errsec ./pkg/auth

# Analyse all packages recursively
errsec ./...

# Use a custom risk rules file
errsec ./myapp --rules /path/to/custom_rules.json
```

### Example output

```
ErrSec — Data-Flow Graph Report
Sites found: 3  (unanalyzable: 0)

══════════════════════════════════════════════════════════════════
[1] RISK: HIGH │ pattern: blank identifier
  Origin  : database/sql
  Location: auth/handler.go:47:12
  Function: (*auth.Handler).Login
──────────────────────────────────────────────────────────────────
  Flow path:
    [B2] t3 = db.QueryRow(...)          propagated    handler.go:47
    ...
══════════════════════════════════════════════════════════════════
```

---

## Extending the Rule Database

Edit `rules/risk_rules.json` to add new categories or packages without modifying any analysis code (NFR-08).  Each rule defines OWASP factor scores; the engine recomputes likelihood, impact, and severity automatically.

---

## Limitations

- Sequential flow only — goroutines and channels are not modelled (NFR-05).
- Static analysis only — runtime-input-dependent errors cannot be detected (NFR-06).
- Functions with more than **1000 jump conditions** are reported as *unanalyzable* to prevent path explosion (FR-08).
- Go 1.21+ source code only (NFR-04).

---

## Library API (FR-11)

```go
import "github.com/errsec/errsec/analyzer"

result, err := analyzer.Run("./pkg/auth", analyzer.Options{
    RulesPath: "rules/risk_rules.json",
    Output:    os.Stdout,
})
// result.Facts contains []* models.FlowFact
```
