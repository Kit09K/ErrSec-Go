// Package config defines the top-level configuration struct for ErrSec.
// Layer 0 — imports only stdlib and pkg/types.
package config

import (
	"time"

	errtypes "github.com/errsec/errsec/pkg/types"
)

// RiskLevel is re-exported from pkg/types for convenience.
type RiskLevel = errtypes.RiskLevel

// Config holds all runtime configuration for an ErrSec analysis run.
type Config struct {
	Patterns        []string
	WorkDir         string
	Format          string
	MinRisk         errtypes.RiskLevel
	BranchCap       int
	NumWorkers      int
	Timeout         time.Duration
	ConfigFile      string
	Verbose         bool
	IncludeVendor   bool
	ExcludePatterns []string
	ExtraRules      []Rule
}

// Rule is an external classifier rule loaded from errsec.yaml.
type Rule struct {
	Pkg     string
	Func    string
	Risk    errtypes.RiskLevel
	RiskStr string
	Reason  string
}

// Default returns a Config with safe defaults.
func Default() *Config {
	return &Config{
		Format:     "text",
		MinRisk:    errtypes.LOW,
		BranchCap:  1000,
		NumWorkers: 4,
		Timeout:    5 * time.Minute,
	}
}
