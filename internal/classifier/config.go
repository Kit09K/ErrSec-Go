package classifier

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/errsec/errsec/pkg/config"
	errtypes "github.com/errsec/errsec/pkg/types"
)

type yamlConfig struct {
	Rules    []yamlRule   `yaml:"rules"`
	Settings yamlSettings `yaml:"settings"`
}

type yamlRule struct {
	Pkg    string `yaml:"pkg"`
	Func   string `yaml:"func"`
	Risk   string `yaml:"risk"`
	Reason string `yaml:"reason"`
}

type yamlSettings struct {
	BranchCap int    `yaml:"branch_cap"`
	MinRisk   string `yaml:"min_risk"`
}

// LoadYAMLConfig reads an errsec.yaml file and merges it into cfg.
func LoadYAMLConfig(path string, cfg *config.Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("errsec.yaml: %w", err)
	}

	var yc yamlConfig
	if err := yaml.Unmarshal(data, &yc); err != nil {
		return fmt.Errorf("errsec.yaml parse: %w", err)
	}

	for _, r := range yc.Rules {
		cfg.ExtraRules = append(cfg.ExtraRules, config.Rule{
			Pkg:     r.Pkg,
			Func:    r.Func,
			RiskStr: r.Risk,
			Reason:  r.Reason,
		})
	}

	if yc.Settings.BranchCap > 0 {
		cfg.BranchCap = yc.Settings.BranchCap
	}
	if yc.Settings.MinRisk != "" {
		risk, err := errtypes.ParseRiskLevel(yc.Settings.MinRisk)
		if err != nil {
			return fmt.Errorf("errsec.yaml settings.min_risk: %w", err)
		}
		cfg.MinRisk = risk
	}
	return nil
}
