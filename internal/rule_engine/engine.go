// Package rule_engine implements the OWASP Risk Rating Methodology for classifying
// the risk level of error sources in Go programs.
//
// Methodology reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
//
// Each rule in the risk_rules.json database assigns OWASP factor scores to an
// error-source category (DB, Auth, Network, Display, Logging).
//
// Computation:
//   Likelihood = average( SkillLevel, Motive, Opportunity, Size,
//                         EaseOfDiscovery, EaseOfExploit, Awareness, IntrusionDetection ) / 8
//   TechnicalImpact = average( LossOfConfidentiality, LossOfIntegrity,
//                              LossOfAvailability, LossOfAccountability ) / 4
//
// Scale (OWASP): 0-<3 = LOW, 3-<6 = MEDIUM, 6-9 = HIGH
//
// OWASP Severity Matrix:
//   Impact\Likelihood    LOW      MEDIUM   HIGH
//   HIGH              → MEDIUM   HIGH     CRITICAL
//   MEDIUM            → LOW      MEDIUM   HIGH
//   LOW               → NOTE     LOW      LOW
//
// ErrSec mapping: CRITICAL|HIGH → RiskHigh ; MEDIUM|LOW|NOTE → RiskLow
package rule_engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/errsec/errsec/internal/models"
)

// ─── JSON schema ─────────────────────────────────────────────────────────────

type rulesFile struct {
	Version     string  `json:"version"`
	Methodology string  `json:"methodology"`
	Rules       []rule  `json:"rules"`
}

type rule struct {
	ID          string      `json:"id"`
	Category    string      `json:"category"`
	Description string      `json:"description"`
	MatchType   string      `json:"match_type"`
	Patterns    []string    `json:"patterns"`
	Factors     owaspFile   `json:"owasp_factors"`
}

type owaspFile struct {
	ThreatAgent     threatAgentFactors     `json:"threat_agent"`
	Vulnerability   vulnerabilityFactors   `json:"vulnerability"`
	TechImpact      technicalImpactFactors `json:"technical_impact"`
}

type threatAgentFactors struct {
	SkillLevel  float64 `json:"skill_level"`
	Motive      float64 `json:"motive"`
	Opportunity float64 `json:"opportunity"`
	Size        float64 `json:"size"`
}

type vulnerabilityFactors struct {
	EaseOfDiscovery    float64 `json:"ease_of_discovery"`
	EaseOfExploit      float64 `json:"ease_of_exploit"`
	Awareness          float64 `json:"awareness"`
	IntrusionDetection float64 `json:"intrusion_detection"`
}

type technicalImpactFactors struct {
	LossOfConfidentiality float64 `json:"loss_of_confidentiality"`
	LossOfIntegrity       float64 `json:"loss_of_integrity"`
	LossOfAvailability    float64 `json:"loss_of_availability"`
	LossOfAccountability  float64 `json:"loss_of_accountability"`
}

// ─── Engine ──────────────────────────────────────────────────────────────────

// Engine classifies error sources using OWASP Risk Rating Methodology rules
// loaded from a JSON database file.
type Engine struct {
	rules []rule
}

// Load reads and parses the risk_rules.json file at path.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rule_engine: read %q: %w", path, err)
	}
	var rf rulesFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("rule_engine: parse %q: %w", path, err)
	}
	return &Engine{rules: rf.Rules}, nil
}

// Classify returns the OWASP-derived RiskLevel for the given package import path.
// If no rule matches, RiskLow is returned (unknown sources are treated conservatively
// as low-risk so the tool does not overwhelm the user).
func (e *Engine) Classify(pkgPath string) (models.RiskLevel, string) {
	for _, r := range e.rules {
		if matches(r, pkgPath) {
			severity := computeSeverity(r.Factors)
			return owaspToRisk(severity), r.Category
		}
	}
	return models.RiskLow, "Unknown"
}

// ─── OWASP computation ────────────────────────────────────────────────────────

// likelihood computes the OWASP Likelihood score (0–9) as the average of all
// eight threat-agent and vulnerability factors.
func likelihood(f owaspFile) float64 {
	ta := f.ThreatAgent
	vf := f.Vulnerability
	sum := ta.SkillLevel + ta.Motive + ta.Opportunity + ta.Size +
		vf.EaseOfDiscovery + vf.EaseOfExploit + vf.Awareness + vf.IntrusionDetection
	return sum / 8.0
}

// technicalImpact computes the OWASP Technical Impact score (0–9) as the average
// of the four technical impact factors.
func technicalImpact(f owaspFile) float64 {
	ti := f.TechImpact
	sum := ti.LossOfConfidentiality + ti.LossOfIntegrity +
		ti.LossOfAvailability + ti.LossOfAccountability
	return sum / 4.0
}

// scale maps a 0–9 score to the OWASP three-band label.
func scale(score float64) string {
	switch {
	case score < 3:
		return "LOW"
	case score < 6:
		return "MEDIUM"
	default:
		return "HIGH"
	}
}

// computeSeverity applies the OWASP severity matrix to produce one of:
// CRITICAL, HIGH, MEDIUM, LOW, NOTE.
func computeSeverity(f owaspFile) string {
	l := scale(likelihood(f))
	i := scale(technicalImpact(f))

	// OWASP Severity Matrix
	switch i {
	case "HIGH":
		switch l {
		case "HIGH":
			return "CRITICAL"
		case "MEDIUM":
			return "HIGH"
		default:
			return "MEDIUM"
		}
	case "MEDIUM":
		switch l {
		case "HIGH":
			return "HIGH"
		case "MEDIUM":
			return "MEDIUM"
		default:
			return "LOW"
		}
	default: // LOW impact
		switch l {
		case "HIGH", "MEDIUM":
			return "LOW"
		default:
			return "NOTE"
		}
	}
}

// owaspToRisk maps OWASP severity strings to ErrSec's binary RiskLevel.
// CRITICAL and HIGH map to RiskHigh; all others map to RiskLow.
func owaspToRisk(severity string) models.RiskLevel {
	if severity == "CRITICAL" || severity == "HIGH" {
		return models.RiskHigh
	}
	return models.RiskLow
}

// ─── Pattern matching ─────────────────────────────────────────────────────────

// matches returns true if pkgPath matches any of the rule's patterns.
func matches(r rule, pkgPath string) bool {
	for _, pat := range r.Patterns {
		switch r.MatchType {
		case "package_prefix":
			if pkgPath == pat || strings.HasPrefix(pkgPath, strings.TrimRight(pat, "/")+"/") {
				return true
			}
		case "exact":
			if pkgPath == pat {
				return true
			}
		default:
			// default: prefix match
			if strings.HasPrefix(pkgPath, pat) {
				return true
			}
		}
	}
	return false
}
