// Package classifier wraps rule_engine to assign OWASP-derived risk levels to
// ErrorSite instances (FR-05).  The classifier is intentionally kept thin so
// that all risk-scoring logic lives in rule_engine and the rule database remains
// the single source of truth (NFR-08: extensible rule DB).
package classifier

import (
	"github.com/errsec/errsec/internal/models"
	"github.com/errsec/errsec/internal/rule_engine"
)

// Classifier assigns risk levels to error sources via the OWASP rule engine.
type Classifier struct {
	engine *rule_engine.Engine
}

// New creates a Classifier backed by the given rule_engine.Engine.
func New(engine *rule_engine.Engine) *Classifier {
	return &Classifier{engine: engine}
}

// ClassificationResult holds the risk level and matched category for a site.
type ClassificationResult struct {
	Risk     models.RiskLevel
	Category string // e.g. "DB", "Auth", "Network", "Display", "Logging", "Unknown"
}

// Classify returns the OWASP-derived risk for the given ErrorSite.
// Classification is based on the import path of the package whose call produced
// the error value (site.SourcePkg).
func (c *Classifier) Classify(site *models.ErrorSite) ClassificationResult {
	risk, category := c.engine.Classify(site.SourcePkg)
	return ClassificationResult{Risk: risk, Category: category}
}
