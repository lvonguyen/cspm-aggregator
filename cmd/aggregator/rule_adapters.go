package main

// rule_adapters.go bridges pkg/contextual rule engines to the scoring.FPEvaluator
// and scoring.FNEvaluator interfaces. This file is the only place in the codebase
// that imports both scoring and contextual, intentionally breaking the import cycle
// by living in the application wiring layer (cmd/) rather than either library package.

import (
	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
	"github.com/lvonguyen/cspm-aggregator/pkg/contextual"
)

// fpRuleAdapter wraps contextual.FPRuleEngine to satisfy scoring.FPEvaluator.
type fpRuleAdapter struct {
	engine *contextual.FPRuleEngine
}

// Evaluate converts an FPRuleResult from the contextual engine into a
// scoring.DeterministicRuleResult, which the scoring package already owns.
func (a *fpRuleAdapter) Evaluate(f scoring.Finding) (*scoring.DeterministicRuleResult, bool) {
	result, matched := a.engine.Evaluate(f)
	if !matched {
		return nil, false
	}
	return &scoring.DeterministicRuleResult{
		OriginalSeverity:   result.OriginalSeverity,
		AdjustedSeverity:   result.AdjustedSeverity,
		Applied:            result.Applied,
		Confidence:         result.Confidence,
		Reason:             result.Reason,
		Pattern:            result.Pattern,
		SuggestedRiskScore: result.SuggestedRiskScore,
	}, true
}

// fnRuleAdapter wraps contextual.FNRuleEngine to satisfy scoring.FNEvaluator.
type fnRuleAdapter struct {
	engine *contextual.FNRuleEngine
}

// Evaluate converts an FNRuleResult from the contextual engine into a
// scoring.DeterministicRuleResult.
func (a *fnRuleAdapter) Evaluate(f scoring.Finding) (*scoring.DeterministicRuleResult, bool) {
	result, matched := a.engine.Evaluate(f)
	if !matched {
		return nil, false
	}
	return &scoring.DeterministicRuleResult{
		OriginalSeverity:   result.OriginalSeverity,
		AdjustedSeverity:   result.AdjustedSeverity,
		Applied:            result.Applied,
		Confidence:         result.Confidence,
		Reason:             result.Reason,
		Pattern:            result.Pattern,
		SuggestedRiskScore: result.SuggestedRiskScore,
	}, true
}

// newRuleBoundScorer constructs a RiskScorer with the deterministic FP/FN rule
// engines wired in. Pass nvd=nil to disable CVE status validation (MP-07).
func newRuleBoundScorer(
	llm scoring.LLMProvider,
	enricher scoring.ContextEnricher,
	fpStore scoring.FPHistoryStore,
	config scoring.RiskScorerConfig,
	nvd contextual.NVDStatusChecker,
) *scoring.RiskScorer {
	rs := scoring.NewRiskScorer(llm, enricher, fpStore, config)
	fp := &fpRuleAdapter{engine: contextual.NewFPRuleEngine(nvd)}
	fn := &fnRuleAdapter{engine: contextual.NewFNRuleEngine()}
	return rs.WithRuleEngines(fp, fn)
}
