package contextual

import (
	"fmt"
	"strings"

	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
	"github.com/lvonguyen/cspm-aggregator/pkg/threatintel"
)

// severityLevels is the ordered list of severity strings from most to least severe.
// Index 0 = CRITICAL, index 4 = INFORMATIONAL.
var severityLevels = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

// severityIndex returns the position of a severity string in severityLevels,
// or -1 if not found. Lower index = higher severity.
func severityIndex(s string) int {
	upper := strings.ToUpper(s)
	for i, level := range severityLevels {
		if level == upper {
			return i
		}
	}
	return -1
}

// downgradeSeverity lowers the severity by n levels, clamped at INFORMATIONAL.
func downgradeSeverity(sev string, levels int) string {
	idx := severityIndex(sev)
	if idx < 0 {
		return sev
	}
	newIdx := idx + levels
	if newIdx >= len(severityLevels) {
		newIdx = len(severityLevels) - 1
	}
	return severityLevels[newIdx]
}

// SeverityAdjustment records the result of a meta-pattern evaluation.
type SeverityAdjustment struct {
	OriginalSeverity string  // Original severity level
	AdjustedSeverity string  // Resulting severity after adjustment (may equal original)
	Reason           string  // Human-readable explanation
	Confidence       float64 // 0.0-1.0 confidence in the adjustment
	Pattern          string  // Meta-pattern identifier
	Applied          bool    // Whether the adjustment was actually applied
}

// ExploitProbabilityDampener implements meta-pattern MP-03.
// When exploitation probability is very low (low EPSS, not in KEV, no known exploit),
// it can downgrade severity by 2 levels — subject to guardrails.
type ExploitProbabilityDampener struct {
	epss *threatintel.EPSSClient
	kev  *threatintel.KEVCatalog

	// EPSSThreshold is the maximum EPSS score that qualifies for dampening (default 0.005).
	EPSSThreshold float64

	// AutoApplyMinConfidence is the minimum confidence required to auto-apply the adjustment (default 0.7).
	AutoApplyMinConfidence float64

	// DowngradeLevels is how many severity levels to drop when all conditions are met (default 2).
	DowngradeLevels int
}

// NewExploitProbabilityDampener creates an MP-03 dampener with default thresholds.
func NewExploitProbabilityDampener(epss *threatintel.EPSSClient, kev *threatintel.KEVCatalog) *ExploitProbabilityDampener {
	return &ExploitProbabilityDampener{
		epss:                   epss,
		kev:                    kev,
		EPSSThreshold:          0.005,
		AutoApplyMinConfidence: 0.7,
		DowngradeLevels:        2,
	}
}

// Evaluate runs MP-03 logic against a finding context.
//
// Condition set (all required for full confidence of 0.85):
//   - EPSS score < EPSSThreshold (default 0.005)
//   - CVE is NOT in CISA KEV catalog
//   - Exploit maturity is "unproven" or unknown (empty string)
//
// Guardrail: never downgrade CRITICAL for Prod + internet-facing findings.
//
// Confidence:
//   - 0.85 — all 3 conditions met
//   - 0.6  — exactly 2 conditions met (adjustment NOT auto-applied)
//   - 0.0  — fewer than 2 conditions met
func (d *ExploitProbabilityDampener) Evaluate(finding scoring.FindingContext, cveID, originalSeverity string) (SeverityAdjustment, error) {
	adj := SeverityAdjustment{
		OriginalSeverity: originalSeverity,
		AdjustedSeverity: originalSeverity,
		Pattern:          "MP-03",
	}

	if cveID == "" {
		adj.Reason = "no CVE ID — MP-03 not applicable"
		return adj, nil
	}

	// --- Evaluate the three conditions ---

	// Condition 1: EPSS score below threshold
	var epssScore float64
	var epssConditionMet bool
	if d.epss != nil {
		score, err := d.epss.GetScore(cveID)
		if err != nil {
			return adj, fmt.Errorf("MP-03 EPSS lookup for %s: %w", cveID, err)
		}
		epssScore = score
		epssConditionMet = score < d.EPSSThreshold
	} else if finding.EPSSScore > 0 {
		// Fall back to pre-populated context field
		epssScore = finding.EPSSScore
		epssConditionMet = finding.EPSSScore < d.EPSSThreshold
	} else {
		// No EPSS data available — treat condition as met (conservative dampening)
		epssConditionMet = true
	}

	// Condition 2: NOT in CISA KEV
	var inKEV bool
	if d.kev != nil {
		inKEV = d.kev.IsKnownExploited(cveID)
	} else {
		inKEV = finding.InKEV
	}
	kevConditionMet := !inKEV

	// Condition 3: Exploit maturity unproven or unknown
	// Finding.ExploitAvailable and ExploitInWild map to "proven" exploit maturity.
	exploitMaturityUnproven := !finding.ExploitAvailable && !finding.ExploitInWild
	maturityConditionMet := exploitMaturityUnproven

	// --- Score conditions ---
	conditionsMet := 0
	if epssConditionMet {
		conditionsMet++
	}
	if kevConditionMet {
		conditionsMet++
	}
	if maturityConditionMet {
		conditionsMet++
	}

	switch conditionsMet {
	case 3:
		adj.Confidence = 0.85
	case 2:
		adj.Confidence = 0.6
	default:
		adj.Confidence = 0.0
		adj.Reason = buildReason(epssScore, inKEV, exploitMaturityUnproven, conditionsMet)
		return adj, nil
	}

	// --- Guardrail: never downgrade CRITICAL on Prod + internet-facing ---
	if strings.ToUpper(originalSeverity) == "CRITICAL" {
		tier := ClassifyEnvironment("", nil, "")
		isProd := finding.EnvType == "prod" || finding.AssetTier == "Tier1-Prod"
		_ = tier
		if isProd && finding.InternetFacing {
			adj.Reason = fmt.Sprintf(
				"MP-03: %d/3 conditions met (confidence %.2f) but guardrail prevents downgrading CRITICAL on Prod+internet-facing",
				conditionsMet, adj.Confidence,
			)
			return adj, nil
		}
	}

	// --- Apply adjustment only if confidence meets threshold ---
	if adj.Confidence < d.AutoApplyMinConfidence {
		adj.Reason = fmt.Sprintf(
			"MP-03: %d/3 conditions met (confidence %.2f < %.2f threshold) — no auto-adjustment",
			conditionsMet, adj.Confidence, d.AutoApplyMinConfidence,
		)
		return adj, nil
	}

	// Apply the downgrade
	newSev := downgradeSeverity(originalSeverity, d.DowngradeLevels)
	adj.AdjustedSeverity = newSev
	adj.Applied = newSev != originalSeverity
	adj.Reason = buildReason(epssScore, inKEV, exploitMaturityUnproven, conditionsMet)

	return adj, nil
}

// buildReason constructs a human-readable rationale string.
func buildReason(epssScore float64, inKEV, exploitUnproven bool, conditionsMet int) string {
	parts := []string{fmt.Sprintf("MP-03: %d/3 dampening conditions met", conditionsMet)}
	parts = append(parts, fmt.Sprintf("EPSS=%.5f", epssScore))
	if inKEV {
		parts = append(parts, "in CISA KEV")
	} else {
		parts = append(parts, "not in KEV")
	}
	if exploitUnproven {
		parts = append(parts, "exploit maturity=unproven")
	} else {
		parts = append(parts, "exploit maturity=proven")
	}
	return strings.Join(parts, "; ")
}
