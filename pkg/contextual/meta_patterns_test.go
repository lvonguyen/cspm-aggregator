package contextual

import (
	"testing"

	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
)

// stubEPSSClient implements a minimal EPSS-like interface for testing.
// We use the real EPSSClient but with a pre-populated cache.

func TestExploitProbabilityDampener_AllConditionsMet(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	ctx := scoring.FindingContext{
		EPSSScore:       0.001, // below threshold
		InKEV:           false,
		ExploitAvailable: false,
		ExploitInWild:   false,
		EnvType:         "dev",
		InternetFacing:  false,
	}

	adj, err := d.Evaluate(ctx, "CVE-2023-99999", "HIGH")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !adj.Applied {
		t.Errorf("expected adjustment to be applied, got Applied=false; reason: %s", adj.Reason)
	}
	if adj.AdjustedSeverity != "LOW" {
		t.Errorf("expected HIGH downgraded 2 levels to LOW, got %s", adj.AdjustedSeverity)
	}
	if adj.Confidence < 0.84 || adj.Confidence > 0.86 {
		t.Errorf("expected confidence ~0.85, got %f", adj.Confidence)
	}
	if adj.Pattern != "MP-03" {
		t.Errorf("expected pattern MP-03, got %s", adj.Pattern)
	}
}

func TestExploitProbabilityDampener_TwoConditionsMet_NoAutoApply(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	// Only EPSS low + not in KEV — exploit available (condition 3 fails)
	ctx := scoring.FindingContext{
		EPSSScore:       0.001,
		InKEV:           false,
		ExploitAvailable: true, // condition 3 fails
		ExploitInWild:   false,
		EnvType:         "dev",
	}

	adj, err := d.Evaluate(ctx, "CVE-2023-99999", "HIGH")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if adj.Applied {
		t.Error("expected no auto-apply with confidence 0.6")
	}
	if adj.AdjustedSeverity != "HIGH" {
		t.Errorf("severity should be unchanged, got %s", adj.AdjustedSeverity)
	}
	if adj.Confidence != 0.6 {
		t.Errorf("expected confidence 0.6 for 2/3 conditions, got %f", adj.Confidence)
	}
}

func TestExploitProbabilityDampener_Guardrail_CriticalProdInternetFacing(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	ctx := scoring.FindingContext{
		EPSSScore:       0.001,
		InKEV:           false,
		ExploitAvailable: false,
		ExploitInWild:   false,
		EnvType:         "prod",         // prod
		AssetTier:       "Tier1-Prod",
		InternetFacing:  true,           // internet-facing
	}

	adj, err := d.Evaluate(ctx, "CVE-2023-99999", "CRITICAL")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if adj.Applied {
		t.Error("guardrail should prevent downgrading CRITICAL on Prod+internet-facing")
	}
	if adj.AdjustedSeverity != "CRITICAL" {
		t.Errorf("expected CRITICAL to be preserved, got %s", adj.AdjustedSeverity)
	}
}

func TestExploitProbabilityDampener_NoCVEID(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	ctx := scoring.FindingContext{
		EPSSScore: 0.001,
		InKEV:     false,
	}

	adj, err := d.Evaluate(ctx, "", "HIGH") // empty CVE
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if adj.Applied {
		t.Error("should not apply when no CVE ID")
	}
	if adj.AdjustedSeverity != "HIGH" {
		t.Errorf("severity should be unchanged without CVE ID, got %s", adj.AdjustedSeverity)
	}
}

func TestExploitProbabilityDampener_InKEV_PreventsDampening(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	// EPSS low + exploit unproven, but IN KEV (condition 2 fails)
	ctx := scoring.FindingContext{
		EPSSScore:       0.001,
		InKEV:           true, // in KEV — condition 2 fails
		ExploitAvailable: false,
		ExploitInWild:   false,
		EnvType:         "dev",
	}

	adj, err := d.Evaluate(ctx, "CVE-2021-44228", "HIGH")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Only 2 conditions met — confidence 0.6, no auto-apply
	if adj.Applied {
		t.Error("should not auto-apply when CVE is in KEV (only 2/3 conditions)")
	}
}

func TestExploitProbabilityDampener_HighEPSS_ZeroConditions(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	// High EPSS + in KEV + exploit available = 0 conditions met
	ctx := scoring.FindingContext{
		EPSSScore:       0.97,  // high EPSS — condition 1 fails
		InKEV:           true,  // in KEV — condition 2 fails
		ExploitAvailable: true, // exploit available — condition 3 fails
		ExploitInWild:   true,
		EnvType:         "prod",
		InternetFacing:  true,
	}

	adj, err := d.Evaluate(ctx, "CVE-2021-44228", "CRITICAL")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if adj.Applied {
		t.Error("should not apply with 0 conditions met")
	}
	if adj.Confidence != 0.0 {
		t.Errorf("expected confidence 0.0, got %f", adj.Confidence)
	}
	if adj.AdjustedSeverity != "CRITICAL" {
		t.Errorf("severity should be unchanged, got %s", adj.AdjustedSeverity)
	}
}

func TestExploitProbabilityDampener_SeverityDowngrade_FromCritical(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	// CRITICAL in non-prod, all conditions met → CRITICAL downgraded 2 levels to MEDIUM
	ctx := scoring.FindingContext{
		EPSSScore:       0.001,
		InKEV:           false,
		ExploitAvailable: false,
		ExploitInWild:   false,
		EnvType:         "dev",
		InternetFacing:  false,
	}

	adj, err := d.Evaluate(ctx, "CVE-2023-00001", "CRITICAL")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !adj.Applied {
		t.Errorf("expected adjustment, got Applied=false; reason: %s", adj.Reason)
	}
	if adj.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected CRITICAL downgraded 2 levels to MEDIUM, got %s", adj.AdjustedSeverity)
	}
}

func TestExploitProbabilityDampener_SeverityDowngrade_FromLow(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	// LOW downgraded 2 levels → clamped at INFORMATIONAL
	ctx := scoring.FindingContext{
		EPSSScore:       0.001,
		InKEV:           false,
		ExploitAvailable: false,
		ExploitInWild:   false,
		EnvType:         "dev",
	}

	adj, err := d.Evaluate(ctx, "CVE-2023-00002", "LOW")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if adj.AdjustedSeverity != "INFORMATIONAL" {
		t.Errorf("expected LOW clamped to INFORMATIONAL, got %s", adj.AdjustedSeverity)
	}
}

func TestDowngradeSeverity(t *testing.T) {
	tests := []struct {
		input  string
		levels int
		want   string
	}{
		{"CRITICAL", 1, "HIGH"},
		{"CRITICAL", 2, "MEDIUM"},
		{"CRITICAL", 3, "LOW"},
		{"CRITICAL", 4, "INFORMATIONAL"},
		{"CRITICAL", 5, "INFORMATIONAL"}, // clamped
		{"HIGH", 1, "MEDIUM"},
		{"HIGH", 2, "LOW"},
		{"MEDIUM", 1, "LOW"},
		{"LOW", 1, "INFORMATIONAL"},
		{"INFORMATIONAL", 1, "INFORMATIONAL"}, // already lowest
		{"invalid", 1, "invalid"},             // passthrough for unknown
	}

	for _, tc := range tests {
		got := downgradeSeverity(tc.input, tc.levels)
		if got != tc.want {
			t.Errorf("downgradeSeverity(%q, %d) = %q, want %q", tc.input, tc.levels, got, tc.want)
		}
	}
}

func TestExploitProbabilityDampener_Guardrail_CriticalProdNotInternetFacing(t *testing.T) {
	d := NewExploitProbabilityDampener(nil, nil)

	// CRITICAL + prod, but NOT internet-facing — guardrail should NOT trigger
	ctx := scoring.FindingContext{
		EPSSScore:       0.001,
		InKEV:           false,
		ExploitAvailable: false,
		ExploitInWild:   false,
		EnvType:         "prod",
		AssetTier:       "Tier1-Prod",
		InternetFacing:  false, // not internet-facing
	}

	adj, err := d.Evaluate(ctx, "CVE-2023-00003", "CRITICAL")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// All 3 conditions met, guardrail not triggered → should downgrade
	if !adj.Applied {
		t.Errorf("expected downgrade for Prod non-internet-facing, got Applied=false; reason: %s", adj.Reason)
	}
	if adj.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected CRITICAL downgraded to MEDIUM, got %s", adj.AdjustedSeverity)
	}
}
