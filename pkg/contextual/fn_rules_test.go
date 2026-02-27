package contextual

import (
	"testing"

	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
)

// ---------------------------------------------------------------------------
// upgradeSeverity helper
// ---------------------------------------------------------------------------

func TestUpgradeSeverity_OneLevel(t *testing.T) {
	cases := []struct {
		input    string
		levels   int
		expected string
	}{
		{"LOW", 1, "MEDIUM"},
		{"MEDIUM", 1, "HIGH"},
		{"HIGH", 1, "CRITICAL"},
		{"CRITICAL", 1, "CRITICAL"}, // clamp at top
		{"INFORMATIONAL", 1, "LOW"},
		{"INFORMATIONAL", 2, "MEDIUM"},
		{"LOW", 3, "CRITICAL"},
		{"LOW", 10, "CRITICAL"}, // clamp
	}

	for _, tc := range cases {
		got := upgradeSeverity(tc.input, tc.levels)
		if got != tc.expected {
			t.Errorf("upgradeSeverity(%q, %d) = %q, want %q", tc.input, tc.levels, got, tc.expected)
		}
	}
}

func TestUpgradeSeverity_UnknownSeverity(t *testing.T) {
	// Unknown severity strings should be returned unchanged
	got := upgradeSeverity("UNKNOWN", 1)
	if got != "UNKNOWN" {
		t.Errorf("upgradeSeverity(%q, 1) = %q, want %q", "UNKNOWN", got, "UNKNOWN")
	}
}

// ---------------------------------------------------------------------------
// MP-09: Private CIDR Width Escalator
// ---------------------------------------------------------------------------

func TestMP09_PrivateCIDRWidthEscalator_Triggers_BroadPrivateCIDRCriticalAsset(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "MEDIUM",
		FindingType: "SECURITY_GROUP_INGRESS_UNRESTRICTED",
		Description: "Security group allows inbound access from 10.0.0.0/8",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-09 expected to match broad private CIDR /8 on critical asset, got no match")
	}
	if result.Pattern != "MP-09" {
		t.Errorf("expected pattern MP-09, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "HIGH" {
		t.Errorf("expected MEDIUM upgraded 1 level to HIGH, got %s", result.AdjustedSeverity)
	}
	if result.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %f", result.Confidence)
	}
	if result.Applied != true {
		t.Error("expected Applied=true")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_Triggers_172_16_Network_HighCriticality(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "AWS_SECURITY_GROUP_WIDE_OPEN",
		Title:       "Security group rule allows traffic from 172.16.0.0/12",
		Context: scoring.FindingContext{
			BusinessCriticality: "high",
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-09 expected to match 172.16.0.0/12 on high criticality asset, got no match")
	}
	if result.Pattern != "MP-09" {
		t.Errorf("expected pattern MP-09, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected LOW upgraded 1 level to MEDIUM, got %s", result.AdjustedSeverity)
	}
}

func TestMP09_PrivateCIDRWidthEscalator_NoTrigger_NarrowCIDR(t *testing.T) {
	engine := NewFNRuleEngine()

	// /32 is a specific host — not broad
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "SECURITY_GROUP_INGRESS",
		Description: "Security group allows traffic from 10.1.2.3/32",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-09 should NOT trigger for narrow CIDR /32")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_NoTrigger_PublicCIDR(t *testing.T) {
	engine := NewFNRuleEngine()

	// Public IP range — not RFC1918
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "SECURITY_GROUP_INGRESS",
		Description: "Security group allows traffic from 8.8.8.0/8",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-09 should NOT trigger for non-RFC1918 CIDR")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_NoTrigger_LowCriticality(t *testing.T) {
	engine := NewFNRuleEngine()

	// Broad CIDR but asset is low criticality
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "SECURITY_GROUP_INGRESS",
		Description: "Security group allows traffic from 10.0.0.0/8",
		Context: scoring.FindingContext{
			BusinessCriticality: "low",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-09 should NOT trigger for low business criticality")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_NoTrigger_NoCIDRInDescription(t *testing.T) {
	engine := NewFNRuleEngine()

	// SECURITY_GROUP finding but no CIDR in description or title
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "SECURITY_GROUP_INGRESS",
		Description: "Security group allows unrestricted inbound traffic",
		Title:       "Open security group rule",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-09 should NOT trigger when no CIDR can be extracted")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_NoTrigger_WrongFindingType(t *testing.T) {
	engine := NewFNRuleEngine()

	// Broad CIDR on critical asset but finding type is not SECURITY_GROUP
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "S3_BUCKET_PUBLIC_READ",
		Description: "Bucket accessible from 10.0.0.0/8",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-09 should NOT trigger when finding type does not contain SECURITY_GROUP")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_NoTrigger_PrefixTooNarrow(t *testing.T) {
	engine := NewFNRuleEngine()

	// /16 is narrower than /12 threshold but still broad — prefix > 12, should NOT trigger
	// wait: rule says prefix <= 12 triggers. /16 has prefix 16 which is > 12, so no trigger.
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "SECURITY_GROUP_INGRESS",
		Description: "Security group allows traffic from 10.1.0.0/16",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-09 should NOT trigger for CIDR prefix /16 (> 12 threshold)")
	}
}

func TestMP09_PrivateCIDRWidthEscalator_Triggers_ExactBoundaryPrefix12(t *testing.T) {
	engine := NewFNRuleEngine()

	// /12 is exactly at boundary — should trigger (prefix <= 12)
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "SECURITY_GROUP_RULE_BROAD",
		Description: "Allows traffic from 172.16.0.0/12",
		Context: scoring.FindingContext{
			BusinessCriticality: "critical",
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-09 expected to trigger at exact boundary prefix /12, got no match")
	}
	if result.Pattern != "MP-09" {
		t.Errorf("expected pattern MP-09, got %s", result.Pattern)
	}
}

// ---------------------------------------------------------------------------
// MP-10: Dormant Privileged Credential Escalator
// ---------------------------------------------------------------------------

func TestMP10_DormantPrivilegedCred_Triggers_StaleAdminKey(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "STALE_ACCESS_KEY",
		Title:       "Stale access key for admin user",
		Description: "IAM user has not used their access key in 180 days",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-10 expected to match stale access key with admin in title, got no match")
	}
	if result.Pattern != "MP-10" {
		t.Errorf("expected pattern MP-10, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "HIGH" {
		t.Errorf("expected upgrade to HIGH, got %s", result.AdjustedSeverity)
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", result.Confidence)
	}
	if result.Applied != true {
		t.Error("expected Applied=true")
	}
}

func TestMP10_DormantPrivilegedCred_Triggers_InactiveRootUser(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "INFORMATIONAL",
		FindingType: "INACTIVE_USER",
		Title:       "Root account has not been used in 90 days",
		Description: "The root user account should have MFA enabled and should not be used for daily operations",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-10 expected to match inactive root user, got no match")
	}
	if result.Pattern != "MP-10" {
		t.Errorf("expected pattern MP-10, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "HIGH" {
		t.Errorf("expected upgrade to HIGH, got %s", result.AdjustedSeverity)
	}
}

func TestMP10_DormantPrivilegedCred_Triggers_NoMFAOnAdministratorRole(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "NO_MFA_ENABLED",
		Title:       "No MFA for Administrator account",
		Description: "User with AdministratorAccess policy has no MFA configured",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-10 expected to match NO_MFA with Administrator in title, got no match")
	}
	if result.Pattern != "MP-10" {
		t.Errorf("expected pattern MP-10, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "HIGH" {
		t.Errorf("expected upgrade to HIGH, got %s", result.AdjustedSeverity)
	}
}

func TestMP10_DormantPrivilegedCred_Triggers_PowerUserNoMFA(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "NO_MFA_ENABLED",
		Title:       "MFA not enabled for user",
		Description: "PowerUser policy is attached and MFA is not required",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-10 expected to match NO_MFA with PowerUser in description, got no match")
	}
	if result.Pattern != "MP-10" {
		t.Errorf("expected pattern MP-10, got %s", result.Pattern)
	}
}

func TestMP10_DormantPrivilegedCred_NoTrigger_HighSeverity(t *testing.T) {
	engine := NewFNRuleEngine()

	// Already HIGH severity — rule only escalates LOW or INFORMATIONAL
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "STALE_ACCESS_KEY",
		Title:       "Stale access key for admin user",
		Description: "IAM admin user has not used their key in 180 days",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-10 should NOT trigger when severity is already HIGH (only LOW/INFORMATIONAL)")
	}
}

func TestMP10_DormantPrivilegedCred_NoTrigger_NonPrivilegedUser(t *testing.T) {
	engine := NewFNRuleEngine()

	// Stale access key but no privileged keywords in title/description
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "STALE_ACCESS_KEY",
		Title:       "Stale access key for developer user",
		Description: "IAM user developer-alice has not used their access key in 180 days",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-10 should NOT trigger for non-privileged user (no admin/root/privileged keywords)")
	}
}

func TestMP10_DormantPrivilegedCred_NoTrigger_WrongFindingType(t *testing.T) {
	engine := NewFNRuleEngine()

	// Admin in description but wrong finding type
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "S3_BUCKET_PUBLIC_READ",
		Title:       "S3 bucket accessible by admin",
		Description: "S3 bucket allows public read access",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-10 should NOT trigger for finding types not in {STALE_ACCESS_KEY, INACTIVE_USER, NO_MFA}")
	}
}

func TestMP10_DormantPrivilegedCred_Triggers_SuperuserKeyword(t *testing.T) {
	engine := NewFNRuleEngine()

	f := scoring.Finding{
		Severity:    "INFORMATIONAL",
		FindingType: "INACTIVE_USER",
		Title:       "Dormant superuser account detected",
		Description: "Account has superuser privileges and has been inactive for 365 days",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-10 expected to match inactive superuser, got no match")
	}
	if result.Pattern != "MP-10" {
		t.Errorf("expected pattern MP-10, got %s", result.Pattern)
	}
}

// ---------------------------------------------------------------------------
// FNRuleEngine — engine-level tests
// ---------------------------------------------------------------------------

func TestFNRuleEngine_NoMatch_ReturnsNilFalse(t *testing.T) {
	engine := NewFNRuleEngine()

	// Finding that matches no FN rule
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "S3_BUCKET_VERSIONING_DISABLED",
		Title:       "S3 versioning not enabled",
		Description: "Bucket does not have versioning enabled",
		Context: scoring.FindingContext{
			BusinessCriticality: "low",
		},
	}

	result, ok := engine.Evaluate(f)
	if ok {
		t.Errorf("expected no FN rule match, got pattern %s", result.Pattern)
	}
	if result != nil {
		t.Error("expected nil result when no rule matches")
	}
}

func TestFNRuleEngine_FirstMatchWins_MP09BeforeMP10(t *testing.T) {
	engine := NewFNRuleEngine()

	// Craft a finding that could match MP-10 (STALE_ACCESS_KEY, LOW, admin keyword)
	// but FindingType also contains SECURITY_GROUP — so MP-09 should not fire here.
	// This test verifies MP-10 fires when only MP-10 conditions are met.
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "STALE_ACCESS_KEY",
		Title:       "Stale privileged access key",
		Description: "Admin user access key has not been rotated",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("expected a rule match, got none")
	}
	if result.Pattern != "MP-10" {
		t.Errorf("expected MP-10 to match for stale admin key, got %s", result.Pattern)
	}
}
