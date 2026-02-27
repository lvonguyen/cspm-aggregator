package contextual

import (
	"strings"
	"testing"

	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
)

// ---------------------------------------------------------------------------
// MP-04: Environment Tier Dampener
// ---------------------------------------------------------------------------

func TestMP04_EnvTierDampener_Triggers_SandboxHighNoPII(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "S3_BUCKET_PUBLIC_READ",
		Context: scoring.FindingContext{
			EnvType:            "sandbox",
			DataClassification: "Internal",
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-04 expected to match sandbox+HIGH+no-PII finding, got no match")
	}
	if result.Pattern != "MP-04" {
		t.Errorf("expected pattern MP-04, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "LOW" {
		t.Errorf("expected HIGH downgraded 2 levels to LOW, got %s", result.AdjustedSeverity)
	}
	if result.Confidence != 0.90 {
		t.Errorf("expected confidence 0.90, got %f", result.Confidence)
	}
	if result.Applied != true {
		t.Error("expected Applied=true")
	}
}

func TestMP04_EnvTierDampener_Triggers_DevCriticalNoPHI(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "CRITICAL",
		FindingType: "IAM_ADMIN_POLICY",
		Context: scoring.FindingContext{
			EnvType:            "dev-simulation",
			DataClassification: "Public",
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-04 expected to match dev-simulation+CRITICAL+no-PHI, got no match")
	}
	if result.Pattern != "MP-04" {
		t.Errorf("expected pattern MP-04, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected CRITICAL downgraded 2 levels to MEDIUM, got %s", result.AdjustedSeverity)
	}
}

func TestMP04_EnvTierDampener_NoTrigger_ProductionEnv(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "S3_BUCKET_PUBLIC_READ",
		Context: scoring.FindingContext{
			EnvType:            "prod",
			DataClassification: "Internal",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-04 should NOT trigger on prod environment")
	}
}

func TestMP04_EnvTierDampener_NoTrigger_PCIData(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// sandbox env but PCI data — must NOT trigger
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "S3_BUCKET_PUBLIC_READ",
		Context: scoring.FindingContext{
			EnvType:            "sandbox",
			DataClassification: "PCI",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-04 should NOT trigger when data is classified PCI")
	}
}

func TestMP04_EnvTierDampener_NoTrigger_LowSeverity(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// sandbox but LOW severity — rule only targets HIGH/CRITICAL
	f := scoring.Finding{
		Severity:    "LOW",
		FindingType: "S3_BUCKET_VERSIONING_DISABLED",
		Context: scoring.FindingContext{
			EnvType:            "dev",
			DataClassification: "Internal",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-04 should NOT trigger for LOW severity (only HIGH/CRITICAL)")
	}
}

// ---------------------------------------------------------------------------
// MP-05: WAF-Compensated Open SG Suppressor
// ---------------------------------------------------------------------------

func TestMP05_WAFCompensated_Triggers_OpenSGWithWAFOnALB(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "OPEN_SECURITY_GROUP_INGRESS_22",
		ResourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
		Context: scoring.FindingContext{
			WAFEnabled: true,
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-05 expected to match open SG with WAF on ALB, got no match")
	}
	if result.Pattern != "MP-05" {
		t.Errorf("expected pattern MP-05, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "LOW" {
		t.Errorf("expected HIGH downgraded 2 levels to LOW, got %s", result.AdjustedSeverity)
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", result.Confidence)
	}
}

func TestMP05_WAFCompensated_Triggers_SecurityGroupIngressOnCloudFront(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:     "CRITICAL",
		FindingType:  "SECURITY_GROUP_INGRESS_ALL_OPEN",
		ResourceType: "AWS::CloudFront::Distribution",
		Context: scoring.FindingContext{
			WAFEnabled: true,
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-05 expected to match SECURITY_GROUP_INGRESS on CloudFront with WAF, got no match")
	}
	if result.Pattern != "MP-05" {
		t.Errorf("expected pattern MP-05, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected CRITICAL downgraded 2 levels to MEDIUM, got %s", result.AdjustedSeverity)
	}
}

func TestMP05_WAFCompensated_NoTrigger_WAFDisabled(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "OPEN_SECURITY_GROUP",
		ResourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
		Context: scoring.FindingContext{
			WAFEnabled: false, // no WAF
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-05 should NOT trigger when WAF is disabled")
	}
}

func TestMP05_WAFCompensated_NoTrigger_NonLBResource(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// WAF enabled but resource is EC2 instance, not a load balancer
	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "OPEN_SECURITY_GROUP",
		ResourceType: "AWS::EC2::Instance",
		Context: scoring.FindingContext{
			WAFEnabled: true,
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-05 should NOT trigger for non-ALB/LB/CloudFront resource types")
	}
}

// ---------------------------------------------------------------------------
// MP-06: Stale RDS Public Attribute Detector
// ---------------------------------------------------------------------------

func TestMP06_RDSPublicAttr_Triggers_PubliclyAccessibleWithPrivateEndpoint(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "RDS_PUBLIC_ACCESS_ENABLED",
		Context: scoring.FindingContext{
			InternetFacing:  false,
			PrivateEndpoint: true,
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-06 expected to match RDS public attribute with private endpoint, got no match")
	}
	if result.Pattern != "MP-06" {
		t.Errorf("expected pattern MP-06, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "LOW" {
		t.Errorf("expected downgrade to LOW, got %s", result.AdjustedSeverity)
	}
	if result.SuggestedRiskScore != 20 {
		t.Errorf("expected SuggestedRiskScore=20, got %d", result.SuggestedRiskScore)
	}
	if result.Confidence != 0.90 {
		t.Errorf("expected confidence 0.90, got %f", result.Confidence)
	}
}

func TestMP06_RDSPublicAttr_Triggers_PubliclyAccessibleWithIsolatedVPC(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "CRITICAL",
		FindingType: "PUBLICLY_ACCESSIBLE_RDS",
		Context: scoring.FindingContext{
			InternetFacing:  false,
			PrivateEndpoint: false,
			VPCType:         "isolated",
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-06 expected to match PUBLICLY_ACCESSIBLE with isolated VPC, got no match")
	}
	if result.Pattern != "MP-06" {
		t.Errorf("expected pattern MP-06, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "LOW" {
		t.Errorf("expected downgrade to LOW, got %s", result.AdjustedSeverity)
	}
}

func TestMP06_RDSPublicAttr_NoTrigger_ActuallyInternetFacing(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "RDS_PUBLIC_ACCESS_ENABLED",
		Context: scoring.FindingContext{
			InternetFacing:  true, // actually internet-facing
			PrivateEndpoint: true,
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-06 should NOT trigger when resource is actually internet-facing")
	}
}

func TestMP06_RDSPublicAttr_NoTrigger_NoPrivateCompensation(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// Not internet-facing but also no private endpoint AND VPC not isolated
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "RDS_PUBLIC_ACCESS_ENABLED",
		Context: scoring.FindingContext{
			InternetFacing:  false,
			PrivateEndpoint: false,
			VPCType:         "shared",
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-06 should NOT trigger without private endpoint or isolated VPC")
	}
}

// ---------------------------------------------------------------------------
// MP-07: CVE Status Validator
// ---------------------------------------------------------------------------

// mockNVDChecker is a test stub that returns a fixed status for any CVE.
type mockNVDChecker struct {
	status string
	err    error
}

func (m *mockNVDChecker) GetCVEStatus(cveID string) (string, error) {
	return m.status, m.err
}

func TestMP07_CVEStatusValidator_Triggers_RejectedCVE(t *testing.T) {
	checker := &mockNVDChecker{status: "REJECTED"}
	engine := NewFPRuleEngine(checker)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "CVE-2023-REJECTED",
		Title:       "CVE-2023-REJECTED: Some vulnerability",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-07 expected to match REJECTED CVE, got no match")
	}
	if result.Pattern != "MP-07" {
		t.Errorf("expected pattern MP-07, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "INFORMATIONAL" {
		t.Errorf("expected suppress to INFORMATIONAL, got %s", result.AdjustedSeverity)
	}
	if result.SuggestedRiskScore != 5 {
		t.Errorf("expected SuggestedRiskScore=5, got %d", result.SuggestedRiskScore)
	}
	if result.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", result.Confidence)
	}
}

func TestMP07_CVEStatusValidator_Triggers_DisputedCVE(t *testing.T) {
	checker := &mockNVDChecker{status: "DISPUTED"}
	engine := NewFPRuleEngine(checker)

	f := scoring.Finding{
		Severity:    "CRITICAL",
		FindingType: "CVE-2022-DISPUTED-001",
		Title:       "CVE-2022-DISPUTED-001: Disputed finding",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-07 expected to match DISPUTED CVE, got no match")
	}
	if result.Pattern != "MP-07" {
		t.Errorf("expected pattern MP-07, got %s", result.Pattern)
	}
	if result.SuggestedRiskScore != 5 {
		t.Errorf("expected SuggestedRiskScore=5, got %d", result.SuggestedRiskScore)
	}
}

func TestMP07_CVEStatusValidator_NoTrigger_ActiveCVE(t *testing.T) {
	checker := &mockNVDChecker{status: "ACTIVE"}
	engine := NewFPRuleEngine(checker)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "CVE-2024-12345",
		Title:       "CVE-2024-12345: Active vulnerability",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-07 should NOT trigger for ACTIVE CVE status")
	}
}

func TestMP07_CVEStatusValidator_Skipped_WhenCheckerNil(t *testing.T) {
	// No NVD checker — rule should be skipped entirely
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "CVE-2023-REJECTED",
		Title:       "CVE-2023-REJECTED: Some vulnerability",
	}

	// With nil checker, no CVE rule should fire
	result, ok := engine.Evaluate(f)
	if ok {
		// Only fail if MP-07 claimed to fire
		if result.Pattern == "MP-07" {
			t.Error("MP-07 should be skipped when NVDStatusChecker is nil")
		}
	}
}

func TestMP07_CVEStatusValidator_NoTrigger_NoCVEInFindingType(t *testing.T) {
	checker := &mockNVDChecker{status: "REJECTED"}
	engine := NewFPRuleEngine(checker)

	// Finding type doesn't start with CVE-
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "S3_BUCKET_PUBLIC_READ",
		Title:       "S3 bucket is publicly readable",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-07 should NOT trigger when finding has no CVE ID")
	}
}

// ---------------------------------------------------------------------------
// MP-08: KMS Asymmetric Key Rotation Suppressor
// ---------------------------------------------------------------------------

func TestMP08_KMSAsymmetric_Triggers_KeyRotationDisabledRSA(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "KMS_KEY_ROTATION_DISABLED",
		ResourceType: "AWS::KMS::Key",
		Title:        "KMS key rotation is disabled",
		Description:  "RSA 4096 asymmetric key does not support automatic rotation",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-08 expected to match KMS asymmetric (RSA) rotation finding, got no match")
	}
	if result.Pattern != "MP-08" {
		t.Errorf("expected pattern MP-08, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "INFORMATIONAL" {
		t.Errorf("expected suppress to INFORMATIONAL, got %s", result.AdjustedSeverity)
	}
	if result.SuggestedRiskScore != 5 {
		t.Errorf("expected SuggestedRiskScore=5, got %d", result.SuggestedRiskScore)
	}
	if result.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", result.Confidence)
	}
	if result.Applied != true {
		t.Error("expected Applied=true")
	}
}

func TestMP08_KMSAsymmetric_Triggers_KeyRotationWithECC(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:     "MEDIUM",
		FindingType:  "KEY_ROTATION_DISABLED",
		ResourceType: "google_kms_key",
		Title:        "Key rotation disabled for ECC key",
		Description:  "ECC_NIST_P256 keys cannot be auto-rotated",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-08 expected to match KMS key rotation finding with ECC description, got no match")
	}
	if result.Pattern != "MP-08" {
		t.Errorf("expected pattern MP-08, got %s", result.Pattern)
	}
}

func TestMP08_KMSAsymmetric_Triggers_AsymmetricInTitle(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "KMS_KEY_ROTATION_DISABLED",
		ResourceType: "AWS::KMS::Key",
		Title:        "Asymmetric KMS key has rotation disabled",
		Description:  "This finding is expected for asymmetric keys",
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-08 expected to match when 'asymmetric' appears in title, got no match")
	}
	if result.Pattern != "MP-08" {
		t.Errorf("expected pattern MP-08, got %s", result.Pattern)
	}
}

func TestMP08_KMSAsymmetric_NoTrigger_SymmetricKey(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// KMS rotation finding but no asymmetric/RSA/ECC keywords — symmetric key
	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "KMS_KEY_ROTATION_DISABLED",
		ResourceType: "AWS::KMS::Key",
		Title:        "KMS key rotation is disabled",
		Description:  "Symmetric encryption key should have rotation enabled",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-08 should NOT trigger for symmetric KMS keys (no asymmetric/RSA/ECC/SM2 keyword)")
	}
}

func TestMP08_KMSAsymmetric_NoTrigger_NonKMSResource(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// Correct finding type but resource is not KMS
	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "KEY_ROTATION_DISABLED",
		ResourceType: "AWS::SecretsManager::Secret",
		Title:        "Secret rotation disabled",
		Description:  "RSA key stored in secrets manager",
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-08 should NOT trigger when resource type is not KMS-related")
	}
}

// ---------------------------------------------------------------------------
// Rule Priority Ordering Test
// ---------------------------------------------------------------------------

// TestFPRuleEngine_PriorityOrder verifies that the engine evaluates rules in
// MP-04 → MP-05 → MP-06 → MP-07 → MP-08 order and returns the FIRST match.
//
// We craft a finding that could match MP-05 (WAF open SG on ALB) but has
// sandbox env (MP-04 trigger). MP-04 should win because it's first.
func TestFPRuleEngine_PriorityOrder_MP04BeforeMP05(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// This finding matches BOTH MP-04 (sandbox+HIGH) AND MP-05 (open SG+WAF+ALB).
	// MP-04 should be returned since it is earlier in the rule chain.
	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "OPEN_SECURITY_GROUP",
		ResourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
		Context: scoring.FindingContext{
			EnvType:            "sandbox",
			DataClassification: "Internal",
			WAFEnabled:         true,
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("expected a rule match for dual-trigger finding, got none")
	}
	if result.Pattern != "MP-04" {
		t.Errorf("expected MP-04 to win (first match wins), got %s", result.Pattern)
	}
}

func TestFPRuleEngine_NoMatch_ReturnsNilFalse(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// A plain finding that matches no FP rule
	f := scoring.Finding{
		Severity:     "HIGH",
		FindingType:  "IAM_ROOT_ACCESS_KEY_ACTIVE",
		ResourceType: "AWS::IAM::Root",
		Context: scoring.FindingContext{
			EnvType:            "prod",
			DataClassification: "PCI",
			InternetFacing:     true,
		},
	}

	result, ok := engine.Evaluate(f)
	if ok {
		t.Errorf("expected no match for prod+PCI+IAM finding, got pattern %s", result.Pattern)
	}
	if result != nil {
		t.Error("expected nil result when no rule matches")
	}
}

// ---------------------------------------------------------------------------
// MP-11: ICS Protocol Port Contextualizer
// ---------------------------------------------------------------------------

func TestFP_MP11_ICSPort_Triggers_OpenSGWithOPCUA(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// OPEN_SECURITY_GROUP + OPC-UA port 4840 — should trigger
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "OPEN_SECURITY_GROUP_4840",
		Context: scoring.FindingContext{
			IngressPorts: []int{4840},
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-11 expected to match OPEN_SECURITY_GROUP with OPC-UA port 4840, got no match")
	}
	if result.Pattern != "MP-11" {
		t.Errorf("expected pattern MP-11, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected HIGH downgraded 1 level to MEDIUM, got %s", result.AdjustedSeverity)
	}
	if result.Confidence != 0.75 {
		t.Errorf("expected confidence 0.75, got %f", result.Confidence)
	}
	if result.Applied != true {
		t.Error("expected Applied=true")
	}
}

func TestFP_MP11_ICSPort_Triggers_MultipleICSPorts(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// Multiple ICS ports — any intersection should trigger
	f := scoring.Finding{
		Severity:    "CRITICAL",
		FindingType: "OPEN_SECURITY_GROUP_MULTI",
		Context: scoring.FindingContext{
			IngressPorts: []int{80, 443, 102, 8080},
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-11 expected to match when IngressPorts includes S7comm port 102, got no match")
	}
	if result.Pattern != "MP-11" {
		t.Errorf("expected pattern MP-11, got %s", result.Pattern)
	}
	if result.AdjustedSeverity != "HIGH" {
		t.Errorf("expected CRITICAL downgraded 1 level to HIGH, got %s", result.AdjustedSeverity)
	}
}

func TestFP_MP11_ICSPort_Triggers_AllPortsInTable(t *testing.T) {
	icsPorts := []int{102, 8883, 4840, 20000, 2404, 44818}
	engine := NewFPRuleEngine(nil)

	for _, port := range icsPorts {
		f := scoring.Finding{
			Severity:    "HIGH",
			FindingType: "OPEN_SECURITY_GROUP",
			Context: scoring.FindingContext{
				IngressPorts: []int{port},
			},
		}

		result, ok := engine.Evaluate(f)
		if !ok {
			t.Errorf("MP-11 expected to match ICS port %d in OPEN_SECURITY_GROUP finding, got no match", port)
			continue
		}
		if result.Pattern != "MP-11" {
			t.Errorf("port %d: expected pattern MP-11, got %s", port, result.Pattern)
		}
	}
}

func TestFP_MP11_ICSPort_NoTrigger_NonICSPorts(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// OPEN_SECURITY_GROUP but only standard web ports — no ICS ports
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "OPEN_SECURITY_GROUP",
		Context: scoring.FindingContext{
			IngressPorts: []int{443, 80},
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-11 should NOT trigger when IngressPorts contains no ICS ports")
	}
}

func TestFP_MP11_ICSPort_NoTrigger_WrongFindingType(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// ICS port present but finding type is not OPEN_SECURITY_GROUP
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "RDS_PUBLIC_ACCESS_ENABLED",
		Context: scoring.FindingContext{
			IngressPorts: []int{4840, 20000},
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-11 should NOT trigger when FindingType does not contain OPEN_SECURITY_GROUP")
	}
}

func TestFP_MP11_ICSPort_NoTrigger_EmptyIngressPorts(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	// OPEN_SECURITY_GROUP but no ingress ports specified
	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "OPEN_SECURITY_GROUP",
		Context: scoring.FindingContext{
			IngressPorts: []int{},
		},
	}

	_, ok := engine.Evaluate(f)
	if ok {
		t.Error("MP-11 should NOT trigger when IngressPorts is empty")
	}
}

func TestFP_MP11_ICSPort_NoteContainsICSMessage(t *testing.T) {
	engine := NewFPRuleEngine(nil)

	f := scoring.Finding{
		Severity:    "HIGH",
		FindingType: "OPEN_SECURITY_GROUP",
		Context: scoring.FindingContext{
			IngressPorts: []int{44818}, // EtherNet/IP
		},
	}

	result, ok := engine.Evaluate(f)
	if !ok {
		t.Fatal("MP-11 expected to match OPEN_SECURITY_GROUP with EtherNet/IP port 44818, got no match")
	}
	if result.Pattern != "MP-11" {
		t.Errorf("expected pattern MP-11, got %s", result.Pattern)
	}
	// Verify the reason contains the expected note
	expectedNote := "ICS/IoT protocol port"
	if !strings.Contains(result.Reason, expectedNote) {
		t.Errorf("expected Reason to contain %q, got %q", expectedNote, result.Reason)
	}
}
