package scoring

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- Mock implementations ---

// mockLLMProvider returns a canned JSON response for all completions.
type mockLLMProvider struct {
	response string
	err      error
}

func (m *mockLLMProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &CompletionResponse{
		Content: m.response,
		Usage:   Usage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
	}, nil
}

func (m *mockLLMProvider) Stream(_ context.Context, _ CompletionRequest) (<-chan StreamChunk, error) {
	ch := make(chan StreamChunk, 1)
	ch <- StreamChunk{Done: true}
	close(ch)
	return ch, nil
}

func (m *mockLLMProvider) CountTokens(_ context.Context, _ string) (int, error) { return 0, nil }
func (m *mockLLMProvider) ModelName() string                                     { return "mock-model" }
func (m *mockLLMProvider) MaxContextLength() int                                 { return 100000 }
func (m *mockLLMProvider) IsAvailable(_ context.Context) bool                   { return true }

// mockContextEnricher sets a fixed AssetTier/EnvType on findings it enriches.
type mockContextEnricher struct {
	assetTier          string
	envType            string
	dataClassification string
	err                error
}

func (m *mockContextEnricher) EnrichContext(_ context.Context, finding *Finding) error {
	if m.err != nil {
		return m.err
	}
	if m.assetTier != "" {
		finding.Context.AssetTier = m.assetTier
	}
	if m.envType != "" {
		finding.Context.EnvType = m.envType
	}
	if m.dataClassification != "" {
		finding.Context.DataClassification = m.dataClassification
	}
	return nil
}

// mockFPHistoryStore returns predetermined FP statistics.
type mockFPHistoryStore struct {
	count float64
	rate  float64
	err   error
}

func (m *mockFPHistoryStore) GetFPStats(_ context.Context, _, _ string) (int, float64, error) {
	return int(m.count), m.rate, m.err
}

func (m *mockFPHistoryStore) RecordFP(_ context.Context, _, _ string) error {
	return nil
}

// --- Helper constructors ---

func newTestFinding(severity string) *Finding {
	return &Finding{
		ID:           "test-001",
		Source:       "aws-securityhub",
		Severity:     severity,
		FindingType:  "S3_BUCKET_PUBLIC_READ",
		ResourceID:   "arn:aws:s3:::my-bucket",
		ResourceType: "AWS::S3::Bucket",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		Title:        "S3 bucket is publicly accessible",
		Description:  "The S3 bucket allows public read access.",
		FirstSeen:    time.Now().AddDate(0, 0, -10),
		DaysOpen:     10,
	}
}

func newDefaultConfig() RiskScorerConfig {
	return DefaultRiskScorerConfig()
}

func validLLMResponse(severity string, score int, confidence float64, action string) string {
	return fmt.Sprintf(`{
  "adjusted_severity": %q,
  "risk_score": %d,
  "confidence": %.2f,
  "rationale": "Test rationale",
  "mitigating_factors": ["WAF enabled"],
  "aggravating_factors": ["Internet-facing"],
  "recommended_action": %q
}`, severity, score, confidence, action)
}

// --- Tests for BuildPrompt ---

func TestBuildPrompt_MinimalContext(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	finding := newTestFinding("HIGH")

	prompt := pb.BuildPrompt(finding)

	// Core finding fields must appear.
	if !strings.Contains(prompt, finding.ID) {
		t.Errorf("expected prompt to contain finding ID %q", finding.ID)
	}
	if !strings.Contains(prompt, finding.Title) {
		t.Errorf("expected prompt to contain title %q", finding.Title)
	}
	if !strings.Contains(prompt, "HIGH") {
		t.Error("expected prompt to contain severity HIGH")
	}
	if !strings.Contains(prompt, "adjusted_severity") {
		t.Error("expected prompt to contain JSON schema for adjusted_severity")
	}

	// Optional sections must NOT appear when context is empty.
	if strings.Contains(prompt, "## Vulnerability Context") {
		t.Error("vulnerability context section should not appear for zero CVSS score")
	}
	if strings.Contains(prompt, "## Historical Pattern") {
		t.Error("historical pattern section should not appear for zero FP count")
	}
	if strings.Contains(prompt, "## Threat Intelligence") {
		t.Error("threat intelligence section should not appear with no TI data")
	}
}

func TestBuildPrompt_FullContext(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	inUse := true
	finding := &Finding{
		ID:           "full-001",
		Source:       "gcp-scc",
		Severity:     "CRITICAL",
		FindingType:  "CVE-2024-9999",
		ResourceID:   "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-vm",
		ResourceType: "google.compute.Instance",
		Region:       "us-central1",
		AccountID:    "my-project",
		Title:        "Critical CVE in running instance",
		Description:  "CVE-2024-9999 found in package libssl on running VM.",
		FirstSeen:    time.Now().AddDate(0, 0, -5),
		DaysOpen:     5,
		Context: FindingContext{
			AssetTier:            "Tier1-Prod",
			EnvType:              "prod",
			DataClassification:   "PCI",
			InternetFacing:       true,
			VPCType:              "shared",
			IngressPorts:         []int{443, 80},
			EgressRestricted:     true,
			WAFEnabled:           true,
			EDREnabled:           true,
			DLPEnabled:           false,
			EncryptionAtRest:     true,
			EncryptionInTransit:  true,
			MFARequired:          true,
			PrivateEndpoint:      false,
			CVSSScore:            9.8,
			ExploitAvailable:     true,
			ExploitInWild:        true,
			PackageInUse:         &inUse,
			PatchAvailable:       false,
			FalsePositiveHistory: 1,
			FPRateForType:        0.02,
			BusinessCriticality:  "critical",
			ComplianceScopes:     []string{"PCI-DSS", "SOC2"},
			DataResidency:        "us",
			CostCenter:           "cc-1234",
			ApplicationOwner:     "payments-team",
			SupportTier:          "platinum",
			InKEV:                true,
			EPSSScore:            0.9421,
			EPSSPercentile:       0.99,
			AttackPathScore:      88.5,
			IsToxicCombination:   true,
			BlastRadiusCount:     42,
		},
	}

	prompt := pb.BuildPrompt(finding)

	requiredSections := []string{
		"## Vulnerability Context",
		"## Historical Pattern",
		"## Threat Intelligence",
		"CVSS Score: 9.8",
		"In CISA KEV: true",
		"EPSS Score: 0.9421",
		"Attack Path Score: 88.5",
		"Toxic Combination: true",
		"Blast Radius",
	}
	for _, section := range requiredSections {
		if !strings.Contains(prompt, section) {
			t.Errorf("expected prompt to contain %q", section)
		}
	}
}

func TestBuildPrompt_WithCVEReferences_IncludesCVEDetails(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	finding := newTestFinding("HIGH")
	finding.FindingType = "CVE-2024-1234"
	finding.Context.CVSSScore = 8.1
	finding.Context.ExploitAvailable = true
	finding.Context.ExploitInWild = false
	finding.Context.PatchAvailable = true

	prompt := pb.BuildPrompt(finding)

	if !strings.Contains(prompt, "## Vulnerability Context") {
		t.Error("expected Vulnerability Context section for non-zero CVSS score")
	}
	if !strings.Contains(prompt, "CVSS Score: 8.1") {
		t.Error("expected CVSS score in prompt")
	}
	if !strings.Contains(prompt, "Exploit Available: true") {
		t.Error("expected exploit availability in prompt")
	}
	if !strings.Contains(prompt, "Patch Available: true") {
		t.Error("expected patch availability in prompt")
	}
}

func TestBuildPrompt_WithComplianceMappings(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	finding := newTestFinding("MEDIUM")
	finding.Context.ComplianceScopes = []string{"PCI-DSS", "HIPAA", "SOC2"}
	finding.Context.DataClassification = "PHI"

	prompt := pb.BuildPrompt(finding)

	if !strings.Contains(prompt, "PHI") {
		t.Error("expected data classification PHI in prompt")
	}
	// ComplianceScopes is printed via %v, check at least one standard appears.
	if !strings.Contains(prompt, "PCI-DSS") {
		t.Error("expected PCI-DSS compliance scope in prompt")
	}
}

func TestBuildPrompt_WithRemediationHistory_IncludesHistoricalPattern(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	finding := newTestFinding("MEDIUM")
	finding.Context.FalsePositiveHistory = 7
	finding.Context.FPRateForType = 0.45

	prompt := pb.BuildPrompt(finding)

	if !strings.Contains(prompt, "## Historical Pattern") {
		t.Error("expected Historical Pattern section")
	}
	if !strings.Contains(prompt, "False Positive Count: 7") {
		t.Error("expected FP count in prompt")
	}
	// 0.45 * 100 = 45.0%
	if !strings.Contains(prompt, "45.0%") {
		t.Error("expected FP rate percentage in prompt")
	}
}

func TestBuildPrompt_ThreatIntelSection_AppearsForKEVOnly(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	finding := newTestFinding("HIGH")
	finding.Context.InKEV = true
	// CVSSScore = 0, so Vulnerability Context should not appear.
	// But threat intel (InKEV=true) should trigger the TI section.

	prompt := pb.BuildPrompt(finding)

	if !strings.Contains(prompt, "## Threat Intelligence") {
		t.Error("expected Threat Intelligence section when InKEV is true")
	}
	if !strings.Contains(prompt, "In CISA KEV: true") {
		t.Error("expected KEV indicator in prompt")
	}
	if strings.Contains(prompt, "## Vulnerability Context") {
		t.Error("Vulnerability Context should not appear when CVSS score is zero")
	}
}

func TestBuildPrompt_ContainsInstructions(t *testing.T) {
	pb := NewRiskScorerPromptBuilder()
	finding := newTestFinding("LOW")

	prompt := pb.BuildPrompt(finding)

	// JSON schema instructions must always be present.
	if !strings.Contains(prompt, "## Instructions") {
		t.Error("expected ## Instructions section in prompt")
	}
	if !strings.Contains(prompt, "recommended_action") {
		t.Error("expected recommended_action field in JSON schema")
	}
	if !strings.Contains(prompt, "risk_score") {
		t.Error("expected risk_score field in JSON schema")
	}
}

// --- Tests for applyGuardrails ---

func TestApplyGuardrails_CriticalTier1InternetFacing_CannotBeDowngraded(t *testing.T) {
	config := newDefaultConfig()
	config.NeverDowngradeCriticalProdInternetFacing = true

	rs := &RiskScorer{config: config}

	finding := newTestFinding("CRITICAL")
	finding.Context.AssetTier = "Tier1-Prod"
	finding.Context.InternetFacing = true

	assessment := &RiskAssessment{
		OriginalSeverity: "CRITICAL",
		AdjustedSeverity: "HIGH", // LLM tried to downgrade
		RiskScore:        70,
	}

	rs.applyGuardrails(assessment, finding)

	if assessment.AdjustedSeverity != "CRITICAL" {
		t.Errorf("expected adjusted severity CRITICAL, got %s", assessment.AdjustedSeverity)
	}
	if assessment.SeverityChanged {
		t.Error("severity_changed should be false after guardrail reset")
	}
	if assessment.SeverityDirection != "unchanged" {
		t.Errorf("expected severity_direction unchanged, got %s", assessment.SeverityDirection)
	}
	// Guardrail explanation must appear in aggravating factors.
	found := false
	for _, f := range assessment.AggravatingFactors {
		if strings.Contains(f, "Guardrail") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected guardrail note in aggravating factors")
	}
}

func TestApplyGuardrails_CriticalTier2NonInternetFacing_AllowedToRemain(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	finding := newTestFinding("CRITICAL")
	finding.Context.AssetTier = "Tier2-NonProd"
	finding.Context.InternetFacing = false

	assessment := &RiskAssessment{
		OriginalSeverity: "CRITICAL",
		AdjustedSeverity: "HIGH",
		RiskScore:        72,
	}

	rs.applyGuardrails(assessment, finding)

	// Rule 1 does NOT apply (not Tier1-Prod+internet-facing), so HIGH should persist.
	if assessment.AdjustedSeverity != "HIGH" {
		t.Errorf("expected HIGH to remain (rule 1 should not fire), got %s", assessment.AdjustedSeverity)
	}
}

func TestApplyGuardrails_PCIData_MinimumMediumEnforced(t *testing.T) {
	config := newDefaultConfig()
	config.MinimumSeverityForPCIPII = "MEDIUM"
	rs := &RiskScorer{config: config}

	finding := newTestFinding("LOW")
	finding.Context.DataClassification = "PCI"

	assessment := &RiskAssessment{
		OriginalSeverity: "LOW",
		AdjustedSeverity: "LOW",
		RiskScore:        20,
	}

	rs.applyGuardrails(assessment, finding)

	if assessment.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected PCI data to be elevated to MEDIUM, got %s", assessment.AdjustedSeverity)
	}
	// Risk score should be clamped to MEDIUM's range [40, 64].
	if assessment.RiskScore < 40 || assessment.RiskScore > 64 {
		t.Errorf("risk score %d out of MEDIUM range [40,64]", assessment.RiskScore)
	}
}

func TestApplyGuardrails_PIIData_MinimumMediumEnforced(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	finding := newTestFinding("LOW")
	finding.Context.DataClassification = "PII"

	assessment := &RiskAssessment{
		OriginalSeverity: "LOW",
		AdjustedSeverity: "LOW",
		RiskScore:        25,
	}

	rs.applyGuardrails(assessment, finding)

	if assessment.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected PII data to be elevated to MEDIUM, got %s", assessment.AdjustedSeverity)
	}
}

func TestApplyGuardrails_PackageUsageUnknown_ConfidenceCapped(t *testing.T) {
	config := newDefaultConfig()
	config.CapConfidenceWhenPackageUsageUnknown = 0.7
	rs := &RiskScorer{config: config}

	finding := newTestFinding("HIGH")
	finding.Context.PackageInUse = nil // nil = unknown

	assessment := &RiskAssessment{
		OriginalSeverity: "HIGH",
		AdjustedSeverity: "HIGH",
		RiskScore:        78,
		Confidence:       0.95, // LLM was very confident
		Rationale:        "Package risk confirmed.",
	}

	rs.applyGuardrails(assessment, finding)

	if assessment.Confidence > 0.7 {
		t.Errorf("expected confidence capped at 0.7, got %.2f", assessment.Confidence)
	}
	if !strings.Contains(assessment.Rationale, "Confidence capped") {
		t.Error("expected rationale to note confidence cap")
	}
}

func TestApplyGuardrails_PackageUsageKnown_ConfidenceNotCapped(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	inUse := true
	finding := newTestFinding("HIGH")
	finding.Context.PackageInUse = &inUse

	assessment := &RiskAssessment{
		OriginalSeverity: "HIGH",
		AdjustedSeverity: "HIGH",
		RiskScore:        78,
		Confidence:       0.95,
		Rationale:        "Package in active use.",
	}

	rs.applyGuardrails(assessment, finding)

	if assessment.Confidence != 0.95 {
		t.Errorf("expected confidence unchanged at 0.95, got %.2f", assessment.Confidence)
	}
}

func TestApplyGuardrails_RiskScoreClamped_ToSeverityRange(t *testing.T) {
	tests := []struct {
		name         string
		severity     string
		inputScore   int
		expectedMin  int
		expectedMax  int
	}{
		{"critical low score clamped up", "CRITICAL", 50, 85, 100},
		{"critical high score stays", "CRITICAL", 95, 85, 100},
		{"high low score clamped up", "HIGH", 30, 65, 84},
		{"high high score clamped down", "HIGH", 90, 65, 84},
		{"medium stays in range", "MEDIUM", 50, 40, 64},
		{"low stays in range", "LOW", 25, 15, 39},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := newDefaultConfig()
			rs := &RiskScorer{config: config}

			finding := newTestFinding(tc.severity)
			assessment := &RiskAssessment{
				OriginalSeverity: tc.severity,
				AdjustedSeverity: tc.severity,
				RiskScore:        tc.inputScore,
			}

			rs.applyGuardrails(assessment, finding)

			if assessment.RiskScore < tc.expectedMin || assessment.RiskScore > tc.expectedMax {
				t.Errorf("severity %s: risk score %d not in [%d,%d]",
					tc.severity, assessment.RiskScore, tc.expectedMin, tc.expectedMax)
			}
		})
	}
}

// --- Tests for checkAutoAccept ---

func TestCheckAutoAccept_LowSandbox_AutoAccepted(t *testing.T) {
	config := newDefaultConfig()
	config.AutoAcceptLowInSandbox = true
	rs := &RiskScorer{config: config}

	finding := newTestFinding("LOW")
	finding.Context.EnvType = "sandbox"

	result := rs.checkAutoAccept(finding)

	if result == nil {
		t.Fatal("expected auto-accept for LOW severity in sandbox")
	}
	if !result.AutoAcceptEligible {
		t.Error("expected auto_accept_eligible to be true")
	}
	if result.AutoAcceptReason != "sandbox_low_severity" {
		t.Errorf("expected reason sandbox_low_severity, got %s", result.AutoAcceptReason)
	}
	if result.RecommendedAction != "accept_risk" {
		t.Errorf("expected recommended_action accept_risk, got %s", result.RecommendedAction)
	}
}

func TestCheckAutoAccept_LowProd_NotAutoAccepted(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	finding := newTestFinding("LOW")
	finding.Context.EnvType = "prod"

	result := rs.checkAutoAccept(finding)

	if result != nil {
		t.Errorf("expected no auto-accept for LOW in prod, got %+v", result)
	}
}

func TestCheckAutoAccept_HighSandbox_NotAutoAccepted(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	finding := newTestFinding("HIGH")
	finding.Context.EnvType = "sandbox"

	result := rs.checkAutoAccept(finding)

	if result != nil {
		t.Error("expected no auto-accept for HIGH severity even in sandbox")
	}
}

func TestCheckAutoAccept_HighFPRate_AutoAccepted(t *testing.T) {
	config := newDefaultConfig()
	config.HighFPRateThreshold = 0.3
	rs := &RiskScorer{config: config}

	finding := newTestFinding("HIGH")
	finding.Context.FPRateForType = 0.45
	finding.Context.FalsePositiveHistory = 5

	result := rs.checkAutoAccept(finding)

	if result == nil {
		t.Fatal("expected auto-accept for high FP rate")
	}
	if result.AutoAcceptReason != "high_fp_rate" {
		t.Errorf("expected reason high_fp_rate, got %s", result.AutoAcceptReason)
	}
	if result.AdjustedSeverity != "LOW" {
		t.Errorf("expected adjusted severity LOW, got %s", result.AdjustedSeverity)
	}
}

func TestCheckAutoAccept_CriticalHighFPRate_NotAutoAccepted(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	finding := newTestFinding("CRITICAL")
	finding.Context.FPRateForType = 0.9
	finding.Context.FalsePositiveHistory = 10

	result := rs.checkAutoAccept(finding)

	// CRITICAL findings are exempt from FP auto-accept.
	if result != nil {
		t.Error("expected no auto-accept for CRITICAL findings regardless of FP rate")
	}
}

func TestCheckAutoAccept_HighFPRate_InsufficientHistory_NotAutoAccepted(t *testing.T) {
	config := newDefaultConfig()
	rs := &RiskScorer{config: config}

	finding := newTestFinding("MEDIUM")
	finding.Context.FPRateForType = 0.5
	finding.Context.FalsePositiveHistory = 2 // requires >= 3

	result := rs.checkAutoAccept(finding)

	if result != nil {
		t.Error("expected no auto-accept when FP history count < 3")
	}
}

// --- Tests for parseResponse ---

func TestParseResponse_ValidJSON_ExtractsAllFields(t *testing.T) {
	rs := &RiskScorer{}
	finding := newTestFinding("HIGH")
	content := `Some LLM preamble text.
{
  "adjusted_severity": "MEDIUM",
  "risk_score": 55,
  "confidence": 0.82,
  "rationale": "Compensating controls reduce risk",
  "mitigating_factors": ["WAF enabled", "Private endpoint"],
  "aggravating_factors": ["Internet-facing"],
  "recommended_action": "accept_risk"
}
Some trailing text.`

	assessment, err := rs.parseResponse(content, finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if assessment.AdjustedSeverity != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", assessment.AdjustedSeverity)
	}
	if assessment.RiskScore != 55 {
		t.Errorf("expected risk score 55, got %d", assessment.RiskScore)
	}
	if assessment.Confidence != 0.82 {
		t.Errorf("expected confidence 0.82, got %.2f", assessment.Confidence)
	}
	if assessment.OriginalSeverity != "HIGH" {
		t.Errorf("expected original severity HIGH, got %s", assessment.OriginalSeverity)
	}
	if !assessment.SeverityChanged {
		t.Error("expected severity_changed true when severity differs")
	}
	if assessment.SeverityDirection != "downgraded" {
		t.Errorf("expected downgraded, got %s", assessment.SeverityDirection)
	}
}

func TestParseResponse_SeverityUpgraded_DirectionIsUpgraded(t *testing.T) {
	rs := &RiskScorer{}
	finding := newTestFinding("MEDIUM")
	content := `{"adjusted_severity": "HIGH", "risk_score": 70, "confidence": 0.9, "rationale": "r", "recommended_action": "remediate"}`

	assessment, err := rs.parseResponse(content, finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if assessment.SeverityDirection != "upgraded" {
		t.Errorf("expected upgraded, got %s", assessment.SeverityDirection)
	}
}

func TestParseResponse_SeverityUnchanged(t *testing.T) {
	rs := &RiskScorer{}
	finding := newTestFinding("HIGH")
	content := `{"adjusted_severity": "HIGH", "risk_score": 75, "confidence": 0.88, "rationale": "r", "recommended_action": "remediate"}`

	assessment, err := rs.parseResponse(content, finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if assessment.SeverityChanged {
		t.Error("expected severity_changed false")
	}
	if assessment.SeverityDirection != "unchanged" {
		t.Errorf("expected unchanged, got %s", assessment.SeverityDirection)
	}
}

func TestParseResponse_NoJSON_ReturnsError(t *testing.T) {
	rs := &RiskScorer{}
	finding := newTestFinding("HIGH")

	_, err := rs.parseResponse("This is plain text with no JSON.", finding)
	if err == nil {
		t.Error("expected error for response with no JSON")
	}
}

func TestParseResponse_InvalidJSON_ReturnsError(t *testing.T) {
	rs := &RiskScorer{}
	finding := newTestFinding("HIGH")

	_, err := rs.parseResponse(`{ "adjusted_severity": "HIGH", broken json }`, finding)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

// --- Tests for ScoreFinding (integration with mocks) ---

func TestScoreFinding_AutoAcceptPath_SkipsLLM(t *testing.T) {
	// Mock LLM that would fail if called — confirms auto-accept path skips it.
	llm := &mockLLMProvider{err: fmt.Errorf("LLM should not be called")}
	enricher := &mockContextEnricher{}
	fpStore := &mockFPHistoryStore{}

	config := newDefaultConfig()
	config.AutoAcceptLowInSandbox = true
	rs := NewRiskScorer(llm, enricher, fpStore, config)

	finding := newTestFinding("LOW")
	finding.Context.EnvType = "sandbox"

	result, err := rs.ScoreFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ModelUsed != "rule_based" {
		t.Errorf("expected model_used=rule_based, got %s", result.ModelUsed)
	}
	if !result.AutoAcceptEligible {
		t.Error("expected auto_accept_eligible true")
	}
}

func TestScoreFinding_LLMPath_ReturnsAssessment(t *testing.T) {
	llm := &mockLLMProvider{
		response: validLLMResponse("HIGH", 75, 0.85, "remediate"),
	}
	enricher := &mockContextEnricher{assetTier: "Tier1-Prod", envType: "prod"}
	fpStore := &mockFPHistoryStore{count: 0, rate: 0.01}

	config := newDefaultConfig()
	rs := NewRiskScorer(llm, enricher, fpStore, config)

	finding := newTestFinding("HIGH")

	result, err := rs.ScoreFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AdjustedSeverity == "" {
		t.Error("expected non-empty adjusted severity")
	}
	if result.RiskScore == 0 {
		t.Error("expected non-zero risk score")
	}
	if result.ScoredAt.IsZero() {
		t.Error("expected scored_at to be set")
	}
	if result.ModelUsed != config.ModelName {
		t.Errorf("expected model_used=%s, got %s", config.ModelName, result.ModelUsed)
	}
}

func TestScoreFinding_LLMError_ReturnsError(t *testing.T) {
	llm := &mockLLMProvider{err: fmt.Errorf("LLM unavailable")}
	enricher := &mockContextEnricher{}
	fpStore := &mockFPHistoryStore{}

	config := newDefaultConfig()
	// Disable auto-accept so we hit the LLM path.
	config.AutoAcceptLowInSandbox = false
	rs := NewRiskScorer(llm, enricher, fpStore, config)

	finding := newTestFinding("HIGH")

	_, err := rs.ScoreFinding(context.Background(), finding)
	if err == nil {
		t.Error("expected error when LLM fails")
	}
	if !strings.Contains(err.Error(), "LLM completion failed") {
		t.Errorf("expected LLM error message, got: %v", err)
	}
}

func TestScoreFinding_EnricherError_ContinuesWithLimitedContext(t *testing.T) {
	llm := &mockLLMProvider{
		response: validLLMResponse("MEDIUM", 50, 0.75, "investigate"),
	}
	enricher := &mockContextEnricher{err: fmt.Errorf("enrichment service down")}
	fpStore := &mockFPHistoryStore{}

	config := newDefaultConfig()
	rs := NewRiskScorer(llm, enricher, fpStore, config)

	// Finding with empty context — enricher will fail, but scoring should continue.
	finding := newTestFinding("MEDIUM")

	result, err := rs.ScoreFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("enricher error should not fail ScoreFinding, got: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result even when enricher fails")
	}
}

func TestScoreFinding_FPStoreLoadsStats(t *testing.T) {
	llm := &mockLLMProvider{
		response: validLLMResponse("MEDIUM", 45, 0.8, "investigate"),
	}
	enricher := &mockContextEnricher{}
	fpStore := &mockFPHistoryStore{count: 4, rate: 0.35}

	config := newDefaultConfig()
	// HighFPRateThreshold=0.3, count=4>=3, severity=MEDIUM (not CRITICAL) → auto-accept
	rs := NewRiskScorer(llm, enricher, fpStore, config)

	finding := newTestFinding("MEDIUM")

	result, err := rs.ScoreFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// FP store returned count=4, rate=0.35 → exceeds threshold → auto-accept path.
	if result.AutoAcceptReason != "high_fp_rate" {
		t.Errorf("expected high_fp_rate auto-accept, got: %s", result.AutoAcceptReason)
	}
}

// --- Tests for helper functions ---

func TestSeverityToInt_Ordering(t *testing.T) {
	// CRITICAL < HIGH < MEDIUM < LOW < INFORMATIONAL (numerically lower = higher priority)
	if severityToInt("CRITICAL") >= severityToInt("HIGH") {
		t.Error("CRITICAL should have lower int than HIGH")
	}
	if severityToInt("HIGH") >= severityToInt("MEDIUM") {
		t.Error("HIGH should have lower int than MEDIUM")
	}
	if severityToInt("MEDIUM") >= severityToInt("LOW") {
		t.Error("MEDIUM should have lower int than LOW")
	}
	if severityToInt("LOW") >= severityToInt("INFORMATIONAL") {
		t.Error("LOW should have lower int than INFORMATIONAL")
	}
}

func TestSeverityToInt_CaseInsensitive(t *testing.T) {
	if severityToInt("critical") != severityToInt("CRITICAL") {
		t.Error("severity comparison should be case-insensitive")
	}
}

func TestSeverityToInt_UnknownMapsToLowest(t *testing.T) {
	// Unknown severity should be treated as lowest priority.
	if severityToInt("UNKNOWN") != severityToInt("INFORMATIONAL") {
		t.Error("unknown severity should map to same value as INFORMATIONAL")
	}
}

func TestSeverityScoreRanges_NoOverlap(t *testing.T) {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for i, sev := range severities {
		min := severityToMinScore(sev)
		max := severityToMaxScore(sev)

		if min > max {
			t.Errorf("severity %s: min %d > max %d", sev, min, max)
		}

		// Ensure no overlap with next severity.
		if i+1 < len(severities) {
			nextMax := severityToMaxScore(severities[i+1])
			if min <= nextMax {
				t.Errorf("severity %s min %d overlaps with %s max %d",
					sev, min, severities[i+1], nextMax)
			}
		}
	}
}

func TestDefaultRiskScorerConfig_ReasonableDefaults(t *testing.T) {
	cfg := DefaultRiskScorerConfig()

	if cfg.ModelName == "" {
		t.Error("expected non-empty model name")
	}
	if cfg.Temperature < 0 || cfg.Temperature > 1 {
		t.Errorf("temperature %f out of range [0,1]", cfg.Temperature)
	}
	if cfg.MaxTokens <= 0 {
		t.Error("expected positive max_tokens")
	}
	if cfg.HighFPRateThreshold <= cfg.LowFPRateThreshold {
		t.Error("high FP threshold should be greater than low FP threshold")
	}
	if !cfg.NeverDowngradeCriticalProdInternetFacing {
		t.Error("expected NeverDowngradeCriticalProdInternetFacing to default to true")
	}
}

func TestCompletionRequest_Clone_IsDeepCopy(t *testing.T) {
	original := CompletionRequest{
		Model:       "claude-opus-4-6",
		Temperature: 0.1,
		MaxTokens:   1024,
		Messages:    []Message{{Role: "user", Content: "hello"}},
		System:      "system prompt",
	}

	clone := original.Clone()

	// Mutating the clone should not affect the original.
	clone.Messages[0].Content = "modified"
	if original.Messages[0].Content == "modified" {
		t.Error("clone mutation affected original — deep copy failed")
	}
	if clone.Model != original.Model {
		t.Error("clone should have same model as original")
	}
	if clone.System != original.System {
		t.Error("clone should have same system prompt as original")
	}
}

func TestCompletionRequest_Clone_NilMessages(t *testing.T) {
	original := CompletionRequest{Model: "m", Messages: nil}
	clone := original.Clone()
	if clone.Messages != nil {
		t.Error("expected nil messages in clone when original has nil messages")
	}
}
