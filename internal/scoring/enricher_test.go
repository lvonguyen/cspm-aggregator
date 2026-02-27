package scoring

import (
	"context"
	"fmt"
	"testing"
)

// --- Mock implementations for enricher consumer interfaces ---

type mockEPSSClient struct {
	score      float64
	percentile float64
	err        error
}

func (m *mockEPSSClient) GetScoreWithPercentile(_ string) (float64, float64, error) {
	return m.score, m.percentile, m.err
}

type mockKEVCatalog struct {
	exploited bool
}

func (m *mockKEVCatalog) IsKnownExploited(_ string) bool {
	return m.exploited
}

type mockEnvClassifier struct {
	envType string
}

func (m *mockEnvClassifier) Classify(_ string, _ map[string]string, _ string) string {
	return m.envType
}

// --- Helper ---

func newCVEFinding(findingType string) *Finding {
	return &Finding{
		ID:           "enrich-001",
		Source:       "aws-securityhub",
		Severity:     "HIGH",
		FindingType:  findingType,
		ResourceID:   "arn:aws:ec2:us-east-1:123456789012:instance/i-abcdef",
		ResourceType: "AWS::EC2::Instance",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		Title:        "CVE finding",
	}
}

// --- CompositeEnricher tests ---

func TestCompositeEnricher_AllSources_FullEnrichment(t *testing.T) {
	epss := &mockEPSSClient{score: 0.75, percentile: 0.92}
	kev := &mockKEVCatalog{exploited: true}
	env := &mockEnvClassifier{envType: "prod"}

	enricher := NewCompositeEnricher(epss, kev, env)
	finding := newCVEFinding("CVE-2024-1234")

	if err := enricher.EnrichContext(context.Background(), finding); err != nil {
		t.Fatalf("EnrichContext returned error: %v", err)
	}

	if finding.Context.EPSSScore != 0.75 {
		t.Errorf("expected EPSSScore 0.75, got %.4f", finding.Context.EPSSScore)
	}
	if finding.Context.EPSSPercentile != 0.92 {
		t.Errorf("expected EPSSPercentile 0.92, got %.4f", finding.Context.EPSSPercentile)
	}
	if !finding.Context.InKEV {
		t.Error("expected InKEV true")
	}
	if finding.Context.EnvType != "prod" {
		t.Errorf("expected EnvType prod, got %s", finding.Context.EnvType)
	}
	if finding.Context.AssetTier != "Tier1-Prod" {
		t.Errorf("expected AssetTier Tier1-Prod, got %s", finding.Context.AssetTier)
	}
	if !finding.Context.ExploitAvailable {
		t.Error("expected ExploitAvailable true (KEV implies exploit available)")
	}
	if !finding.Context.ExploitInWild {
		t.Error("expected ExploitInWild true (KEV implies exploit in wild)")
	}
}

func TestCompositeEnricher_EPSSFailure_StillSetsKEVAndEnv(t *testing.T) {
	epss := &mockEPSSClient{err: fmt.Errorf("EPSS service timeout")}
	kev := &mockKEVCatalog{exploited: true}
	env := &mockEnvClassifier{envType: "staging"}

	enricher := NewCompositeEnricher(epss, kev, env)
	finding := newCVEFinding("CVE-2023-9999")

	if err := enricher.EnrichContext(context.Background(), finding); err != nil {
		t.Fatalf("EnrichContext must not return error on enrichment failure: %v", err)
	}

	if finding.Context.EPSSScore != 0 {
		t.Errorf("expected EPSSScore 0 on EPSS failure, got %.4f", finding.Context.EPSSScore)
	}
	if finding.Context.EPSSPercentile != 0 {
		t.Errorf("expected EPSSPercentile 0 on EPSS failure, got %.4f", finding.Context.EPSSPercentile)
	}
	if !finding.Context.InKEV {
		t.Error("expected InKEV true despite EPSS failure")
	}
	if finding.Context.EnvType != "staging" {
		t.Errorf("expected EnvType staging, got %s", finding.Context.EnvType)
	}
}

func TestCompositeEnricher_NoCVEInFindingType_SkipsEPSSAndKEV(t *testing.T) {
	// mockKEVCatalog.exploited=true — if called, would incorrectly set InKEV=true.
	epss := &mockEPSSClient{err: fmt.Errorf("should not be called")}
	kev := &mockKEVCatalog{exploited: true}
	env := &mockEnvClassifier{envType: "sandbox"}

	enricher := NewCompositeEnricher(epss, kev, env)
	finding := newCVEFinding("S3_BUCKET_PUBLIC_READ")

	if err := enricher.EnrichContext(context.Background(), finding); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if finding.Context.EPSSScore != 0 {
		t.Errorf("expected EPSSScore 0 for non-CVE finding, got %.4f", finding.Context.EPSSScore)
	}
	if finding.Context.InKEV {
		t.Error("expected InKEV false for non-CVE finding")
	}
	if finding.Context.EnvType != "sandbox" {
		t.Errorf("expected EnvType sandbox, got %s", finding.Context.EnvType)
	}
}

func TestCompositeEnricher_ProdEnv_MapsToTier1(t *testing.T) {
	env := &mockEnvClassifier{envType: "prod"}
	enricher := NewCompositeEnricher(nil, nil, env)
	finding := newCVEFinding("SOME_FINDING")

	_ = enricher.EnrichContext(context.Background(), finding)

	if finding.Context.AssetTier != "Tier1-Prod" {
		t.Errorf("expected Tier1-Prod for prod env, got %s", finding.Context.AssetTier)
	}
}

func TestCompositeEnricher_StagingEnv_MapsToTier2(t *testing.T) {
	env := &mockEnvClassifier{envType: "staging"}
	enricher := NewCompositeEnricher(nil, nil, env)
	finding := newCVEFinding("SOME_FINDING")

	_ = enricher.EnrichContext(context.Background(), finding)

	if finding.Context.AssetTier != "Tier2-NonProd" {
		t.Errorf("expected Tier2-NonProd for staging env, got %s", finding.Context.AssetTier)
	}
}

func TestCompositeEnricher_DevEnv_MapsToTier3(t *testing.T) {
	env := &mockEnvClassifier{envType: "dev"}
	enricher := NewCompositeEnricher(nil, nil, env)
	finding := newCVEFinding("SOME_FINDING")

	_ = enricher.EnrichContext(context.Background(), finding)

	if finding.Context.AssetTier != "Tier3-Dev" {
		t.Errorf("expected Tier3-Dev for dev env, got %s", finding.Context.AssetTier)
	}
}

func TestCompositeEnricher_SandboxEnv_MapsToTier3(t *testing.T) {
	env := &mockEnvClassifier{envType: "sandbox"}
	enricher := NewCompositeEnricher(nil, nil, env)
	finding := newCVEFinding("SOME_FINDING")

	_ = enricher.EnrichContext(context.Background(), finding)

	if finding.Context.AssetTier != "Tier3-Dev" {
		t.Errorf("expected Tier3-Dev for sandbox env, got %s", finding.Context.AssetTier)
	}
}

func TestCompositeEnricher_NilSources_NoopSafe(t *testing.T) {
	enricher := NewCompositeEnricher(nil, nil, nil)
	finding := newCVEFinding("CVE-2024-5678")

	if err := enricher.EnrichContext(context.Background(), finding); err != nil {
		t.Fatalf("unexpected error with nil sources: %v", err)
	}

	if finding.Context.EPSSScore != 0 {
		t.Error("expected zero EPSSScore with nil EPSS client")
	}
	if finding.Context.InKEV {
		t.Error("expected InKEV false with nil KEV catalog")
	}
	if finding.Context.EnvType != "" {
		t.Error("expected empty EnvType with nil env classifier")
	}
}

func TestCompositeEnricher_HighEPSSScore_SetsExploitInWild(t *testing.T) {
	epss := &mockEPSSClient{score: 0.85, percentile: 0.96}
	enricher := NewCompositeEnricher(epss, nil, nil)
	finding := newCVEFinding("CVE-2024-3333")

	_ = enricher.EnrichContext(context.Background(), finding)

	if !finding.Context.ExploitInWild {
		t.Error("expected ExploitInWild true for EPSS score > 0.5")
	}
	if !finding.Context.ExploitAvailable {
		t.Error("expected ExploitAvailable true for EPSS score > 0")
	}
}

func TestCompositeEnricher_LowEPSSScore_DoesNotSetExploitInWild(t *testing.T) {
	epss := &mockEPSSClient{score: 0.12, percentile: 0.45}
	enricher := NewCompositeEnricher(epss, nil, nil)
	finding := newCVEFinding("CVE-2024-7777")

	_ = enricher.EnrichContext(context.Background(), finding)

	if finding.Context.ExploitInWild {
		t.Error("expected ExploitInWild false for EPSS score <= 0.5")
	}
	if !finding.Context.ExploitAvailable {
		t.Error("expected ExploitAvailable true for EPSS score > 0")
	}
}

func TestCompositeEnricher_CaseInsensitiveCVEExtraction(t *testing.T) {
	epss := &mockEPSSClient{score: 0.5, percentile: 0.8}
	enricher := NewCompositeEnricher(epss, nil, nil)
	finding := newCVEFinding("cve-2023-44444")

	_ = enricher.EnrichContext(context.Background(), finding)

	if finding.Context.EPSSScore != 0.5 {
		t.Errorf("expected EPSS lookup for lowercase cve- prefix, got score %.4f", finding.Context.EPSSScore)
	}
}

// --- extractCVEID unit tests ---

func TestExtractCVEID_StandardFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CVE-2024-1234", "CVE-2024-1234"},
		{"CVE-2021-44228", "CVE-2021-44228"},
		{"PREFIX_CVE-2023-9999_SUFFIX", "CVE-2023-9999"},
		{"cve-2024-0001", "CVE-2024-0001"},
		{"S3_BUCKET_PUBLIC_READ", ""},
		{"", ""},
	}

	for _, tc := range tests {
		got := extractCVEID(tc.input)
		if got != tc.expected {
			t.Errorf("extractCVEID(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestExtractCVEID_LongCVENumber(t *testing.T) {
	got := extractCVEID("CVE-2021-44228") // Log4Shell
	if got != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %s", got)
	}
}

func TestExtractCVEID_EmbeddedInFindingType(t *testing.T) {
	got := extractCVEID("INSPECTOR_CVE-2024-99999_EC2")
	if got != "CVE-2024-99999" {
		t.Errorf("expected CVE-2024-99999, got %s", got)
	}
}

// --- envTypeToAssetTier unit tests ---

func TestEnvTypeToAssetTier_KnownMappings(t *testing.T) {
	tests := []struct {
		envType  string
		expected string
	}{
		{"prod", "Tier1-Prod"},
		{"production", "Tier1-Prod"},
		{"staging", "Tier2-NonProd"},
		{"stg", "Tier2-NonProd"},
		{"preprod", "Tier2-NonProd"},
		{"dev", "Tier3-Dev"},
		{"development", "Tier3-Dev"},
		{"sandbox", "Tier3-Dev"},
		{"test", "Tier3-Dev"},
		{"qa", "Tier3-Dev"},
		{"uat", "Tier3-Dev"},
		{"unknown-env", "Tier1-Prod"},
		{"", "Tier1-Prod"},
	}

	for _, tc := range tests {
		got := envTypeToAssetTier(tc.envType)
		if got != tc.expected {
			t.Errorf("envTypeToAssetTier(%q) = %q, want %q", tc.envType, got, tc.expected)
		}
	}
}
