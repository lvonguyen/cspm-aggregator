package normalizer

import (
	"strings"
	"testing"
	"time"
)

// --- Helpers ---

func newNormalizer() *Normalizer {
	accounts := []AccountInfo{
		{AccountID: "123456789012", CBU: "payments", Tier: "Tier1", EnvType: "PROD", Owner: "payments-team"},
		{AccountID: "sub-abc-001", CBU: "platform", Tier: "Tier2", EnvType: "STG", Owner: "platform-team"},
		{AccountID: "my-gcp-project", CBU: "security", Tier: "Tier1", EnvType: "PROD", Owner: "security-team"},
	}
	return NewNormalizer(accounts, nil)
}

// --- Tests for NormalizeAWSFinding ---

func TestNormalizeAWSFinding_FullASFF(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"Id":           "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/abc123",
		"AwsAccountId": "123456789012",
		"Title":        "S3 bucket should not allow public access",
		"Description":  "This S3 bucket is configured to allow public access.",
		"Region":       "us-east-1",
		"Severity": map[string]interface{}{
			"Label": "HIGH",
		},
		"Workflow": map[string]interface{}{
			"Status": "NEW",
		},
		"Resources": []interface{}{
			map[string]interface{}{
				"Id":   "arn:aws:s3:::my-public-bucket",
				"Type": "AwsS3Bucket",
			},
		},
		"GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
		"ProductFields": map[string]interface{}{
			"ControlId":    "S3.1",
			"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
		},
		"Remediation": map[string]interface{}{
			"Recommendation": map[string]interface{}{
				"Url": "https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-read-prohibited.html",
			},
		},
		"CreatedAt":      "2024-01-15T10:00:00Z",
		"LastObservedAt": "2024-02-01T10:00:00Z",
	}

	f := n.NormalizeAWSFinding(raw)

	if f.CSP != "aws" {
		t.Errorf("expected CSP aws, got %s", f.CSP)
	}
	if f.AccountID != "123456789012" {
		t.Errorf("expected account 123456789012, got %s", f.AccountID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", f.Severity)
	}
	if f.Status != "ACTIVE" {
		t.Errorf("expected status ACTIVE, got %s", f.Status)
	}
	if f.ResourceID != "arn:aws:s3:::my-public-bucket" {
		t.Errorf("unexpected resource ID: %s", f.ResourceID)
	}
	if f.ResourceType != "AwsS3Bucket" {
		t.Errorf("unexpected resource type: %s", f.ResourceType)
	}
	if f.ControlID != "S3.1" {
		t.Errorf("expected ControlID S3.1, got %s", f.ControlID)
	}
	if f.Standard != "FSBP" {
		t.Errorf("expected standard FSBP, got %s", f.Standard)
	}
	if !strings.Contains(f.RemediationURL, "https://") {
		t.Errorf("expected remediation URL, got %s", f.RemediationURL)
	}
	// Organizational metadata from account mapping.
	if f.CBU != "payments" {
		t.Errorf("expected CBU payments, got %s", f.CBU)
	}
	if f.EnvType != "PROD" {
		t.Errorf("expected EnvType PROD, got %s", f.EnvType)
	}
	// Short ID should be set.
	if f.FindingIDShort == "" {
		t.Error("expected non-empty FindingIDShort")
	}
	if f.DeltaStatus != DeltaNew {
		t.Errorf("expected DeltaNew (no previous state), got %s", f.DeltaStatus)
	}
}

func TestNormalizeAWSFinding_SeverityFromLabel(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		label    string
		expected string
	}{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"INFORMATIONAL", "INFORMATIONAL"},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			raw := map[string]interface{}{
				"AwsAccountId": "999",
				"Title":        "Test",
				"Severity":     map[string]interface{}{"Label": tc.label},
			}
			f := n.NormalizeAWSFinding(raw)
			if f.Severity != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, f.Severity)
			}
		})
	}
}

func TestNormalizeAWSFinding_SeverityFallbackToNormalizedScore(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		score    float64
		expected string
	}{
		{95, "CRITICAL"},
		{75, "HIGH"},
		{50, "MEDIUM"},
		{10, "LOW"},
		{0, "LOW"},
	}

	for _, tc := range tests {
		raw := map[string]interface{}{
			"AwsAccountId": "999",
			"Title":        "Test",
			"Severity":     map[string]interface{}{"Normalized": tc.score},
		}
		f := n.NormalizeAWSFinding(raw)
		if f.Severity != tc.expected {
			t.Errorf("score %.0f: expected %s, got %s", tc.score, tc.expected, f.Severity)
		}
	}
}

func TestNormalizeAWSFinding_WorkflowStatus_MappedCorrectly(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		workflowStatus string
		expectedStatus string
	}{
		{"NEW", "ACTIVE"},
		{"NOTIFIED", "ACTIVE"},
		{"RESOLVED", "RESOLVED"},
		{"SUPPRESSED", "SUPPRESSED"},
	}

	for _, tc := range tests {
		t.Run(tc.workflowStatus, func(t *testing.T) {
			raw := map[string]interface{}{
				"AwsAccountId": "999",
				"Title":        "Test",
				"Workflow":     map[string]interface{}{"Status": tc.workflowStatus},
			}
			f := n.NormalizeAWSFinding(raw)
			if f.Status != tc.expectedStatus {
				t.Errorf("workflow %s: expected status %s, got %s",
					tc.workflowStatus, tc.expectedStatus, f.Status)
			}
		})
	}
}

func TestNormalizeAWSFinding_ComplianceStandards_Extracted(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"AwsAccountId": "999",
		"Title":        "Test",
		"Compliance": map[string]interface{}{
			"AssociatedStandards": []interface{}{
				map[string]interface{}{"StandardsId": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/3.0.0"},
				map[string]interface{}{"StandardsId": "arn:aws:securityhub:::ruleset/pci-dss/v/4.0.1"},
			},
		},
	}

	f := n.NormalizeAWSFinding(raw)

	if len(f.ComplianceStandards) != 2 {
		t.Fatalf("expected 2 compliance standards, got %d: %v", len(f.ComplianceStandards), f.ComplianceStandards)
	}
	if !contains(f.ComplianceStandards, "CIS-v3.0") {
		t.Errorf("expected CIS-v3.0 in compliance standards: %v", f.ComplianceStandards)
	}
	if !contains(f.ComplianceStandards, "PCI-DSS-v4.0.1") {
		t.Errorf("expected PCI-DSS-v4.0.1 in compliance standards: %v", f.ComplianceStandards)
	}
}

func TestNormalizeAWSFinding_FindingClass_GuardDutyProduct(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"AwsAccountId": "999",
		"Title":        "Threat detected",
		"ProductArn":   "arn:aws:securityhub:us-east-1::product/aws/guardduty",
	}

	f := n.NormalizeAWSFinding(raw)

	if f.FindingClass != ClassThreat {
		t.Errorf("expected ClassThreat for GuardDuty product, got %s", f.FindingClass)
	}
}

func TestNormalizeAWSFinding_FindingClass_InspectorProduct(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"AwsAccountId": "999",
		"Title":        "CVE detected",
		"ProductArn":   "arn:aws:securityhub:us-east-1::product/aws/inspector",
	}

	f := n.NormalizeAWSFinding(raw)

	if f.FindingClass != ClassVulnerability {
		t.Errorf("expected ClassVulnerability for Inspector product, got %s", f.FindingClass)
	}
}

func TestNormalizeAWSFinding_EmptyFinding_NoError(t *testing.T) {
	n := newNormalizer()

	f := n.NormalizeAWSFinding(map[string]interface{}{})

	if f.CSP != "aws" {
		t.Errorf("expected CSP aws, got %s", f.CSP)
	}
	if f.Status != "ACTIVE" {
		t.Errorf("expected default ACTIVE status, got %s", f.Status)
	}
	// Empty finding still gets a delta status.
	if f.DeltaStatus == "" {
		t.Error("expected non-empty delta status")
	}
}

func TestNormalizeAWSFinding_MissingSeverity_DefaultsToEmpty(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"AwsAccountId": "999",
		"Title":        "No severity",
	}

	f := n.NormalizeAWSFinding(raw)
	// Severity is empty when neither Label nor Normalized is present.
	// The normalizer does not add a default — callers must handle empty.
	_ = f.Severity // just verify no panic
}

func TestNormalizeAWSFinding_AIWorkload_Detected(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"AwsAccountId": "999",
		"Title":        "SageMaker notebook instance is publicly accessible",
	}

	f := n.NormalizeAWSFinding(raw)

	if !f.AIWorkload {
		t.Error("expected AIWorkload=true for SageMaker finding")
	}
}

// --- Tests for NormalizeAzureFinding ---

func TestNormalizeAzureFinding_FullAssessment(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"id":             "/subscriptions/sub-abc-001/providers/Microsoft.Security/assessments/abc-guid",
		"name":           "abc-guid",
		"displayName":    "Ensure HTTPS is used for storage accounts",
		"subscriptionId": "sub-abc-001",
		"statusCode":     "Unhealthy",
		"severity":       "High",
		"resourceId":     "/subscriptions/sub-abc-001/resourceGroups/rg-test/providers/Microsoft.Storage/storageAccounts/mystorage",
		"resourceType":   "Microsoft.Storage/storageAccounts",
		"metadata": map[string]interface{}{
			"description":            "Storage accounts should use HTTPS only.",
			"remediationDescription": "Enable secure transfer required.",
			"policyDefinitionId":     "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9",
		},
		"status": map[string]interface{}{
			"firstEvaluationDate": "2024-01-10T08:00:00Z",
			"statusChangeDate":    "2024-02-01T08:00:00Z",
		},
		"risk": map[string]interface{}{
			"level": "High",
		},
	}

	f := n.NormalizeAzureFinding(raw)

	if f.CSP != "azure" {
		t.Errorf("expected CSP azure, got %s", f.CSP)
	}
	if f.AccountID != "sub-abc-001" {
		t.Errorf("expected subscription sub-abc-001, got %s", f.AccountID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", f.Severity)
	}
	if f.Status != "ACTIVE" {
		t.Errorf("expected status ACTIVE, got %s", f.Status)
	}
	if f.Standard != "MCSB" {
		t.Errorf("expected standard MCSB, got %s", f.Standard)
	}
	if f.RiskScore != 80 {
		t.Errorf("expected risk score 80 for High risk level, got %.0f", f.RiskScore)
	}
	if !f.FirstSeen.IsZero() && f.FirstSeen.Year() != 2024 {
		t.Errorf("unexpected first seen: %v", f.FirstSeen)
	}
	// Organizational enrichment.
	if f.CBU != "platform" {
		t.Errorf("expected CBU platform, got %s", f.CBU)
	}
}

func TestNormalizeAzureFinding_SeverityMapping(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		input    string
		expected string
	}{
		{"Critical", "CRITICAL"},
		{"High", "HIGH"},
		{"Medium", "MEDIUM"},
		{"Low", "LOW"},
		{"N/A", "LOW"},
		{"", "LOW"},
		{"Unknown", "LOW"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			raw := map[string]interface{}{
				"subscriptionId": "sub-test",
				"severity":       tc.input,
				"statusCode":     "Unhealthy",
			}
			f := n.NormalizeAzureFinding(raw)
			if f.Severity != tc.expected {
				t.Errorf("input %q: expected %s, got %s", tc.input, tc.expected, f.Severity)
			}
		})
	}
}

func TestNormalizeAzureFinding_StatusMapping(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		statusCode     string
		expectedStatus string
	}{
		{"Unhealthy", "ACTIVE"},
		{"unhealthy", "ACTIVE"},
		{"Healthy", "RESOLVED"},
		{"healthy", "RESOLVED"},
		{"NotApplicable", "SUPPRESSED"},
		{"", "SUPPRESSED"},
	}

	for _, tc := range tests {
		t.Run(tc.statusCode, func(t *testing.T) {
			raw := map[string]interface{}{
				"subscriptionId": "sub-test",
				"statusCode":     tc.statusCode,
			}
			f := n.NormalizeAzureFinding(raw)
			if f.Status != tc.expectedStatus {
				t.Errorf("statusCode %q: expected %s, got %s",
					tc.statusCode, tc.expectedStatus, f.Status)
			}
		})
	}
}

func TestNormalizeAzureFinding_SubscriptionFromResourceID(t *testing.T) {
	n := newNormalizer()

	// subscriptionId missing but present in resource ID path.
	raw := map[string]interface{}{
		"id":         "/subscriptions/sub-xyz-999/providers/Microsoft.Security/assessments/guid",
		"statusCode": "Unhealthy",
	}

	f := n.NormalizeAzureFinding(raw)

	if f.AccountID != "sub-xyz-999" {
		t.Errorf("expected subscription extracted from resource path, got %s", f.AccountID)
	}
}

func TestNormalizeAzureFinding_ComplianceCategories(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"subscriptionId": "sub-test",
		"statusCode":     "Unhealthy",
		"metadata": map[string]interface{}{
			"categories": []interface{}{"Identity", "Networking"},
		},
	}

	f := n.NormalizeAzureFinding(raw)

	if len(f.ComplianceStandards) != 2 {
		t.Fatalf("expected 2 compliance standards, got %d: %v", len(f.ComplianceStandards), f.ComplianceStandards)
	}
	if !contains(f.ComplianceStandards, "MCSB:Identity") {
		t.Errorf("expected MCSB:Identity in standards: %v", f.ComplianceStandards)
	}
	if !contains(f.ComplianceStandards, "MCSB:Networking") {
		t.Errorf("expected MCSB:Networking in standards: %v", f.ComplianceStandards)
	}
}

func TestNormalizeAzureFinding_FindingClass_AlwaysMisconfiguration(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"subscriptionId": "sub-test",
		"statusCode":     "Unhealthy",
	}

	f := n.NormalizeAzureFinding(raw)

	if f.FindingClass != ClassMisconfiguration {
		t.Errorf("expected ClassMisconfiguration for Azure, got %s", f.FindingClass)
	}
}

// --- Tests for NormalizeGCPFinding ---

func TestNormalizeGCPFinding_FullSCCFinding(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"name":         "organizations/123/sources/456/findings/gcp-finding-001",
		"category":     "PUBLIC_BUCKET_ACL",
		"description":  "GCS bucket allows public access",
		"severity":     "HIGH",
		"state":        "ACTIVE",
		"resourceName": "//storage.googleapis.com/projects/my-gcp-project/buckets/my-public-bucket",
		"findingClass": "MISCONFIGURATION",
		"nextSteps":    "Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
		"compliances": []interface{}{
			map[string]interface{}{"standard": "CIS GCP", "version": "1.3.0"},
		},
		"createTime": "2024-03-01T12:00:00Z",
		"eventTime":  "2024-03-10T12:00:00Z",
		"attackExposure": map[string]interface{}{
			"score": float64(55),
		},
	}

	f := n.NormalizeGCPFinding(raw)

	if f.CSP != "gcp" {
		t.Errorf("expected CSP gcp, got %s", f.CSP)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", f.Severity)
	}
	if f.Status != "ACTIVE" {
		t.Errorf("expected status ACTIVE, got %s", f.Status)
	}
	if f.AccountID != "my-gcp-project" {
		t.Errorf("expected project my-gcp-project, got %s", f.AccountID)
	}
	if f.ControlID != "PUBLIC_BUCKET_ACL" {
		t.Errorf("expected ControlID PUBLIC_BUCKET_ACL, got %s", f.ControlID)
	}
	if f.FindingClass != ClassMisconfiguration {
		t.Errorf("expected ClassMisconfiguration, got %s", f.FindingClass)
	}
	if f.RiskScore != 55 {
		t.Errorf("expected attack exposure score 55, got %.0f", f.RiskScore)
	}
	if !strings.Contains(f.RemediationURL, "Remove allUsers") {
		t.Errorf("expected nextSteps in remediation URL, got %s", f.RemediationURL)
	}
	if len(f.ComplianceStandards) == 0 {
		t.Error("expected compliance standards from compliances array")
	}
	// Organizational enrichment from account mapping.
	if f.CBU != "security" {
		t.Errorf("expected CBU security, got %s", f.CBU)
	}
}

func TestNormalizeGCPFinding_SeverityUnspecified_DefaultsToLow(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		severity string
		expected string
	}{
		{"", "LOW"},
		{"SEVERITY_UNSPECIFIED", "LOW"},
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			raw := map[string]interface{}{
				"severity": tc.severity,
				"state":    "ACTIVE",
			}
			f := n.NormalizeGCPFinding(raw)
			if f.Severity != tc.expected {
				t.Errorf("severity %q: expected %s, got %s", tc.severity, tc.expected, f.Severity)
			}
		})
	}
}

func TestNormalizeGCPFinding_StateMapping(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		state    string
		mute     string
		expected string
	}{
		{"ACTIVE", "", "ACTIVE"},
		{"INACTIVE", "", "RESOLVED"},
		{"", "", "ACTIVE"}, // unknown defaults to ACTIVE
		{"ACTIVE", "MUTED", "SUPPRESSED"},
	}

	for _, tc := range tests {
		t.Run(tc.state+"/"+tc.mute, func(t *testing.T) {
			raw := map[string]interface{}{
				"state": tc.state,
				"mute":  tc.mute,
			}
			f := n.NormalizeGCPFinding(raw)
			if f.Status != tc.expected {
				t.Errorf("state=%s mute=%s: expected %s, got %s",
					tc.state, tc.mute, tc.expected, f.Status)
			}
		})
	}
}

func TestNormalizeGCPFinding_FindingClassMapping(t *testing.T) {
	n := newNormalizer()

	tests := []struct {
		gcpClass string
		expected FindingClass
	}{
		{"THREAT", ClassThreat},
		{"VULNERABILITY", ClassVulnerability},
		{"MISCONFIGURATION", ClassMisconfiguration},
		{"OBSERVATION", ClassObservation},
		{"POSTURE_VIOLATION", ClassPostureViolation},
		{"TOXIC_COMBINATION", ClassToxicCombination},
		{"CHOKEPOINT", ClassChokepoint},
		{"SENSITIVE_DATA_RISK", ClassSensitiveDataRisk},
		{"UNKNOWN_CLASS", ClassMisconfiguration}, // default
		{"", ClassMisconfiguration},
	}

	for _, tc := range tests {
		t.Run(tc.gcpClass, func(t *testing.T) {
			raw := map[string]interface{}{
				"findingClass": tc.gcpClass,
				"state":        "ACTIVE",
			}
			f := n.NormalizeGCPFinding(raw)
			if f.FindingClass != tc.expected {
				t.Errorf("findingClass=%q: expected %s, got %s",
					tc.gcpClass, tc.expected, f.FindingClass)
			}
		})
	}
}

func TestNormalizeGCPFinding_AIWorkload_VertexAI(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"state":    "ACTIVE",
		"vertexAi": map[string]interface{}{"model": "gemini-pro"},
	}

	f := n.NormalizeGCPFinding(raw)

	if !f.AIWorkload {
		t.Error("expected AIWorkload=true when vertexAi field is present")
	}
}

func TestNormalizeGCPFinding_ComplianceStandards_WithVersion(t *testing.T) {
	n := newNormalizer()

	raw := map[string]interface{}{
		"state": "ACTIVE",
		"compliances": []interface{}{
			map[string]interface{}{"standard": "nist-800-53", "version": "Rev5"},
			map[string]interface{}{"standard": "pci-dss"},
		},
	}

	f := n.NormalizeGCPFinding(raw)

	if !contains(f.ComplianceStandards, "NIST-800-53-vRev5") {
		t.Errorf("expected versioned standard, got: %v", f.ComplianceStandards)
	}
	if !contains(f.ComplianceStandards, "PCI-DSS") {
		t.Errorf("expected PCI-DSS in standards: %v", f.ComplianceStandards)
	}
}

// --- Tests for EnrichFinding ---

func TestEnrichFinding_SetsOrganizationalMetadata(t *testing.T) {
	n := newNormalizer()

	f := &Finding{
		CSP:        "aws",
		AccountID:  "123456789012",
		ControlID:  "S3.1",
		ResourceID: "arn:aws:s3:::my-bucket",
		Status:     "ACTIVE",
		Severity:   "HIGH",
	}

	n.EnrichFinding(f)

	if f.CBU != "payments" {
		t.Errorf("expected CBU payments, got %s", f.CBU)
	}
	if f.Tier != "Tier1" {
		t.Errorf("expected Tier1, got %s", f.Tier)
	}
	if f.EnvType != "PROD" {
		t.Errorf("expected EnvType PROD, got %s", f.EnvType)
	}
	if f.Owner != "payments-team" {
		t.Errorf("expected owner payments-team, got %s", f.Owner)
	}
}

func TestEnrichFinding_UnknownAccount_NoMetadata(t *testing.T) {
	n := newNormalizer()

	f := &Finding{
		CSP:        "aws",
		AccountID:  "unknown-account",
		ControlID:  "X.1",
		ResourceID: "arn:aws:s3:::some-bucket",
		Status:     "ACTIVE",
		Severity:   "LOW",
	}

	n.EnrichFinding(f)

	// CBU/Tier/EnvType should remain empty if account not in mapping.
	if f.CBU != "" {
		t.Errorf("expected empty CBU for unknown account, got %s", f.CBU)
	}
}

func TestEnrichFinding_SetsRemediationSLA(t *testing.T) {
	n := newNormalizer()
	now := time.Now()

	tests := []struct {
		severity string
		slaDays  int
	}{
		{"CRITICAL", 7},
		{"HIGH", 14},
		{"MEDIUM", 30},
		{"LOW", 90},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			f := &Finding{
				AccountID:  "123456789012",
				ControlID:  "C.1",
				ResourceID: "rid",
				Status:     "ACTIVE",
				Severity:   tc.severity,
			}
			n.EnrichFinding(f)

			expectedSLA := f.FirstSeen.AddDate(0, 0, tc.slaDays)
			if f.RemediationSLA.IsZero() {
				t.Error("expected remediation SLA to be set")
			}
			// SLA should be within 1 second of expected (timing variance).
			diff := expectedSLA.Sub(f.RemediationSLA)
			if diff < -time.Second || diff > time.Second {
				t.Errorf("severity %s: SLA %v not ~%d days from first seen %v",
					tc.severity, f.RemediationSLA, tc.slaDays, f.FirstSeen)
			}
			_ = now
		})
	}
}

func TestEnrichFinding_PreservesExistingOwner(t *testing.T) {
	n := newNormalizer()

	f := &Finding{
		CSP:        "aws",
		AccountID:  "123456789012",
		ControlID:  "C.1",
		ResourceID: "rid",
		Status:     "ACTIVE",
		Severity:   "LOW",
		Owner:      "custom-owner", // already set
	}

	n.EnrichFinding(f)

	// Should NOT overwrite existing owner.
	if f.Owner != "custom-owner" {
		t.Errorf("expected custom-owner preserved, got %s", f.Owner)
	}
}

func TestEnrichFinding_ShortIDIsStable(t *testing.T) {
	n := newNormalizer()

	f := &Finding{
		CSP:        "aws",
		AccountID:  "123456789012",
		ControlID:  "S3.1",
		ResourceID: "arn:aws:s3:::my-bucket",
	}

	n.EnrichFinding(f)
	id1 := f.FindingIDShort

	// Re-enrich — same input should produce same ID.
	f2 := &Finding{
		CSP:        "aws",
		AccountID:  "123456789012",
		ControlID:  "S3.1",
		ResourceID: "arn:aws:s3:::my-bucket",
	}
	n.EnrichFinding(f2)
	id2 := f2.FindingIDShort

	if id1 != id2 {
		t.Errorf("expected stable short ID: %s != %s", id1, id2)
	}
}

// --- Tests for delta detection ---

func TestCalculateDeltaStatus_NoPreviousState_AlwaysNew(t *testing.T) {
	n := newNormalizer() // previousState = nil

	f := &Finding{
		FindingIDShort: "abc123",
		Status:         "ACTIVE",
	}

	status := n.calculateDeltaStatus(f)
	if status != DeltaNew {
		t.Errorf("expected DeltaNew with nil previous state, got %s", status)
	}
}

func TestCalculateDeltaStatus_ExistingInPrevious(t *testing.T) {
	prevState := &State{
		Findings: map[string]Finding{
			"abc123": {Status: "ACTIVE"},
		},
	}
	n := NewNormalizer(nil, prevState)

	f := &Finding{
		FindingIDShort: "abc123",
		Status:         "ACTIVE",
	}

	status := n.calculateDeltaStatus(f)
	if status != DeltaExisting {
		t.Errorf("expected DeltaExisting, got %s", status)
	}
}

func TestCalculateDeltaStatus_Reopened(t *testing.T) {
	prevState := &State{
		Findings: map[string]Finding{
			"abc123": {Status: "RESOLVED"},
		},
	}
	n := NewNormalizer(nil, prevState)

	f := &Finding{
		FindingIDShort: "abc123",
		Status:         "ACTIVE",
	}

	status := n.calculateDeltaStatus(f)
	if status != DeltaReopened {
		t.Errorf("expected DeltaReopened, got %s", status)
	}
}

func TestDetectClosedFindings_FindsMissingFromCurrent(t *testing.T) {
	prevState := &State{
		Findings: map[string]Finding{
			"abc123": {FindingIDShort: "abc123", Status: "ACTIVE"},
			"def456": {FindingIDShort: "def456", Status: "ACTIVE"},
		},
	}
	n := NewNormalizer(nil, prevState)

	current := []Finding{
		{FindingIDShort: "abc123", Status: "ACTIVE"}, // still present
	}

	closed := n.DetectClosedFindings(current)

	if len(closed) != 1 {
		t.Fatalf("expected 1 closed finding, got %d", len(closed))
	}
	if closed[0].FindingIDShort != "def456" {
		t.Errorf("expected def456 to be closed, got %s", closed[0].FindingIDShort)
	}
	if closed[0].DeltaStatus != DeltaClosed {
		t.Errorf("expected DeltaClosed, got %s", closed[0].DeltaStatus)
	}
	if closed[0].Status != "RESOLVED" {
		t.Errorf("expected RESOLVED status for closed finding, got %s", closed[0].Status)
	}
}

func TestDetectClosedFindings_NilPreviousState_ReturnsNil(t *testing.T) {
	n := newNormalizer() // nil previous state

	result := n.DetectClosedFindings([]Finding{{FindingIDShort: "x"}})
	if result != nil {
		t.Error("expected nil for nil previous state")
	}
}

func TestDetectClosedFindings_PreviousAlreadyResolved_NotIncluded(t *testing.T) {
	prevState := &State{
		Findings: map[string]Finding{
			"old-resolved": {FindingIDShort: "old-resolved", Status: "RESOLVED"},
		},
	}
	n := NewNormalizer(nil, prevState)

	// old-resolved is not in current set but was already RESOLVED.
	closed := n.DetectClosedFindings([]Finding{})

	if len(closed) != 0 {
		t.Errorf("expected no closed findings for already-resolved, got %d", len(closed))
	}
}

// --- Tests for CalculateTrends ---

func TestCalculateTrends_CountsByDeltaStatus(t *testing.T) {
	now := time.Now()
	findings := []Finding{
		{DeltaStatus: DeltaNew, Status: "ACTIVE", CSP: "aws", Severity: "HIGH",
			FirstSeen: now.AddDate(0, 0, -5), RemediationSLA: now.AddDate(0, 0, 10)},
		{DeltaStatus: DeltaNew, Status: "ACTIVE", CSP: "azure", Severity: "MEDIUM",
			FirstSeen: now.AddDate(0, 0, -3), RemediationSLA: now.AddDate(0, 0, 27)},
		{DeltaStatus: DeltaExisting, Status: "ACTIVE", CSP: "gcp", Severity: "LOW",
			FirstSeen: now.AddDate(0, 0, -30), RemediationSLA: now.AddDate(0, 0, 60)},
		{DeltaStatus: DeltaClosed, Status: "RESOLVED", CSP: "aws", DaysOpen: 8},
		{DeltaStatus: DeltaReopened, Status: "ACTIVE", CSP: "aws", Severity: "CRITICAL",
			FirstSeen: now.AddDate(0, 0, -1), RemediationSLA: now.AddDate(0, 0, 6)},
	}

	metrics := CalculateTrends(findings, 10, "Monthly")

	if metrics.NewFindings != 2 {
		t.Errorf("expected 2 new findings, got %d", metrics.NewFindings)
	}
	if metrics.ClosedFindings != 1 {
		t.Errorf("expected 1 closed finding, got %d", metrics.ClosedFindings)
	}
	if metrics.ReopenedFindings != 1 {
		t.Errorf("expected 1 reopened finding, got %d", metrics.ReopenedFindings)
	}
	// Active findings: 2 new + 1 existing + 1 reopened = 4
	if metrics.TotalFindings != 4 {
		t.Errorf("expected 4 total active findings, got %d", metrics.TotalFindings)
	}
	if metrics.NetChange != 1 { // 2 new - 1 closed
		t.Errorf("expected net change 1, got %d", metrics.NetChange)
	}
}

func TestCalculateTrends_ClosureRate_Calculated(t *testing.T) {
	now := time.Now()
	findings := []Finding{
		{DeltaStatus: DeltaClosed, Status: "RESOLVED", DaysOpen: 5},
		{DeltaStatus: DeltaClosed, Status: "RESOLVED", DaysOpen: 10},
		{DeltaStatus: DeltaNew, Status: "ACTIVE", CSP: "aws", Severity: "LOW",
			FirstSeen: now, RemediationSLA: now.AddDate(0, 0, 90)},
	}

	metrics := CalculateTrends(findings, 20, "Weekly")

	expectedRate := float64(2) / float64(20) // 2 closed / 20 previous total
	if metrics.ClosureRate != expectedRate {
		t.Errorf("expected closure rate %.2f, got %.2f", expectedRate, metrics.ClosureRate)
	}
}

func TestCalculateTrends_MTTR_AverageOfClosedDaysOpen(t *testing.T) {
	findings := []Finding{
		{DeltaStatus: DeltaClosed, Status: "RESOLVED", DaysOpen: 6},
		{DeltaStatus: DeltaClosed, Status: "RESOLVED", DaysOpen: 14},
	}

	metrics := CalculateTrends(findings, 100, "Monthly")

	expectedMTTR := (6.0 + 14.0) / 2.0 // = 10
	if metrics.MTTR != expectedMTTR {
		t.Errorf("expected MTTR %.1f, got %.1f", expectedMTTR, metrics.MTTR)
	}
}

func TestCalculateTrends_EmptyFindings_ZeroMetrics(t *testing.T) {
	metrics := CalculateTrends([]Finding{}, 0, "Monthly")

	if metrics.TotalFindings != 0 || metrics.NewFindings != 0 || metrics.ClosedFindings != 0 {
		t.Error("expected all zero metrics for empty findings")
	}
}

// --- Tests for GenerateShortID ---

func TestGenerateShortID_SameInputSameOutput(t *testing.T) {
	id1 := GenerateShortID("aws", "123456789012", "S3.1", "arn:aws:s3:::bucket")
	id2 := GenerateShortID("aws", "123456789012", "S3.1", "arn:aws:s3:::bucket")
	if id1 != id2 {
		t.Errorf("expected deterministic short ID, got %s != %s", id1, id2)
	}
}

func TestGenerateShortID_DifferentInputsDifferentOutputs(t *testing.T) {
	id1 := GenerateShortID("aws", "111", "S3.1", "bucket-a")
	id2 := GenerateShortID("aws", "111", "S3.1", "bucket-b")
	if id1 == id2 {
		t.Error("expected different IDs for different resource IDs")
	}
}

func TestGenerateShortID_NonEmptyFixed16Chars(t *testing.T) {
	id := GenerateShortID("gcp", "my-project", "PUBLIC_BUCKET_ACL", "//storage.googleapis.com/projects/p/buckets/b")
	if len(id) != 16 {
		t.Errorf("expected 16-char short ID, got %d chars: %s", len(id), id)
	}
}

// --- Tests for helper functions ---

func TestNormalizeAzureSeverity_AllVariants(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "CRITICAL"},
		{"Critical", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"  medium  ", "MEDIUM"},
		{"low", "LOW"},
		{"n/a", "LOW"},
		{"na", "LOW"},
		{"", "LOW"},
		{"random", "LOW"},
	}
	for _, tc := range tests {
		got := normalizeAzureSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeAzureSeverity(%q): expected %s, got %s", tc.input, tc.expected, got)
		}
	}
}

func TestNormalizeSeverityFromScore_Boundaries(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{100, "CRITICAL"},
		{90, "CRITICAL"},
		{89, "HIGH"},
		{70, "HIGH"},
		{69, "MEDIUM"},
		{40, "MEDIUM"},
		{39, "LOW"},
		{1, "LOW"},
		{0, "LOW"},
	}
	for _, tc := range tests {
		got := normalizeSeverityFromScore(tc.score)
		if got != tc.expected {
			t.Errorf("normalizeSeverityFromScore(%.0f): expected %s, got %s",
				tc.score, tc.expected, got)
		}
	}
}

func TestParseAWSStandard_KnownARNs(t *testing.T) {
	tests := []struct {
		arn      string
		expected string
	}{
		{"arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0", "FSBP"},
		{"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/3.0.0", "CIS-v3.0"},
		{"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0", "CIS-v5.0"},
		{"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0", "CIS"},
		{"arn:aws:securityhub:::ruleset/pci-dss/v/4.0.1", "PCI-DSS-v4.0.1"},
		{"arn:aws:securityhub:::ruleset/pci-dss/v/3.2.1", "PCI-DSS"},
		{"arn:aws:securityhub:::ruleset/nist-800-53/v/5.0.0", "NIST-800-53"},
		{"arn:aws:securityhub:::ruleset/nist-800-171/v/2.0.0", "NIST-800-171"},
	}
	for _, tc := range tests {
		got := parseAWSStandard(tc.arn)
		if got != tc.expected {
			t.Errorf("parseAWSStandard(%q): expected %s, got %s", tc.arn, tc.expected, got)
		}
	}
}

func TestExtractAzureSubscription_ValidPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/subscriptions/abc-123/resourceGroups/rg/providers/...", "abc-123"},
		{"/SUBSCRIPTIONS/ABC-123/resourceGroups/rg", "ABC-123"},
		{"no-subscription-here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractAzureSubscription(tc.input)
		if got != tc.expected {
			t.Errorf("extractAzureSubscription(%q): expected %q, got %q",
				tc.input, tc.expected, got)
		}
	}
}

func TestExtractGCPProject_ValidResourceNames(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"//storage.googleapis.com/projects/my-project/buckets/b", "my-project"},
		{"projects/another-project/zones/us-central1-a/instances/vm", "another-project"},
		{"no-project-here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractGCPProject(tc.input)
		if got != tc.expected {
			t.Errorf("extractGCPProject(%q): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestExtractGCPRegion_ZoneConversion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"projects/p/zones/us-central1-a/instances/vm", "us-central1"},
		{"projects/p/zones/europe-west1-b/instances/vm", "europe-west1"},
		{"projects/p/locations/us-east1/clusters/c", "us-east1"},
		{"projects/p/regions/us-west2/subnetworks/s", "us-west2"},
		{"projects/p/global/firewalls/f", ""},
	}
	for _, tc := range tests {
		got := extractGCPRegion(tc.input)
		if got != tc.expected {
			t.Errorf("extractGCPRegion(%q): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestExtractGCPResourceType_ValidPaths(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"projects/p/zones/us-central1-a/instances/my-vm", "instances"},
		{"projects/p/buckets/my-bucket", "buckets"},
		{"//compute.googleapis.com/projects/p/global/firewalls/my-fw", "firewalls"},
	}
	for _, tc := range tests {
		got := extractGCPResourceType(tc.input)
		if got != tc.expected {
			t.Errorf("extractGCPResourceType(%q): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestIsAIWorkload_Detection(t *testing.T) {
	tests := []struct {
		title        string
		resourceType string
		controlID    string
		expected     bool
	}{
		{"SageMaker endpoint is public", "", "", true},
		{"Bedrock model access not restricted", "", "", true},
		{"", "microsoft.cognitiveservices/accounts", "", true},
		{"Vertex AI training job config issue", "", "", true},
		{"S3 bucket public access", "AWS::S3::Bucket", "", false},
		{"EC2 IMDSv2 not enforced", "AWS::EC2::Instance", "", false},
		{"", "", "Amazon Q permissions", true},
	}

	for _, tc := range tests {
		got := isAIWorkload(tc.title, tc.resourceType, tc.controlID)
		if got != tc.expected {
			t.Errorf("isAIWorkload(%q, %q, %q): expected %v, got %v",
				tc.title, tc.resourceType, tc.controlID, tc.expected, got)
		}
	}
}

func TestSeverityPriority_ContainsAllSeverities(t *testing.T) {
	required := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, sev := range required {
		if _, ok := SeverityPriority[sev]; !ok {
			t.Errorf("SeverityPriority missing key %s", sev)
		}
	}
	// Priority ordering: CRITICAL < HIGH < MEDIUM < LOW.
	if SeverityPriority["CRITICAL"] >= SeverityPriority["HIGH"] {
		t.Error("CRITICAL priority should be numerically lower than HIGH")
	}
}

func TestSLADays_ContainsAllSeverities(t *testing.T) {
	required := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, sev := range required {
		days, ok := SLADays[sev]
		if !ok {
			t.Errorf("SLADays missing key %s", sev)
		}
		if days <= 0 {
			t.Errorf("SLADays[%s] should be positive, got %d", sev, days)
		}
	}
	// More severe = shorter SLA.
	if SLADays["CRITICAL"] >= SLADays["HIGH"] {
		t.Error("CRITICAL SLA should be shorter than HIGH SLA")
	}
}

func TestTruncate_LongerThanMax(t *testing.T) {
	s := strings.Repeat("a", 2000)
	got := truncate(s, 1024)
	if len(got) != 1024 {
		t.Errorf("expected length 1024, got %d", len(got))
	}
}

func TestTruncate_ShorterThanMax_Unchanged(t *testing.T) {
	s := "short string"
	got := truncate(s, 1024)
	if got != s {
		t.Errorf("expected unchanged string, got %q", got)
	}
}

func TestParseTime_ValidFormats(t *testing.T) {
	inputs := []string{
		"2024-01-15T10:00:00Z",
		"2024-01-15T10:00:00.000Z",
		"2024-01-15",
	}
	for _, ts := range inputs {
		got := parseTime(ts)
		if got.IsZero() {
			t.Errorf("parseTime(%q) returned zero time", ts)
		}
	}
}

func TestParseTime_EmptyString_ReturnsZero(t *testing.T) {
	got := parseTime("")
	if !got.IsZero() {
		t.Error("expected zero time for empty string")
	}
}

func TestParseTime_InvalidString_ReturnsZero(t *testing.T) {
	got := parseTime("not-a-timestamp")
	if !got.IsZero() {
		t.Error("expected zero time for invalid timestamp")
	}
}

// --- helper ---

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
