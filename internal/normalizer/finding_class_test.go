package normalizer

import "testing"

// --- MapGCPFindingClass ---

func TestMapGCPFindingClass_AllBaseClasses(t *testing.T) {
	tests := []struct {
		gcpClass string
		expected FindingClass
	}{
		{"THREAT", ClassThreat},
		{"threat", ClassThreat},
		{"VULNERABILITY", ClassVulnerability},
		{"MISCONFIGURATION", ClassMisconfiguration},
		{"OBSERVATION", ClassObservation},
		{"POSTURE_VIOLATION", ClassPostureViolation},
		{"TOXIC_COMBINATION", ClassToxicCombination},
		{"CHOKEPOINT", ClassChokepoint},
		{"SENSITIVE_DATA_RISK", ClassSensitiveDataRisk},
		{"SCC_ERROR", ClassObservation},
		{"UNKNOWN", ClassMisconfiguration},
		{"", ClassMisconfiguration},
	}
	for _, tc := range tests {
		t.Run(tc.gcpClass, func(t *testing.T) {
			got := MapGCPFindingClass(tc.gcpClass)
			if got != tc.expected {
				t.Errorf("MapGCPFindingClass(%q): want %s, got %s", tc.gcpClass, tc.expected, got)
			}
		})
	}
}

// --- MapAWSFindingType ---

func TestMapAWSFindingType_Mappings(t *testing.T) {
	tests := []struct {
		awsType  string
		expected FindingClass
	}{
		{"TTPs/Privilege Escalation/AWS-iam-privilege-escalation", ClassPrivilegeEscalation},
		{"TTPs/Initial Access/Backdoor", ClassThreat},
		{"Unusual Behaviors/VM/Crypto Mining", ClassResourceAnomaly},
		{"Effects/Data Exfiltration", ClassThreat},
		{"Sensitive Data Identifications/PII", ClassSensitiveDataRisk},
		{"Software and Configuration Checks/Vulnerabilities/CVE/CVE-2024-1234", ClassVulnerability},
		{"Software and Configuration Checks/Industry and Regulatory Standards/CIS", ClassMisconfiguration},
		{"", ClassMisconfiguration},
		{"Unknown/Random/Type", ClassMisconfiguration},
	}
	for _, tc := range tests {
		t.Run(tc.awsType, func(t *testing.T) {
			got := MapAWSFindingType(tc.awsType)
			if got != tc.expected {
				t.Errorf("MapAWSFindingType(%q): want %s, got %s", tc.awsType, tc.expected, got)
			}
		})
	}
}

// --- MapAzureAlertType ---

func TestMapAzureAlertType_Mappings(t *testing.T) {
	tests := []struct {
		azureType string
		expected  FindingClass
	}{
		{"Threat", ClassThreat},
		{"threat", ClassThreat},
		{"IdentityAndAccess", ClassIAMMisconfiguration},
		{"identityandaccess", ClassIAMMisconfiguration},
		{"Identity", ClassIAMMisconfiguration},
		{"Networking", ClassNetworkExposure},
		{"networking", ClassNetworkExposure},
		{"Data", ClassDataExposure},
		{"data", ClassDataExposure},
		{"IoT", ClassObservation},
		{"iot", ClassObservation},
		{"Compute", ClassMisconfiguration},
		{"compute", ClassMisconfiguration},
		{"", ClassMisconfiguration},
		{"UnknownCategory", ClassMisconfiguration},
	}
	for _, tc := range tests {
		t.Run(tc.azureType, func(t *testing.T) {
			got := MapAzureAlertType(tc.azureType)
			if got != tc.expected {
				t.Errorf("MapAzureAlertType(%q): want %s, got %s", tc.azureType, tc.expected, got)
			}
		})
	}
}

// --- SubClassifyGCPVulnerability heuristics ---

func TestSubClassifyGCPVulnerability_Heuristics(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		title        string
		description  string
		expected     FindingClass
	}{
		{
			name:         "container_resource_gke",
			resourceType: "google.container.Cluster",
			title:        "Vulnerable container image detected",
			expected:     ClassContainerVulnerability,
		},
		{
			name:         "container_eks",
			resourceType: "aws.eks.nodegroup",
			title:        "Base image CVE",
			expected:     ClassContainerVulnerability,
		},
		{
			name:         "container_kubernetes",
			resourceType: "k8s.Pod",
			title:        "CVE in image",
			expected:     ClassContainerVulnerability,
		},
		{
			name:         "os_vulnerability_vm_cve",
			resourceType: "google.compute.Instance",
			title:        "CVE-2023-4911 in glibc package",
			expected:     ClassOSVulnerability,
		},
		{
			name:         "os_vulnerability_vm_kernel",
			resourceType: "AwsEc2Instance",
			title:        "Kernel vulnerability detected",
			expected:     ClassOSVulnerability,
		},
		{
			name:         "iam_misconfiguration_wildcard",
			resourceType: "google.iam.ServiceAccount",
			title:        "Overprivileged IAM role with wildcard permissions",
			expected:     ClassIAMMisconfiguration,
		},
		{
			name:         "iam_policy_stale_key",
			resourceType: "aws.iam.User",
			title:        "Stale access key detected",
			expected:     ClassIAMMisconfiguration,
		},
		{
			name:         "identity_risk_mfa",
			resourceType: "google.iam.User",
			title:        "MFA not enabled for service account",
			expected:     ClassIdentityRisk,
		},
		{
			name:         "identity_risk_federation",
			resourceType: "azure.ad.Application",
			title:        "Federation misconfiguration in identity provider",
			expected:     ClassIdentityRisk,
		},
		{
			name:         "privilege_escalation",
			resourceType: "google.iam.Role",
			title:        "IAM privilege escalation path via role chaining",
			expected:     ClassPrivilegeEscalation,
		},
		{
			name:         "network_exposure_open_port",
			resourceType: "google.compute.Firewall",
			title:        "Port 22 exposed to internet (0.0.0.0/0)",
			expected:     ClassNetworkExposure,
		},
		{
			name:         "network_exposure_public_endpoint",
			resourceType: "google.compute.ForwardingRule",
			title:        "Public endpoint with no WAF",
			expected:     ClassNetworkExposure,
		},
		{
			name:         "data_exposure_public_bucket",
			resourceType: "storage.Bucket",
			title:        "GCS bucket is publicly accessible",
			expected:     ClassDataExposure,
		},
		{
			name:         "data_exposure_s3",
			resourceType: "AWS::S3::Bucket",
			title:        "S3 bucket allows public read",
			expected:     ClassDataExposure,
		},
		{
			name:         "encryption_weakness_unencrypted",
			resourceType: "google.compute.Disk",
			title:        "Disk is unencrypted at rest",
			expected:     ClassEncryptionWeakness,
		},
		{
			name:         "encryption_weakness_tls",
			resourceType: "aws.elasticloadbalancing.Listener",
			title:        "TLS 1.0 in use — weak cipher configuration",
			expected:     ClassEncryptionWeakness,
		},
		{
			name:         "supply_chain_risk",
			resourceType: "",
			title:        "Supply chain risk: dependency confusion attack detected",
			expected:     ClassSupplyChainRisk,
		},
		{
			name:         "runtime_vulnerability_jvm",
			resourceType: "aws.lambda.Function",
			title:        "JVM CVE-2023-21954 vulnerability detected",
			expected:     ClassRuntimeVulnerability,
		},
		{
			name:         "runtime_vulnerability_nodejs",
			resourceType: "aws.lambda.Function",
			title:        "Node.js runtime version vulnerable",
			description:  "outdated version with CVE",
			expected:     ClassRuntimeVulnerability,
		},
		{
			name:         "application_vulnerability_npm",
			resourceType: "aws.lambda.Function",
			title:        "npm dependency outdated CVE",
			expected:     ClassApplicationVulnerability,
		},
		{
			name:         "application_vulnerability_pip",
			resourceType: "",
			title:        "pip package vulnerability",
			description:  "CVE detected in outdated dependency",
			expected:     ClassApplicationVulnerability,
		},
		{
			name:         "fallback_generic_vulnerability",
			resourceType: "",
			title:        "Some generic CVE finding",
			expected:     ClassVulnerability,
		},
		{
			name:         "all_empty_fallback",
			resourceType: "",
			title:        "",
			description:  "",
			expected:     ClassVulnerability,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SubClassifyGCPVulnerability(tc.resourceType, tc.title, tc.description)
			if got != tc.expected {
				t.Errorf("SubClassifyGCPVulnerability(%q, %q, %q): want %s, got %s",
					tc.resourceType, tc.title, tc.description, tc.expected, got)
			}
		})
	}
}

// --- SubClassifyVulnerability (generic, same engine) ---

func TestSubClassifyVulnerability_SameEngineAsGCP(t *testing.T) {
	// SubClassifyVulnerability and SubClassifyGCPVulnerability use the same
	// heuristic engine — verify they produce identical results.
	resourceType := "google.compute.Instance"
	title := "CVE in OS kernel package"
	description := "kernel vulnerability"

	got1 := SubClassifyGCPVulnerability(resourceType, title, description)
	got2 := SubClassifyVulnerability(resourceType, title, description)
	if got1 != got2 {
		t.Errorf("SubClassifyGCPVulnerability and SubClassifyVulnerability diverge: %s vs %s", got1, got2)
	}
	if got1 != ClassOSVulnerability {
		t.Errorf("expected ClassOSVulnerability, got %s", got1)
	}
}

// --- ClassMetadata ---

func TestClassMetadata_AllClasses(t *testing.T) {
	allClasses := []FindingClass{
		ClassThreat,
		ClassVulnerability,
		ClassMisconfiguration,
		ClassObservation,
		ClassPostureViolation,
		ClassToxicCombination,
		ClassChokepoint,
		ClassSensitiveDataRisk,
		ClassOSVulnerability,
		ClassRuntimeVulnerability,
		ClassContainerVulnerability,
		ClassApplicationVulnerability,
		ClassSupplyChainRisk,
		ClassIAMMisconfiguration,
		ClassIdentityRisk,
		ClassPrivilegeEscalation,
		ClassNetworkExposure,
		ClassDataExposure,
		ClassEncryptionWeakness,
		ClassComplianceDrift,
		ClassResourceAnomaly,
	}

	for _, class := range allClasses {
		t.Run(string(class), func(t *testing.T) {
			info := ClassMetadata(class)
			if info.Category == "" {
				t.Errorf("ClassMetadata(%s): Category is empty", class)
			}
			if info.Description == "" {
				t.Errorf("ClassMetadata(%s): Description is empty", class)
			}
			if info.DefaultSeverityWeight <= 0 {
				t.Errorf("ClassMetadata(%s): DefaultSeverityWeight must be > 0, got %f", class, info.DefaultSeverityWeight)
			}
			if info.CSPMappings == nil {
				t.Errorf("ClassMetadata(%s): CSPMappings is nil", class)
			}
		})
	}
}

func TestClassMetadata_UnknownClass_ReturnsZero(t *testing.T) {
	info := ClassMetadata(FindingClass("BOGUS_CLASS"))
	if info.Category != "" {
		t.Errorf("expected zero Category for unknown class, got %q", info.Category)
	}
	if info.Description != "" {
		t.Errorf("expected empty Description for unknown class, got %q", info.Description)
	}
}

func TestClassMetadata_SpecificValues(t *testing.T) {
	tests := []struct {
		class            FindingClass
		wantCategory     FindingClassCategory
		wantWeightAtLeast float64
	}{
		{ClassThreat, CategoryThreat, 1.3},
		{ClassToxicCombination, CategoryThreat, 1.5},
		{ClassPrivilegeEscalation, CategoryIdentity, 1.4},
		{ClassDataExposure, CategoryData, 1.2},
		{ClassNetworkExposure, CategoryNetwork, 1.1},
		{ClassVulnerability, CategoryVulnerability, 1.0},
		{ClassComplianceDrift, CategoryCompliance, 0.9},
	}
	for _, tc := range tests {
		t.Run(string(tc.class), func(t *testing.T) {
			info := ClassMetadata(tc.class)
			if info.Category != tc.wantCategory {
				t.Errorf("ClassMetadata(%s).Category: want %s, got %s", tc.class, tc.wantCategory, info.Category)
			}
			if info.DefaultSeverityWeight < tc.wantWeightAtLeast {
				t.Errorf("ClassMetadata(%s).DefaultSeverityWeight: want >= %f, got %f",
					tc.class, tc.wantWeightAtLeast, info.DefaultSeverityWeight)
			}
		})
	}
}

func TestClassMetadata_MITRETactics_ValidFormat(t *testing.T) {
	// Classes that represent active threats/escalation must have MITRE tactics
	threatClasses := []FindingClass{
		ClassThreat,
		ClassPrivilegeEscalation,
		ClassToxicCombination,
		ClassChokepoint,
		ClassResourceAnomaly,
	}
	for _, class := range threatClasses {
		t.Run(string(class), func(t *testing.T) {
			info := ClassMetadata(class)
			if len(info.MITRETactics) == 0 {
				t.Errorf("ClassMetadata(%s): expected non-empty MITRETactics for threat class", class)
			}
			for _, tactic := range info.MITRETactics {
				if len(tactic) < 4 || tactic[:2] != "TA" {
					t.Errorf("ClassMetadata(%s): tactic %q does not match TA#### format", class, tactic)
				}
			}
		})
	}
}

// --- Backward compatibility: existing classes still resolve correctly ---

func TestBackwardCompatibility_BaseClassConstants(t *testing.T) {
	// Verify all original FindingClass string values are unchanged
	checks := map[FindingClass]string{
		ClassThreat:            "THREAT",
		ClassVulnerability:     "VULNERABILITY",
		ClassMisconfiguration:  "MISCONFIGURATION",
		ClassObservation:       "OBSERVATION",
		ClassPostureViolation:  "POSTURE_VIOLATION",
		ClassToxicCombination:  "TOXIC_COMBINATION",
		ClassChokepoint:        "CHOKEPOINT",
		ClassSensitiveDataRisk: "SENSITIVE_DATA_RISK",
	}
	for class, want := range checks {
		if string(class) != want {
			t.Errorf("FindingClass constant changed: want %q, got %q", want, string(class))
		}
	}
}

func TestBackwardCompatibility_NewSubClassValues(t *testing.T) {
	checks := map[FindingClass]string{
		ClassOSVulnerability:          "OS_VULNERABILITY",
		ClassRuntimeVulnerability:     "RUNTIME_VULNERABILITY",
		ClassContainerVulnerability:   "CONTAINER_VULNERABILITY",
		ClassApplicationVulnerability: "APPLICATION_VULNERABILITY",
		ClassSupplyChainRisk:          "SUPPLY_CHAIN_RISK",
		ClassIAMMisconfiguration:      "IAM_MISCONFIGURATION",
		ClassIdentityRisk:             "IDENTITY_RISK",
		ClassPrivilegeEscalation:      "PRIVILEGE_ESCALATION",
		ClassNetworkExposure:          "NETWORK_EXPOSURE",
		ClassDataExposure:             "DATA_EXPOSURE",
		ClassEncryptionWeakness:       "ENCRYPTION_WEAKNESS",
		ClassComplianceDrift:          "COMPLIANCE_DRIFT",
		ClassResourceAnomaly:          "RESOURCE_ANOMALY",
	}
	for class, want := range checks {
		if string(class) != want {
			t.Errorf("FindingClass constant value wrong: want %q, got %q", want, string(class))
		}
	}
}

func TestBackwardCompatibility_FindingClassCategoryValues(t *testing.T) {
	checks := map[FindingClassCategory]string{
		CategoryVulnerability: "VULNERABILITY",
		CategoryIdentity:      "IDENTITY",
		CategoryNetwork:       "NETWORK",
		CategoryData:          "DATA",
		CategoryCompliance:    "COMPLIANCE",
		CategoryThreat:        "THREAT",
	}
	for cat, want := range checks {
		if string(cat) != want {
			t.Errorf("FindingClassCategory constant value wrong: want %q, got %q", want, string(cat))
		}
	}
}

// --- Integration: NormalizeGCPFinding sub-classification ---

func TestNormalizeGCPFinding_VulnerabilitySubClassified_Container(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"findingClass": "VULNERABILITY",
		"category":     "CONTAINER_CVE",
		"state":        "ACTIVE",
		"resourceName": "//container.googleapis.com/projects/p/zones/us-central1-a/clusters/my-cluster",
		"description":  "CVE detected in GKE container image",
	}
	f := n.NormalizeGCPFinding(raw)
	if f.FindingClass != ClassContainerVulnerability {
		t.Errorf("expected ClassContainerVulnerability for GKE finding, got %s", f.FindingClass)
	}
}

func TestNormalizeGCPFinding_VulnerabilitySubClassified_OSInstance(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"findingClass": "VULNERABILITY",
		"category":     "OS_CVE_ACTIVE",
		"state":        "ACTIVE",
		"resourceName": "//compute.googleapis.com/projects/p/zones/us-central1-a/instances/my-vm",
		"description":  "CVE in OS kernel package on compute instance",
	}
	f := n.NormalizeGCPFinding(raw)
	if f.FindingClass != ClassOSVulnerability {
		t.Errorf("expected ClassOSVulnerability for compute instance OS CVE, got %s", f.FindingClass)
	}
}

func TestNormalizeGCPFinding_VulnerabilitySubClassified_DataExposure(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"findingClass": "VULNERABILITY",
		"state":        "ACTIVE",
		"resourceName": "//storage.googleapis.com/projects/p/buckets/my-bucket",
		"category":     "PUBLIC_BUCKET",
		"description":  "GCS bucket is publicly accessible",
	}
	f := n.NormalizeGCPFinding(raw)
	if f.FindingClass != ClassDataExposure {
		t.Errorf("expected ClassDataExposure for public bucket VULNERABILITY, got %s", f.FindingClass)
	}
}

func TestNormalizeGCPFinding_VulnerabilitySubClassified_NetworkExposure(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"findingClass": "VULNERABILITY",
		"state":        "ACTIVE",
		"category":     "OPEN_SSH_PORT",
		"description":  "Port 22 open endpoint exposed to internet (0.0.0.0/0)",
	}
	f := n.NormalizeGCPFinding(raw)
	if f.FindingClass != ClassNetworkExposure {
		t.Errorf("expected ClassNetworkExposure for open port VULNERABILITY, got %s", f.FindingClass)
	}
}

func TestNormalizeGCPFinding_VulnerabilitySubClassified_IAM(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"findingClass": "VULNERABILITY",
		"state":        "ACTIVE",
		"category":     "IAM_POLICY_EXCESSIVE",
		"description":  "IAM role has overly permissive policy with wildcard permissions",
	}
	f := n.NormalizeGCPFinding(raw)
	if f.FindingClass != ClassIAMMisconfiguration {
		t.Errorf("expected ClassIAMMisconfiguration for IAM policy VULNERABILITY, got %s", f.FindingClass)
	}
}

func TestNormalizeGCPFinding_VulnerabilitySubClassified_Encryption(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"findingClass": "VULNERABILITY",
		"state":        "ACTIVE",
		"category":     "UNENCRYPTED_DISK",
		"description":  "Disk has no encryption at rest configured",
	}
	f := n.NormalizeGCPFinding(raw)
	if f.FindingClass != ClassEncryptionWeakness {
		t.Errorf("expected ClassEncryptionWeakness for unencrypted disk VULNERABILITY, got %s", f.FindingClass)
	}
}

// --- Integration: NormalizeAzureFinding with category-driven sub-classification ---

func TestNormalizeAzureFinding_FindingClass_CategoryNetworking(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"subscriptionId": "sub-001",
		"statusCode":     "Unhealthy",
		"displayName":    "Open management port",
		"metadata": map[string]interface{}{
			"severity":   "High",
			"categories": []interface{}{"Networking"},
		},
	}
	f := n.NormalizeAzureFinding(raw)
	if f.FindingClass != ClassNetworkExposure {
		t.Errorf("expected ClassNetworkExposure for Networking category, got %s", f.FindingClass)
	}
}

func TestNormalizeAzureFinding_FindingClass_CategoryIdentity(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"subscriptionId": "sub-001",
		"statusCode":     "Unhealthy",
		"displayName":    "MFA not enabled",
		"metadata": map[string]interface{}{
			"severity":   "High",
			"categories": []interface{}{"IdentityAndAccess"},
		},
	}
	f := n.NormalizeAzureFinding(raw)
	if f.FindingClass != ClassIAMMisconfiguration {
		t.Errorf("expected ClassIAMMisconfiguration for IdentityAndAccess category, got %s", f.FindingClass)
	}
}

func TestNormalizeAzureFinding_FindingClass_CategoryData(t *testing.T) {
	n := newNormalizer()
	raw := map[string]interface{}{
		"subscriptionId": "sub-001",
		"statusCode":     "Unhealthy",
		"displayName":    "Storage account public access",
		"metadata": map[string]interface{}{
			"severity":   "High",
			"categories": []interface{}{"Data"},
		},
	}
	f := n.NormalizeAzureFinding(raw)
	if f.FindingClass != ClassDataExposure {
		t.Errorf("expected ClassDataExposure for Data category, got %s", f.FindingClass)
	}
}

func TestNormalizeAzureFinding_FindingClass_NoCategory_Heuristic(t *testing.T) {
	// Without a category, heuristic sub-classification from title+description applies.
	// An empty title/description yields ClassMisconfiguration as the fallback.
	n := newNormalizer()
	raw := map[string]interface{}{
		"subscriptionId": "sub-001",
		"statusCode":     "Unhealthy",
	}
	f := n.NormalizeAzureFinding(raw)
	if f.FindingClass != ClassMisconfiguration {
		t.Errorf("expected ClassMisconfiguration for empty Azure finding, got %s", f.FindingClass)
	}
}
