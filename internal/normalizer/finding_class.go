package normalizer

import "strings"

// ClassMetadata returns metadata for a given FindingClass.
// Returns a zero-value ClassInfo for unknown classes.
func ClassMetadata(class FindingClass) ClassInfo {
	switch class {
	// --- Base classes ---
	case ClassThreat:
		return ClassInfo{
			Category:              CategoryThreat,
			DefaultSeverityWeight: 1.4,
			Description:           "Active attack or exploitation in progress",
			MITRETactics:          []string{"TA0001", "TA0002", "TA0003", "TA0040"},
			CSPMappings: map[string]string{
				"gcp":   "THREAT",
				"aws":   "TTPs",
				"azure": "Threat",
			},
		}
	case ClassVulnerability:
		return ClassInfo{
			Category:              CategoryVulnerability,
			DefaultSeverityWeight: 1.2,
			Description:           "Known vulnerability requiring remediation",
			MITRETactics:          []string{"TA0001", "TA0002"},
			CSPMappings: map[string]string{
				"gcp": "VULNERABILITY",
				"aws": "Software and Configuration Checks/Vulnerabilities",
			},
		}
	case ClassMisconfiguration:
		return ClassInfo{
			Category:              CategoryCompliance,
			DefaultSeverityWeight: 1.0,
			Description:           "Security misconfiguration in cloud resource",
			MITRETactics:          []string{"TA0001"},
			CSPMappings: map[string]string{
				"gcp":   "MISCONFIGURATION",
				"aws":   "Software and Configuration Checks",
				"azure": "Compute",
			},
		}
	case ClassObservation:
		return ClassInfo{
			Category:              CategoryCompliance,
			DefaultSeverityWeight: 0.7,
			Description:           "Informational finding requiring review but not immediate action",
			MITRETactics:          []string{},
			CSPMappings: map[string]string{
				"gcp":   "OBSERVATION",
				"aws":   "Software and Configuration Checks/Industry and Regulatory Standards",
				"azure": "IoT",
			},
		}
	case ClassPostureViolation:
		return ClassInfo{
			Category:              CategoryCompliance,
			DefaultSeverityWeight: 1.1,
			Description:           "Violation of defined security posture or policy baseline",
			MITRETactics:          []string{"TA0001"},
			CSPMappings: map[string]string{
				"gcp": "POSTURE_VIOLATION",
			},
		}
	case ClassToxicCombination:
		return ClassInfo{
			Category:              CategoryThreat,
			DefaultSeverityWeight: 1.6,
			Description:           "Combination of findings that together create critical risk",
			MITRETactics:          []string{"TA0001", "TA0003", "TA0004"},
			CSPMappings: map[string]string{
				"gcp": "TOXIC_COMBINATION",
			},
		}
	case ClassChokepoint:
		return ClassInfo{
			Category:              CategoryThreat,
			DefaultSeverityWeight: 1.5,
			Description:           "Single resource whose compromise enables broad lateral movement",
			MITRETactics:          []string{"TA0008"},
			CSPMappings: map[string]string{
				"gcp": "CHOKEPOINT",
			},
		}
	case ClassSensitiveDataRisk:
		return ClassInfo{
			Category:              CategoryData,
			DefaultSeverityWeight: 1.3,
			Description:           "Risk to sensitive or regulated data",
			MITRETactics:          []string{"TA0009", "TA0010"},
			CSPMappings: map[string]string{
				"gcp": "SENSITIVE_DATA_RISK",
				"aws": "Sensitive Data Identifications",
			},
		}

	// --- Vulnerability sub-classes ---
	case ClassOSVulnerability:
		return ClassInfo{
			Category:              CategoryVulnerability,
			DefaultSeverityWeight: 1.25,
			Description:           "OS-level CVE affecting kernel or system packages",
			MITRETactics:          []string{"TA0002", "TA0004"},
			CSPMappings: map[string]string{
				"gcp": "VULNERABILITY",
				"aws": "Software and Configuration Checks/Vulnerabilities/CVE",
			},
		}
	case ClassRuntimeVulnerability:
		return ClassInfo{
			Category:              CategoryVulnerability,
			DefaultSeverityWeight: 1.2,
			Description:           "CVE in language runtime (JVM, Node.js, Python, Go)",
			MITRETactics:          []string{"TA0002"},
			CSPMappings: map[string]string{
				"gcp": "VULNERABILITY",
				"aws": "Software and Configuration Checks/Vulnerabilities/CVE",
			},
		}
	case ClassContainerVulnerability:
		return ClassInfo{
			Category:              CategoryVulnerability,
			DefaultSeverityWeight: 1.2,
			Description:           "CVE in container image or base image layer",
			MITRETactics:          []string{"TA0002"},
			CSPMappings: map[string]string{
				"gcp": "VULNERABILITY",
				"aws": "Software and Configuration Checks/Vulnerabilities/CVE",
			},
		}
	case ClassApplicationVulnerability:
		return ClassInfo{
			Category:              CategoryVulnerability,
			DefaultSeverityWeight: 1.15,
			Description:           "CVE in application-level dependencies (npm, pip, go mod)",
			MITRETactics:          []string{"TA0002"},
			CSPMappings: map[string]string{
				"gcp": "VULNERABILITY",
				"aws": "Software and Configuration Checks/Vulnerabilities/CVE",
			},
		}
	case ClassSupplyChainRisk:
		return ClassInfo{
			Category:              CategoryVulnerability,
			DefaultSeverityWeight: 1.35,
			Description:           "Supply chain risk: dependency confusion, typosquatting, or compromised package",
			MITRETactics:          []string{"TA0001", "TA0002"},
			CSPMappings:           map[string]string{},
		}

	// --- Identity & Access sub-classes ---
	case ClassIAMMisconfiguration:
		return ClassInfo{
			Category:              CategoryIdentity,
			DefaultSeverityWeight: 1.2,
			Description:           "Overprivileged roles, wildcard policies, or stale access keys",
			MITRETactics:          []string{"TA0004"},
			CSPMappings: map[string]string{
				"gcp":   "MISCONFIGURATION",
				"aws":   "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices",
				"azure": "IdentityAndAccess",
			},
		}
	case ClassIdentityRisk:
		return ClassInfo{
			Category:              CategoryIdentity,
			DefaultSeverityWeight: 1.15,
			Description:           "MFA gaps, federation misconfiguration, or service account sprawl",
			MITRETactics:          []string{"TA0006"},
			CSPMappings: map[string]string{
				"gcp":   "MISCONFIGURATION",
				"azure": "IdentityAndAccess",
			},
		}
	case ClassPrivilegeEscalation:
		return ClassInfo{
			Category:              CategoryIdentity,
			DefaultSeverityWeight: 1.45,
			Description:           "IAM privilege escalation path or role chaining vulnerability",
			MITRETactics:          []string{"TA0004"},
			CSPMappings: map[string]string{
				"gcp": "THREAT",
				"aws": "TTPs/Privilege Escalation",
			},
		}

	// --- Network & Data sub-classes ---
	case ClassNetworkExposure:
		return ClassInfo{
			Category:              CategoryNetwork,
			DefaultSeverityWeight: 1.2,
			Description:           "Public endpoint, open port, or missing WAF protection",
			MITRETactics:          []string{"TA0001"},
			CSPMappings: map[string]string{
				"gcp":   "MISCONFIGURATION",
				"aws":   "Software and Configuration Checks/Industry and Regulatory Standards",
				"azure": "Networking",
			},
		}
	case ClassDataExposure:
		return ClassInfo{
			Category:              CategoryData,
			DefaultSeverityWeight: 1.3,
			Description:           "Publicly accessible storage, unencrypted data store, or PII exposure",
			MITRETactics:          []string{"TA0009", "TA0010"},
			CSPMappings: map[string]string{
				"gcp":   "MISCONFIGURATION",
				"aws":   "Sensitive Data Identifications",
				"azure": "Data",
			},
		}
	case ClassEncryptionWeakness:
		return ClassInfo{
			Category:              CategoryData,
			DefaultSeverityWeight: 1.1,
			Description:           "Missing encryption at rest/transit or use of weak cipher",
			MITRETactics:          []string{"TA0009"},
			CSPMappings: map[string]string{
				"gcp":   "MISCONFIGURATION",
				"aws":   "Software and Configuration Checks",
				"azure": "Data",
			},
		}

	// --- Cloud-native sub-classes ---
	case ClassComplianceDrift:
		return ClassInfo{
			Category:              CategoryCompliance,
			DefaultSeverityWeight: 1.0,
			Description:           "Configuration drift from approved baseline or CIS benchmark violation",
			MITRETactics:          []string{},
			CSPMappings: map[string]string{
				"gcp":   "POSTURE_VIOLATION",
				"aws":   "Software and Configuration Checks/Industry and Regulatory Standards",
				"azure": "Compute",
			},
		}
	case ClassResourceAnomaly:
		return ClassInfo{
			Category:              CategoryThreat,
			DefaultSeverityWeight: 1.3,
			Description:           "Unusual API calls, impossible travel, or crypto mining signals",
			MITRETactics:          []string{"TA0003", "TA0040"},
			CSPMappings: map[string]string{
				"gcp":   "THREAT",
				"aws":   "Unusual Behaviors",
				"azure": "Threat",
			},
		}

	default:
		return ClassInfo{}
	}
}

// MapGCPFindingClass maps a GCP SCC findingClass string to a FindingClass.
// For VULNERABILITY, sub-classification requires additional context — use
// SubClassifyGCPVulnerability for that purpose.
func MapGCPFindingClass(gcpClass string) FindingClass {
	switch strings.ToUpper(gcpClass) {
	case "THREAT":
		return ClassThreat
	case "VULNERABILITY":
		return ClassVulnerability
	case "MISCONFIGURATION":
		return ClassMisconfiguration
	case "OBSERVATION":
		return ClassObservation
	case "POSTURE_VIOLATION":
		return ClassPostureViolation
	case "TOXIC_COMBINATION":
		return ClassToxicCombination
	case "CHOKEPOINT":
		return ClassChokepoint
	case "SENSITIVE_DATA_RISK":
		return ClassSensitiveDataRisk
	case "SCC_ERROR":
		return ClassObservation
	default:
		return ClassMisconfiguration
	}
}

// MapAWSFindingType maps an AWS Security Hub ASFF Types namespace string to a FindingClass.
// Uses the same heuristic logic as classifyAWSFinding but also covers sub-classes.
func MapAWSFindingType(awsType string) FindingClass {
	lower := strings.ToLower(awsType)
	switch {
	case strings.Contains(lower, "ttps/privilege"):
		return ClassPrivilegeEscalation
	case strings.Contains(lower, "ttps"):
		return ClassThreat
	case strings.Contains(lower, "unusual behaviors"):
		return ClassResourceAnomaly
	case strings.Contains(lower, "effects"):
		return ClassThreat
	case strings.Contains(lower, "sensitive data"):
		return ClassSensitiveDataRisk
	case strings.Contains(lower, "vulnerabilities/cve"):
		return ClassVulnerability
	case strings.Contains(lower, "software and configuration checks"):
		return ClassMisconfiguration
	default:
		return ClassMisconfiguration
	}
}

// MapAzureAlertType maps an Azure Defender for Cloud category string to a FindingClass.
func MapAzureAlertType(azureType string) FindingClass {
	lower := strings.ToLower(strings.TrimSpace(azureType))
	switch {
	case lower == "threat" || strings.Contains(lower, "threat"):
		return ClassThreat
	case lower == "identityandaccess" || strings.Contains(lower, "identity"):
		return ClassIAMMisconfiguration
	case lower == "networking" || strings.Contains(lower, "network"):
		return ClassNetworkExposure
	case lower == "data" || strings.Contains(lower, "data"):
		return ClassDataExposure
	case lower == "iot":
		return ClassObservation
	case lower == "compute":
		return ClassMisconfiguration
	default:
		return ClassMisconfiguration
	}
}

// SubClassifyGCPVulnerability applies heuristic sub-classification to GCP VULNERABILITY findings.
// It examines the resource type, title, and description to select a granular sub-class.
// Falls back to ClassVulnerability when no heuristic matches.
func SubClassifyGCPVulnerability(resourceType, title, description string) FindingClass {
	combined := strings.ToLower(resourceType + " " + title + " " + description)
	return subClassifyByHeuristic(combined)
}

// SubClassifyVulnerability applies heuristic sub-classification to generic VULNERABILITY findings
// from any CSP. Examines the combined lowercase text of resourceType, title, and description.
func SubClassifyVulnerability(resourceType, title, description string) FindingClass {
	combined := strings.ToLower(resourceType + " " + title + " " + description)
	return subClassifyByHeuristic(combined)
}

// subClassifyByHeuristic is the shared heuristic engine used by all CSP sub-classifiers.
// Input must already be lowercased.
func subClassifyByHeuristic(combined string) FindingClass {
	// Privilege escalation takes highest priority
	if containsAny(combined, "privilege escalation", "role chain", "iam escalation") {
		return ClassPrivilegeEscalation
	}

	// Identity risk: MFA gaps, federation, SSO, IdP misconfig — checked before generic IAM
	if containsAny(combined, "mfa", "federation", "identity provider", "service account sprawl") {
		return ClassIdentityRisk
	}

	// IAM / access control signals (but not runtime keywords like "jvm" which contains no IAM terms)
	if containsAny(combined, "iam", "role", "policy", "permission", "principal", "service account", "access key", "stale key") {
		return ClassIAMMisconfiguration
	}

	// Container / GKE / EKS / AKS → container vulnerability (before runtime/OS to avoid false matches)
	if containsAny(combined, "container", "gke", "eks", "aks", "docker", "k8s", "kubernetes") {
		return ClassContainerVulnerability
	}

	// Container image vulnerability (distinct from runtime; checked after named orchestrators)
	if containsAny(combined, "image") && containsAny(combined, "cve", "vulnerability", "layer") {
		return ClassContainerVulnerability
	}

	// Runtime vulnerability — checked before OS to prevent "vm" in "jvm" triggering OS branch
	if containsAny(combined, "jvm", "node.js", "nodejs", "runtime", "interpreter") &&
		containsAny(combined, "cve", "vulnerability", "version") {
		return ClassRuntimeVulnerability
	}
	// Java/Python runtime check is separate to avoid "python" matching "option" etc.
	if containsAny(combined, "java runtime", "python runtime") &&
		containsAny(combined, "cve", "vulnerability", "version") {
		return ClassRuntimeVulnerability
	}

	// OS/VM CVE (requires explicit VM/instance indicator alongside cve/kernel/package)
	if containsAny(combined, "instance", "virtual machine", "compute engine") &&
		containsAny(combined, "cve", "kernel", "os ", "operating system", "package") {
		return ClassOSVulnerability
	}
	// Broader OS check: "vm" only as standalone indicator (not substring of "jvm")
	if strings.Contains(combined, " vm ") || strings.HasPrefix(combined, "vm ") {
		if containsAny(combined, "cve", "kernel", "os ", "operating system", "package") {
			return ClassOSVulnerability
		}
	}

	// Encryption weakness signals
	if containsAny(combined, "encryption", "unencrypted", "plaintext", "cipher", "tls", "ssl", "kms") {
		return ClassEncryptionWeakness
	}

	// Data exposure: storage + public access
	if containsAny(combined, "bucket", "blob", "storage", "s3", "gcs", "adls") &&
		containsAny(combined, "public", "accessible", "exposed", "open") {
		return ClassDataExposure
	}

	// Network exposure: public + port/endpoint
	if containsAny(combined, "public", "exposed", "open", "internet") &&
		containsAny(combined, "port", "endpoint", "firewall", "ingress", "0.0.0.0", "waf", "loadbalancer") {
		return ClassNetworkExposure
	}

	// Supply chain signals
	if containsAny(combined, "supply chain", "dependency confusion", "typosquat", "compromised package") {
		return ClassSupplyChainRisk
	}

	// Application dependency CVE
	if containsAny(combined, "npm", "pip", "go mod", "maven", "gradle", "dependency", "package") &&
		containsAny(combined, "cve", "vulnerability", "outdated") {
		return ClassApplicationVulnerability
	}

	return ClassVulnerability
}

// containsAny returns true if s contains any of the provided substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
