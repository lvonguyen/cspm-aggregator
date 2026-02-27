package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// DeltaStatus represents the change status of a finding
type DeltaStatus string

const (
	DeltaNew      DeltaStatus = "NEW"
	DeltaExisting DeltaStatus = "EXISTING"
	DeltaClosed   DeltaStatus = "CLOSED"
	DeltaReopened DeltaStatus = "REOPENED"
)

// FindingClass categorizes the type of security finding
type FindingClass string

const (
	// --- Base classes (GCP SCC-compatible) ---
	ClassThreat            FindingClass = "THREAT"
	ClassVulnerability     FindingClass = "VULNERABILITY"
	ClassMisconfiguration  FindingClass = "MISCONFIGURATION"
	ClassObservation       FindingClass = "OBSERVATION"
	ClassPostureViolation  FindingClass = "POSTURE_VIOLATION"
	ClassToxicCombination  FindingClass = "TOXIC_COMBINATION"
	ClassChokepoint        FindingClass = "CHOKEPOINT"
	ClassSensitiveDataRisk FindingClass = "SENSITIVE_DATA_RISK"

	// --- Vulnerability sub-classes ---
	ClassOSVulnerability          FindingClass = "OS_VULNERABILITY"          // OS-level CVEs (kernel, system packages)
	ClassRuntimeVulnerability     FindingClass = "RUNTIME_VULNERABILITY"     // Language runtime CVEs (JVM, Node.js, Python, Go)
	ClassContainerVulnerability   FindingClass = "CONTAINER_VULNERABILITY"   // Container image CVEs, base image issues
	ClassApplicationVulnerability FindingClass = "APPLICATION_VULNERABILITY" // Application-level deps (npm, pip, go mod)
	ClassSupplyChainRisk          FindingClass = "SUPPLY_CHAIN_RISK"         // Dependency confusion, typosquatting, compromised packages

	// --- Identity & Access sub-classes ---
	ClassIAMMisconfiguration FindingClass = "IAM_MISCONFIGURATION" // Overprivileged roles, wildcard policies, stale keys
	ClassIdentityRisk        FindingClass = "IDENTITY_RISK"        // MFA gaps, federation misconfig, service account sprawl
	ClassPrivilegeEscalation FindingClass = "PRIVILEGE_ESCALATION" // IAM escalation paths, role chaining

	// --- Network & Data sub-classes ---
	ClassNetworkExposure    FindingClass = "NETWORK_EXPOSURE"    // Public endpoints, open ports, missing WAF
	ClassDataExposure       FindingClass = "DATA_EXPOSURE"       // Public buckets, unencrypted data stores, PII exposure
	ClassEncryptionWeakness FindingClass = "ENCRYPTION_WEAKNESS" // Missing encryption at rest/transit, weak ciphers

	// --- Cloud-native sub-classes ---
	ClassComplianceDrift FindingClass = "COMPLIANCE_DRIFT" // Config drift from baseline, CIS benchmark violations
	ClassResourceAnomaly FindingClass = "RESOURCE_ANOMALY" // Unusual API calls, impossible travel, crypto mining signals

	// --- Additional sub-classes ---
	ClassWebVulnerability       FindingClass = "WEB_VULNERABILITY"        // Web app vulnerabilities: OWASP Top 10, SQLi, XSS, SSRF (under SOFTWARE_VULNERABILITY)
	ClassMalware                FindingClass = "MALWARE"                  // Malware or backdoor detected on host or in workload (under THREAT)
	ClassCryptomining           FindingClass = "CRYPTOMINING"             // Unauthorized cryptomining activity detected (under THREAT)
	ClassKubernetesAnomaly      FindingClass = "KUBERNETES_ANOMALY"       // Anomalous Kubernetes API calls or runtime behavior (under RESOURCE_ANOMALY)
	ClassContainerRuntimeThreat FindingClass = "CONTAINER_RUNTIME_THREAT" // Container escape or runtime threat (under THREAT)
)

// FindingClassCategory groups sub-classes into parent categories
type FindingClassCategory string

const (
	CategoryVulnerability FindingClassCategory = "VULNERABILITY"
	CategoryIdentity      FindingClassCategory = "IDENTITY"
	CategoryNetwork       FindingClassCategory = "NETWORK"
	CategoryData          FindingClassCategory = "DATA"
	CategoryCompliance    FindingClassCategory = "COMPLIANCE"
	CategoryThreat        FindingClassCategory = "THREAT"
)

// ClassInfo holds metadata for a FindingClass
type ClassInfo struct {
	Category              FindingClassCategory
	DefaultSeverityWeight float64
	Description           string
	MITRETactics          []string
	// CSPMappings maps csp name ("aws", "azure", "gcp") to the provider's native source/type name
	CSPMappings map[string]string
}

// AttackPathContext contains attack path analysis context from cloud-native
// attack path engines (Azure attack paths, GCP attack exposure, AWS GuardDuty
// attack sequences) and open-source tools (Cartography, PMapper).
type AttackPathContext struct {
	Score              float64  `json:"score,omitempty"`              // 0-100 composite attack path score
	PathNodeCount      int      `json:"path_node_count,omitempty"`    // Number of nodes in longest attack path
	EntryPointType     string   `json:"entry_point_type,omitempty"`   // internet, lateral, insider
	TargetType         string   `json:"target_type,omitempty"`        // data, compute, identity, network
	BlastRadiusCount   int      `json:"blast_radius_count,omitempty"` // Number of resources reachable from finding
	IsToxicCombination bool     `json:"is_toxic_combination,omitempty"`
	IsChokepoint       bool     `json:"is_chokepoint,omitempty"`
	IAMEscalationPath  []string `json:"iam_escalation_path,omitempty"` // Privilege escalation chain
}

// ThreatIntelContext contains threat intelligence enrichment from public feeds
// (CISA KEV, EPSS, NVD, GreyNoise, AlienVault OTX).
type ThreatIntelContext struct {
	CVEIDs         []string  `json:"cve_ids,omitempty"`
	InKEV          bool      `json:"in_kev,omitempty"`          // CISA Known Exploited Vulnerabilities catalog
	KEVDateAdded   string    `json:"kev_date_added,omitempty"`  // When CVE was added to KEV
	EPSSScore      float64   `json:"epss_score,omitempty"`      // 0.0-1.0 exploitation probability (EPSS v4)
	EPSSPercentile float64   `json:"epss_percentile,omitempty"` // 0.0-1.0 relative ranking
	CVSSBaseScore  float64   `json:"cvss_base_score,omitempty"` // NVD CVSS v3.1 base score
	CVSSVector     string    `json:"cvss_vector,omitempty"`     // CVSS vector string
	GreyNoiseClass string    `json:"greynoise_class,omitempty"` // benign, malicious, unknown
	OTXPulseCount  int       `json:"otx_pulse_count,omitempty"` // Number of OTX threat pulses referencing this
	EnrichedAt     time.Time `json:"enriched_at,omitempty"`     // When TI enrichment was last performed
}

// Finding represents a normalized cross-cloud security finding
type Finding struct {
	// Core identification
	FindingID      string `json:"finding_id"`
	FindingIDShort string `json:"finding_id_short"` // Dedupe key (hash)
	CSP            string `json:"csp"`              // aws, azure, gcp
	AccountID      string `json:"account_id"`       // AWS account, Azure subscription, GCP project
	ResourceID     string `json:"resource_id"`

	// Resource context
	ResourceType string `json:"resource_type,omitempty"` // AwsEc2Instance, microsoft.compute/*, google.compute.Instance
	Region       string `json:"region,omitempty"`        // us-east-1, westus2, us-central1

	// Finding details
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	Severity     string       `json:"severity"`                // CRITICAL, HIGH, MEDIUM, LOW
	Status       string       `json:"status"`                  // ACTIVE, RESOLVED, SUPPRESSED
	FindingClass FindingClass `json:"finding_class,omitempty"` // THREAT, VULNERABILITY, MISCONFIGURATION, etc.

	// Control mapping
	ControlID           string   `json:"control_id"`
	Standard            string   `json:"standard"`                       // CIS, FSBP, MCSB
	ComplianceStandards []string `json:"compliance_standards,omitempty"` // ["CIS-v5.0", "PCI-DSS-v4.0.1"]
	RemediationURL      string   `json:"remediation_url,omitempty"`      // Link to remediation docs

	// Risk context (Azure attack paths, GCP attack exposure)
	RiskScore   float64            `json:"risk_score,omitempty"`  // 0-100 composite risk score
	AIWorkload  bool               `json:"ai_workload,omitempty"` // true if finding relates to AI/ML service
	AttackPath  AttackPathContext  `json:"attack_path,omitempty"`
	ThreatIntel ThreatIntelContext `json:"threat_intel,omitempty"`

	// Classification
	CBU     string `json:"cbu"`      // Business unit
	Tier    string `json:"tier"`     // Tier 1, Tier 2, Tier 3
	EnvType string `json:"env_type"` // DEV, STG, PROD
	Owner   string `json:"owner"`    // Team or individual owner

	// Timestamps
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Remediation tracking
	AsanaTaskID    string    `json:"asana_task_id,omitempty"`
	RemediationSLA time.Time `json:"remediation_sla,omitempty"`

	// Delta tracking
	DeltaStatus DeltaStatus `json:"delta_status"`
	DaysOpen    int         `json:"days_open"`
}

// TrendMetrics contains aggregated metrics for reporting
type TrendMetrics struct {
	Period           string    `json:"period"` // Monthly/Weekly
	GeneratedAt      time.Time `json:"generated_at"`
	TotalFindings    int       `json:"total_findings"`
	NewFindings      int       `json:"new_findings"`
	ClosedFindings   int       `json:"closed_findings"`
	ReopenedFindings int       `json:"reopened_findings"`
	NetChange        int       `json:"net_change"`   // New - Closed
	ClosureRate      float64   `json:"closure_rate"` // Closed / Previous Total
	MTTR             float64   `json:"mttr_days"`    // Mean Time To Remediate

	// Breakdowns
	BySeverity map[string]int `json:"by_severity"`
	ByCSP      map[string]int `json:"by_csp"`
	ByCBU      map[string]int `json:"by_cbu"`

	// SLA compliance
	WithinSLA  int `json:"within_sla"`
	OverdueSLA int `json:"overdue_sla"`
}

// State represents the persisted state for delta detection
type State struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Findings    map[string]Finding `json:"findings"` // Keyed by FindingIDShort
}

// SeverityPriority maps severity to numeric priority for sorting
var SeverityPriority = map[string]int{
	"CRITICAL": 1,
	"HIGH":     2,
	"MEDIUM":   3,
	"LOW":      4,
}

// SLADays maps severity to remediation SLA in days
var SLADays = map[string]int{
	"CRITICAL": 7,
	"HIGH":     14,
	"MEDIUM":   30,
	"LOW":      90,
}

// Normalizer converts provider-specific findings to common schema
type Normalizer struct {
	accountMapping map[string]AccountInfo
	previousState  *State
}

// AccountInfo contains metadata about a cloud account
type AccountInfo struct {
	AccountID string
	CBU       string
	Tier      string
	EnvType   string
	Owner     string
}

// NewNormalizer creates a new normalizer with account mappings
func NewNormalizer(accounts []AccountInfo, previousState *State) *Normalizer {
	mapping := make(map[string]AccountInfo)
	for _, a := range accounts {
		mapping[a.AccountID] = a
	}
	return &Normalizer{
		accountMapping: mapping,
		previousState:  previousState,
	}
}

// EnrichFinding adds organizational metadata and delta status
func (n *Normalizer) EnrichFinding(f *Finding) {
	// Add organizational metadata from account mapping
	if info, ok := n.accountMapping[f.AccountID]; ok {
		f.CBU = info.CBU
		f.Tier = info.Tier
		f.EnvType = info.EnvType
		if f.Owner == "" {
			f.Owner = info.Owner
		}
	}

	// Generate short ID for deduplication
	f.FindingIDShort = GenerateShortID(f.CSP, f.AccountID, f.ControlID, f.ResourceID)

	// Calculate delta status
	f.DeltaStatus = n.calculateDeltaStatus(f)

	// Set timestamps
	now := time.Now()
	if f.FirstSeen.IsZero() {
		// Check if we have historical first seen
		if n.previousState != nil {
			if prev, ok := n.previousState.Findings[f.FindingIDShort]; ok {
				f.FirstSeen = prev.FirstSeen
				f.AsanaTaskID = prev.AsanaTaskID // Preserve task ID
			}
		}
		if f.FirstSeen.IsZero() {
			f.FirstSeen = now
		}
	}
	f.LastSeen = now

	// Calculate days open
	f.DaysOpen = int(now.Sub(f.FirstSeen).Hours() / 24)

	// Calculate SLA deadline
	if f.RemediationSLA.IsZero() {
		if days, ok := SLADays[f.Severity]; ok {
			f.RemediationSLA = f.FirstSeen.AddDate(0, 0, days)
		}
	}
}

// calculateDeltaStatus determines if finding is new, existing, closed, or reopened
func (n *Normalizer) calculateDeltaStatus(f *Finding) DeltaStatus {
	if n.previousState == nil {
		return DeltaNew
	}

	prev, existed := n.previousState.Findings[f.FindingIDShort]
	if !existed {
		return DeltaNew
	}

	// Check if previously closed (status was RESOLVED/SUPPRESSED) and now active
	if prev.Status != "ACTIVE" && f.Status == "ACTIVE" {
		return DeltaReopened
	}

	return DeltaExisting
}

// DetectClosedFindings identifies findings in previous state not in current
func (n *Normalizer) DetectClosedFindings(currentFindings []Finding) []Finding {
	if n.previousState == nil {
		return nil
	}

	// Build set of current finding IDs
	currentSet := make(map[string]bool)
	for _, f := range currentFindings {
		currentSet[f.FindingIDShort] = true
	}

	// Find findings in previous state that are not in current
	var closed []Finding
	for id, prev := range n.previousState.Findings {
		if !currentSet[id] && prev.Status == "ACTIVE" {
			prev.DeltaStatus = DeltaClosed
			prev.Status = "RESOLVED"
			closed = append(closed, prev)
		}
	}

	return closed
}

// CalculateTrends generates trend metrics from findings
func CalculateTrends(findings []Finding, previousTotal int, period string) TrendMetrics {
	metrics := TrendMetrics{
		Period:      period,
		GeneratedAt: time.Now(),
		BySeverity:  make(map[string]int),
		ByCSP:       make(map[string]int),
		ByCBU:       make(map[string]int),
	}

	var totalMTTR float64
	var closedCount int

	for _, f := range findings {
		// Count by delta status
		switch f.DeltaStatus {
		case DeltaNew:
			metrics.NewFindings++
		case DeltaClosed:
			metrics.ClosedFindings++
			closedCount++
			totalMTTR += float64(f.DaysOpen)
		case DeltaReopened:
			metrics.ReopenedFindings++
		case DeltaExisting:
			// Existing findings are counted in TotalFindings below
		}

		// Count active findings
		if f.Status == "ACTIVE" {
			metrics.TotalFindings++
			metrics.BySeverity[f.Severity]++
			metrics.ByCSP[f.CSP]++
			if f.CBU != "" {
				metrics.ByCBU[f.CBU]++
			}

			// SLA compliance
			if time.Now().Before(f.RemediationSLA) {
				metrics.WithinSLA++
			} else {
				metrics.OverdueSLA++
			}
		}
	}

	// Calculate derived metrics
	metrics.NetChange = metrics.NewFindings - metrics.ClosedFindings
	if previousTotal > 0 {
		metrics.ClosureRate = float64(metrics.ClosedFindings) / float64(previousTotal)
	}
	if closedCount > 0 {
		metrics.MTTR = totalMTTR / float64(closedCount)
	}

	return metrics
}

// GenerateShortID creates a dedupe key from finding attributes
func GenerateShortID(csp, accountID, controlID, resourceID string) string {
	// Create a stable hash for deduplication
	data := csp + "|" + accountID + "|" + controlID + "|" + resourceID
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // First 16 chars of hash
}

// NormalizeAWSFinding converts an AWS Security Hub ASFF finding to the common schema.
// Input: map[string]interface{} from JSON-decoded ASFF finding.
func (n *Normalizer) NormalizeAWSFinding(raw map[string]interface{}) Finding {
	f := Finding{CSP: "aws"}

	f.FindingID = getStr(raw, "Id")
	f.AccountID = getStr(raw, "AwsAccountId")
	f.Title = getStr(raw, "Title")
	f.Description = truncate(getStr(raw, "Description"), 1024)
	f.Region = getStr(raw, "Region")

	// Severity: prefer Label, fall back to Normalized range mapping
	if sev := getMap(raw, "Severity"); sev != nil {
		f.Severity = strings.ToUpper(getStr(sev, "Label"))
		if f.Severity == "" {
			f.Severity = normalizeSeverityFromScore(getFloat(sev, "Normalized"))
		}
	}

	// Status: map Compliance.Status + Workflow.Status → normalized status
	f.Status = "ACTIVE"
	if wf := getMap(raw, "Workflow"); wf != nil {
		switch strings.ToUpper(getStr(wf, "Status")) {
		case "RESOLVED":
			f.Status = "RESOLVED"
		case "SUPPRESSED":
			f.Status = "SUPPRESSED"
		}
	}

	// Resource extraction
	if resources := getSlice(raw, "Resources"); len(resources) > 0 {
		if r0, ok := resources[0].(map[string]interface{}); ok {
			f.ResourceID = getStr(r0, "Id")
			f.ResourceType = getStr(r0, "Type")
			if f.Region == "" {
				f.Region = getStr(r0, "Region")
			}
		}
	}

	// Control ID: extract from GeneratorId or ProductFields.ControlId
	f.ControlID = getStr(raw, "GeneratorId")
	if pf := getMap(raw, "ProductFields"); pf != nil {
		if controlID := getStr(pf, "ControlId"); controlID != "" {
			f.ControlID = controlID
		}
		// Standard from StandardsArn
		if stdArn := getStr(pf, "StandardsArn"); stdArn != "" {
			f.Standard = parseAWSStandard(stdArn)
		}
	}

	// Remediation URL
	if rem := getMap(raw, "Remediation"); rem != nil {
		if rec := getMap(rem, "Recommendation"); rec != nil {
			f.RemediationURL = getStr(rec, "Url")
		}
	}

	// Compliance standards
	if comp := getMap(raw, "Compliance"); comp != nil {
		if stds := getSlice(comp, "AssociatedStandards"); len(stds) > 0 {
			for _, s := range stds {
				if sm, ok := s.(map[string]interface{}); ok {
					if sid := getStr(sm, "StandardsId"); sid != "" {
						f.ComplianceStandards = append(f.ComplianceStandards, parseAWSStandard(sid))
					}
				}
			}
		}
	}

	// Finding class: derive from Types[] namespace
	f.FindingClass = classifyAWSFinding(raw)

	// AI workload detection
	f.AIWorkload = isAIWorkload(f.Title, f.ResourceType, f.ControlID)

	// Timestamps
	f.FirstSeen = parseTime(getStr(raw, "FirstObservedAt"))
	if f.FirstSeen.IsZero() {
		f.FirstSeen = parseTime(getStr(raw, "CreatedAt"))
	}
	f.LastSeen = parseTime(getStr(raw, "LastObservedAt"))
	if f.LastSeen.IsZero() {
		f.LastSeen = parseTime(getStr(raw, "UpdatedAt"))
	}

	n.EnrichFinding(&f)
	return f
}

// NormalizeAzureFinding converts an Azure Defender for Cloud assessment to the common schema.
// Input: map[string]interface{} from JSON-decoded Resource Graph assessment row.
func (n *Normalizer) NormalizeAzureFinding(raw map[string]interface{}) Finding {
	f := Finding{CSP: "azure"}

	f.FindingID = getStr(raw, "id")
	f.Title = getStr(raw, "displayName")
	if f.Title == "" {
		f.Title = getStr(raw, "properties_displayName")
	}

	// Account ID = subscription ID, extracted from resource path
	f.AccountID = getStr(raw, "subscriptionId")
	if f.AccountID == "" {
		f.AccountID = extractAzureSubscription(f.FindingID)
	}

	// Status: map Unhealthy/Healthy/NotApplicable → ACTIVE/RESOLVED/SUPPRESSED
	statusCode := getStr(raw, "statusCode")
	if statusCode == "" {
		if status := getMap(raw, "status"); status != nil {
			statusCode = getStr(status, "code")
		}
	}
	switch strings.ToLower(statusCode) {
	case "unhealthy":
		f.Status = "ACTIVE"
	case "healthy":
		f.Status = "RESOLVED"
	default:
		f.Status = "SUPPRESSED"
	}

	// Severity: normalize Azure values (High/Medium/Low/Critical/N/A) to uppercase
	severity := getStr(raw, "severity")
	if severity == "" {
		severity = getStr(raw, "properties_severity")
	}
	if severity == "" {
		if meta := getMap(raw, "metadata"); meta != nil {
			severity = getStr(meta, "severity")
		}
	}
	f.Severity = normalizeAzureSeverity(severity)

	// Resource details
	f.ResourceID = getStr(raw, "resourceId")
	if f.ResourceID == "" {
		if rd := getMap(raw, "resourceDetails"); rd != nil {
			f.ResourceID = getStr(rd, "Id")
			f.ResourceType = getStr(rd, "ResourceType")
		}
	}
	if f.ResourceType == "" {
		f.ResourceType = getStr(raw, "resourceType")
		if f.ResourceType == "" {
			f.ResourceType = getStr(raw, "properties_resourceDetails_ResourceType")
		}
	}

	// Region: parse from resource ID (/subscriptions/.../resourceGroups/.../providers/...)
	f.Region = extractAzureRegion(f.ResourceID)

	// Control mapping
	f.ControlID = getStr(raw, "name") // assessment GUID
	if meta := getMap(raw, "metadata"); meta != nil {
		f.Description = truncate(getStr(meta, "description"), 1024)
		f.RemediationURL = getStr(meta, "remediationDescription")
		if policyID := getStr(meta, "policyDefinitionId"); policyID != "" {
			f.Standard = "MCSB"
		}
		// Compliance categories
		if cats := getSlice(meta, "categories"); len(cats) > 0 {
			for _, c := range cats {
				if cs, ok := c.(string); ok {
					f.ComplianceStandards = append(f.ComplianceStandards, "MCSB:"+cs)
				}
			}
		}
	}
	if f.Standard == "" {
		f.Standard = "MCSB"
	}

	// Risk context (2025-05-04-preview): attack path scoring
	if risk := getMap(raw, "risk"); risk != nil {
		switch strings.ToLower(getStr(risk, "level")) {
		case "high":
			f.RiskScore = 80
		case "medium":
			f.RiskScore = 50
		case "low":
			f.RiskScore = 20
		}
	}

	// Finding class: use category from metadata if available, else heuristic sub-classification
	azureCategory := ""
	if meta := getMap(raw, "metadata"); meta != nil {
		if cats := getSlice(meta, "categories"); len(cats) > 0 {
			if cs, ok := cats[0].(string); ok {
				azureCategory = cs
			}
		}
	}
	if azureCategory != "" {
		f.FindingClass = MapAzureAlertType(azureCategory)
	} else {
		// Heuristic sub-classification from title/description
		sub := SubClassifyVulnerability(f.ResourceType, f.Title, f.Description)
		if sub != ClassVulnerability {
			f.FindingClass = sub
		} else {
			f.FindingClass = ClassMisconfiguration
		}
	}

	// AI workload detection
	f.AIWorkload = isAIWorkload(f.Title, f.ResourceType, f.ControlID)

	// Timestamps
	if status := getMap(raw, "status"); status != nil {
		f.FirstSeen = parseTime(getStr(status, "firstEvaluationDate"))
		f.LastSeen = parseTime(getStr(status, "statusChangeDate"))
	}

	n.EnrichFinding(&f)
	return f
}

// NormalizeGCPFinding converts a GCP Security Command Center finding to the common schema.
// Input: map[string]interface{} from JSON-decoded SCC finding.
func (n *Normalizer) NormalizeGCPFinding(raw map[string]interface{}) Finding {
	f := Finding{CSP: "gcp"}

	f.FindingID = getStr(raw, "name")
	f.Title = getStr(raw, "category")
	f.Description = truncate(getStr(raw, "description"), 1024)

	// Severity
	severity := getStr(raw, "severity")
	if severity == "" || severity == "SEVERITY_UNSPECIFIED" {
		f.Severity = "LOW"
	} else {
		f.Severity = strings.ToUpper(severity)
	}

	// Status: map state → ACTIVE/RESOLVED
	switch strings.ToUpper(getStr(raw, "state")) {
	case "ACTIVE":
		f.Status = "ACTIVE"
	case "INACTIVE":
		f.Status = "RESOLVED"
	default:
		f.Status = "ACTIVE"
	}

	// Mute → SUPPRESSED override
	if strings.ToUpper(getStr(raw, "mute")) == "MUTED" {
		f.Status = "SUPPRESSED"
	}

	// Resource
	f.ResourceID = getStr(raw, "resourceName")
	f.AccountID = extractGCPProject(f.ResourceID)
	f.Region = extractGCPRegion(f.ResourceID)
	f.ResourceType = extractGCPResourceType(f.ResourceID)

	// Control mapping
	f.ControlID = getStr(raw, "category")

	// Compliance standards from compliances[] array
	if compliances := getSlice(raw, "compliances"); len(compliances) > 0 {
		for _, c := range compliances {
			if cm, ok := c.(map[string]interface{}); ok {
				std := getStr(cm, "standard")
				ver := getStr(cm, "version")
				if std != "" {
					label := strings.ToUpper(std)
					if ver != "" {
						label = fmt.Sprintf("%s-v%s", label, ver)
					}
					f.ComplianceStandards = append(f.ComplianceStandards, label)
					if f.Standard == "" {
						f.Standard = strings.ToUpper(std)
					}
				}
			}
		}
	}
	if f.Standard == "" {
		f.Standard = "GCP-SHA"
	}

	// Finding class: map from findingClass field, then apply sub-classification for vulnerabilities
	gcpClass := getStr(raw, "findingClass")
	f.FindingClass = MapGCPFindingClass(gcpClass)
	if f.FindingClass == ClassVulnerability {
		f.FindingClass = SubClassifyGCPVulnerability(f.ResourceType, f.Title, f.Description)
	}

	// Risk context: attack exposure score (v2 API)
	if ae := getMap(raw, "attackExposure"); ae != nil {
		f.RiskScore = getFloat(ae, "score")
	}

	// Remediation: nextSteps field (text, not URL)
	if ns := getStr(raw, "nextSteps"); ns != "" {
		f.RemediationURL = ns
	}

	// AI workload detection
	f.AIWorkload = isAIWorkload(f.Title, f.ResourceType, f.ControlID)
	if getMap(raw, "vertexAi") != nil || getMap(raw, "notebook") != nil {
		f.AIWorkload = true
	}

	// Timestamps
	f.FirstSeen = parseTime(getStr(raw, "createTime"))
	f.LastSeen = parseTime(getStr(raw, "eventTime"))

	n.EnrichFinding(&f)
	return f
}

// --- Helper functions ---

// getStr safely extracts a string from a nested map
func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getMap safely extracts a nested map
func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if sub, ok := v.(map[string]interface{}); ok {
			return sub
		}
	}
	return nil
}

// getSlice safely extracts a slice from a map
func getSlice(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if s, ok := v.([]interface{}); ok {
			return s
		}
	}
	return nil
}

// getFloat safely extracts a float64 from a map
func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		}
	}
	return 0
}

// parseTime parses an ISO 8601 timestamp string
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// truncate limits a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// parseAWSStandard extracts a human-readable standard name from an ARN
func parseAWSStandard(arn string) string {
	lower := strings.ToLower(arn)
	switch {
	case strings.Contains(lower, "aws-foundational-security-best-practices"):
		return "FSBP"
	case strings.Contains(lower, "cis-aws-foundations-benchmark"):
		if strings.Contains(lower, "v/3.0.0") {
			return "CIS-v3.0"
		}
		if strings.Contains(lower, "v/5.0.0") {
			return "CIS-v5.0"
		}
		return "CIS"
	case strings.Contains(lower, "pci-dss"):
		if strings.Contains(lower, "v/4.0.1") {
			return "PCI-DSS-v4.0.1"
		}
		return "PCI-DSS"
	case strings.Contains(lower, "nist-800-53"):
		return "NIST-800-53"
	case strings.Contains(lower, "nist-800-171"):
		return "NIST-800-171"
	default:
		// Extract last meaningful segment
		parts := strings.Split(arn, "/")
		for _, p := range parts {
			if p != "" && p != "v" && !strings.HasPrefix(p, "arn:") {
				return strings.ToUpper(p)
			}
		}
		return "UNKNOWN"
	}
}

// normalizeAzureSeverity maps Azure severity values to the common enum
func normalizeAzureSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "n/a", "na", "":
		return "LOW"
	default:
		return "LOW"
	}
}

// normalizeSeverityFromScore maps a 0-100 ASFF Normalized score to a label
func normalizeSeverityFromScore(score float64) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 70:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 1:
		return "LOW"
	default:
		return "LOW"
	}
}

// classifyAWSFinding derives FindingClass from ASFF Types[] namespace.
// For vulnerability findings it applies heuristic sub-classification using
// title and resource type context extracted from the raw finding.
func classifyAWSFinding(raw map[string]interface{}) FindingClass {
	// Check for Detection object (GuardDuty attack sequences)
	if getMap(raw, "Detection") != nil {
		return ClassThreat
	}

	title := getStr(raw, "Title")
	description := getStr(raw, "Description")
	resourceType := ""
	if resources := getSlice(raw, "Resources"); len(resources) > 0 {
		if r0, ok := resources[0].(map[string]interface{}); ok {
			resourceType = getStr(r0, "Type")
		}
	}

	types := getSlice(raw, "Types")
	for _, t := range types {
		ts, ok := t.(string)
		if !ok {
			continue
		}
		lower := strings.ToLower(ts)
		switch {
		case strings.Contains(lower, "ttps/privilege"):
			return ClassPrivilegeEscalation
		// Container runtime threats take priority over generic TTPs
		case strings.Contains(lower, "ttps") && (strings.Contains(lower, "container") || strings.Contains(lower, "runtime")):
			return ClassContainerRuntimeThreat
		// Malware is a specific TTPs sub-type
		case strings.Contains(lower, "ttps") && strings.Contains(lower, "malware"):
			return ClassMalware
		case strings.Contains(lower, "ttps"):
			return ClassThreat
		// Cryptomining and Kubernetes anomalies are sub-types of unusual behaviors
		case strings.Contains(lower, "unusual behaviors") && strings.Contains(lower, "crypto"):
			return ClassCryptomining
		case strings.Contains(lower, "unusual behaviors") && (strings.Contains(lower, "kubernetes") || strings.Contains(lower, "k8s")):
			return ClassKubernetesAnomaly
		case strings.Contains(lower, "unusual behaviors"):
			return ClassResourceAnomaly
		case strings.Contains(lower, "effects"):
			return ClassThreat
		case strings.Contains(lower, "sensitive data"):
			return ClassSensitiveDataRisk
		case strings.Contains(lower, "vulnerabilities/cve"):
			// Apply sub-classification using context; check for web vulnerability signals first
			combined := strings.ToLower(title + " " + description)
			if containsAny(combined, "sqli", "sql injection", "xss", "cross-site", "ssrf", "server-side request", "injection", "web application") {
				return ClassWebVulnerability
			}
			return SubClassifyVulnerability(resourceType, title, description)
		case strings.Contains(lower, "software and configuration checks"):
			// May still be sub-classifiable (IAM, network, encryption)
			sub := SubClassifyVulnerability(resourceType, title, description)
			if sub != ClassVulnerability {
				return sub
			}
			return ClassMisconfiguration
		}
	}

	// Default based on product
	productArn := getStr(raw, "ProductArn")
	switch {
	case strings.Contains(productArn, "guardduty"):
		return ClassThreat
	case strings.Contains(productArn, "inspector"):
		return SubClassifyVulnerability(resourceType, title, description)
	case strings.Contains(productArn, "macie"):
		return ClassSensitiveDataRisk
	default:
		return ClassMisconfiguration
	}
}

// isAIWorkload detects if a finding relates to an AI/ML service
func isAIWorkload(title, resourceType, controlID string) bool {
	indicators := []string{
		"bedrock", "sagemaker", "amazon q",
		"openai", "cognitive", "foundry", "ai services", "machine learning",
		"vertex", "notebook", "workbench", "colab", "gemini",
	}
	combined := strings.ToLower(title + " " + resourceType + " " + controlID)
	for _, ind := range indicators {
		if strings.Contains(combined, ind) {
			return true
		}
	}
	return false
}

// extractAzureSubscription extracts subscription ID from an Azure resource path
func extractAzureSubscription(resourceID string) string {
	lower := strings.ToLower(resourceID)
	idx := strings.Index(lower, "/subscriptions/")
	if idx == -1 {
		return ""
	}
	rest := resourceID[idx+len("/subscriptions/"):]
	if end := strings.Index(rest, "/"); end != -1 {
		return rest[:end]
	}
	return rest
}

// extractAzureRegion attempts to parse region from a resource ID.
// Azure resource IDs don't always embed region; returns empty if not determinable.
func extractAzureRegion(resourceID string) string {
	// Azure resource IDs don't consistently contain region in the path.
	// Region is typically a property on the resource, not in the ID.
	return ""
}

// extractGCPProject extracts project ID from a GCP resource name
func extractGCPProject(resourceName string) string {
	// Patterns: //service.googleapis.com/projects/{project}/...
	// or projects/{project}/...
	lower := strings.ToLower(resourceName)
	idx := strings.Index(lower, "projects/")
	if idx == -1 {
		return ""
	}
	rest := resourceName[idx+len("projects/"):]
	if end := strings.Index(rest, "/"); end != -1 {
		return rest[:end]
	}
	return rest
}

// extractGCPRegion extracts region from a GCP resource name
func extractGCPRegion(resourceName string) string {
	for _, prefix := range []string{"zones/", "locations/", "regions/"} {
		idx := strings.Index(resourceName, prefix)
		if idx == -1 {
			continue
		}
		rest := resourceName[idx+len(prefix):]
		if end := strings.Index(rest, "/"); end != -1 {
			region := rest[:end]
			// zones/ returns zone (us-central1-a), convert to region
			if prefix == "zones/" {
				if lastDash := strings.LastIndex(region, "-"); lastDash > 0 {
					// Check if suffix is a single char (zone letter)
					suffix := region[lastDash+1:]
					if len(suffix) == 1 {
						return region[:lastDash]
					}
				}
			}
			return region
		}
	}
	return ""
}

// extractGCPResourceType extracts resource type from a GCP resource name
func extractGCPResourceType(resourceName string) string {
	// Pattern: //service.googleapis.com/projects/{p}/zones/{z}/{type}/{name}
	// or: //service.googleapis.com/projects/{p}/{type}/{name}
	parts := strings.Split(resourceName, "/")
	// Walk backwards to find the resource type (second-to-last non-empty segment)
	nonEmpty := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	if len(nonEmpty) >= 2 {
		return nonEmpty[len(nonEmpty)-2]
	}
	return ""
}
