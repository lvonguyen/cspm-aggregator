// Package scoring provides AI-powered finding prioritization combining
// contextual risk assessment with remediation complexity analysis.
package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ComplexityTier represents the remediation complexity level.
type ComplexityTier int

const (
	Tier1 ComplexityTier = 1 // Low complexity - full automation candidate
	Tier2 ComplexityTier = 2 // Medium complexity - partial automation
	Tier3 ComplexityTier = 3 // High complexity - manual execution required
)

// String returns the string representation of ComplexityTier.
func (t ComplexityTier) String() string {
	switch t {
	case Tier1:
		return "Tier1"
	case Tier2:
		return "Tier2"
	case Tier3:
		return "Tier3"
	default:
		return "Unknown"
	}
}

// ComplexityFinding represents a finding for complexity assessment.
type ComplexityFinding struct {
	ID           string `json:"id"`
	Source       string `json:"source"`
	Severity     string `json:"severity"`
	FindingType  string `json:"finding_type"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Region       string `json:"region"`
	AccountID    string `json:"account_id"`
	Title        string `json:"title"`
	Description  string `json:"description"`

	// Environment context
	EnvType            string `json:"env_type"`
	AssetTier          string `json:"asset_tier"`
	DataClassification string `json:"data_classification"`
}

// ComplexityAssessment is the output of remediation complexity analysis.
type ComplexityAssessment struct {
	// Tier classification
	Tier     ComplexityTier `json:"tier"`
	TierName string         `json:"tier_name"`

	// Complexity score (1-100, higher = more complex)
	ComplexityScore int `json:"complexity_score"`

	// Automation candidacy
	AutomationCandidate bool     `json:"automation_candidate"`
	AutomationBlockers  []string `json:"automation_blockers,omitempty"`

	// Coordination requirements
	RequiresAppTeam      bool `json:"requires_app_team"`
	RequiresNetworkTeam  bool `json:"requires_network_team"`
	RequiresDBTeam       bool `json:"requires_db_team"`
	RequiresChangeWindow bool `json:"requires_change_window"`
	RequiresDowntime     bool `json:"requires_downtime"`

	// Service impact
	ServiceImpact        string `json:"service_impact"` // none, minimal, moderate, significant
	EstimatedDowntimeMin int    `json:"estimated_downtime_min,omitempty"`

	// Effort estimation
	EstimatedEffortHours float64 `json:"estimated_effort_hours"`
	RecommendedApproach  string  `json:"recommended_approach"`

	// Explanation
	Rationale         string   `json:"rationale"`
	ComplexityFactors []string `json:"complexity_factors,omitempty"`

	// Metadata
	AssessedAt  time.Time `json:"assessed_at"`
	RuleMatched string    `json:"rule_matched,omitempty"`
	AIAssessed  bool      `json:"ai_assessed"`
}

// ComplexityRule defines a rule for assessing remediation complexity.
type ComplexityRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// Matching criteria
	FindingTypes  []string `json:"finding_types"`  // Glob patterns
	ResourceTypes []string `json:"resource_types"` // Glob patterns
	CloudProvider string   `json:"cloud_provider"` // aws, azure, gcp, or empty for all

	// Assessment output
	Tier                 ComplexityTier `json:"tier"`
	AutomationCandidate  bool           `json:"automation_candidate"`
	AutomationBlockers   []string       `json:"automation_blockers,omitempty"`
	RequiresAppTeam      bool           `json:"requires_app_team"`
	RequiresNetworkTeam  bool           `json:"requires_network_team"`
	RequiresDBTeam       bool           `json:"requires_db_team"`
	RequiresChangeWindow bool           `json:"requires_change_window"`
	RequiresDowntime     bool           `json:"requires_downtime"`
	ServiceImpact        string         `json:"service_impact"`
	EstimatedEffortHours float64        `json:"estimated_effort_hours"`
	RecommendedApproach  string         `json:"recommended_approach"`
}

// ComplexityNormalizer assesses remediation complexity for findings.
type ComplexityNormalizer struct {
	rules            []ComplexityRule
	llmProvider      LLMProvider
	metadataProvider ResourceMetadataProvider
	config           ComplexityConfig
}

// ComplexityConfig holds configuration for complexity assessment.
type ComplexityConfig struct {
	// Bump rules
	ProdEnvironmentBump   bool           // Bump tier +1 for prod
	StatefulResourceBump  bool           // Bump tier +1 for stateful resources
	HighDependencyBump    bool           // Bump tier +1 for >5 dependencies
	SharedResourceMinTier ComplexityTier // Minimum tier for shared resources

	// AI fallback
	UseAIForUnknown bool
	AIModelName     string
	AITemperature   float64
}

// DefaultComplexityConfig returns sensible defaults.
func DefaultComplexityConfig() ComplexityConfig {
	return ComplexityConfig{
		ProdEnvironmentBump:   true,
		StatefulResourceBump:  true,
		HighDependencyBump:    true,
		SharedResourceMinTier: Tier2,
		UseAIForUnknown:       true,
		AIModelName:           "claude-sonnet-4-20250514",
		AITemperature:         0.1,
	}
}

// ResourceMetadataProvider fetches resource metadata for complexity assessment.
type ResourceMetadataProvider interface {
	GetDependencyCount(ctx context.Context, resourceID string) (int, error)
	IsStateful(ctx context.Context, resourceID, resourceType string) (bool, error)
	IsSharedResource(ctx context.Context, resourceID string) (bool, error)
	GetSLATier(ctx context.Context, resourceID string) (string, error)
}

// NewComplexityNormalizer creates a new complexity normalizer.
func NewComplexityNormalizer(
	llm LLMProvider,
	metadata ResourceMetadataProvider,
	config ComplexityConfig,
) *ComplexityNormalizer {
	return &ComplexityNormalizer{
		rules:            defaultComplexityRules(),
		llmProvider:      llm,
		metadataProvider: metadata,
		config:           config,
	}
}

// AssessFinding evaluates remediation complexity for a finding.
func (cn *ComplexityNormalizer) AssessFinding(ctx context.Context, finding *ComplexityFinding) (*ComplexityAssessment, error) {
	// Step 1: Try to match a rule
	rule := cn.matchRule(finding)

	var assessment *ComplexityAssessment

	if rule != nil {
		// Step 2a: Apply rule-based assessment
		assessment = cn.applyRule(rule, finding)
	} else if cn.config.UseAIForUnknown && cn.llmProvider != nil {
		// Step 2b: Fall back to AI assessment
		var err error
		assessment, err = cn.aiAssess(ctx, finding)
		if err != nil {
			// Fall back to conservative estimate
			assessment = cn.conservativeAssessment(finding)
		}
	} else {
		// Step 2c: Conservative default
		assessment = cn.conservativeAssessment(finding)
	}

	// Step 3: Apply environment/resource bumps
	cn.applyBumps(ctx, assessment, finding)

	// Step 4: Calculate complexity score
	assessment.ComplexityScore = cn.calculateScore(assessment)

	// Step 5: Set metadata
	assessment.AssessedAt = time.Now()
	assessment.TierName = assessment.Tier.String()

	return assessment, nil
}

// matchRule finds the first matching complexity rule.
func (cn *ComplexityNormalizer) matchRule(finding *ComplexityFinding) *ComplexityRule {
	for i := range cn.rules {
		rule := &cn.rules[i]

		// Check cloud provider
		if rule.CloudProvider != "" {
			provider := cn.extractCloudProvider(finding.Source)
			if rule.CloudProvider != provider {
				continue
			}
		}

		// Check finding type patterns
		if len(rule.FindingTypes) > 0 {
			if !matchesAnyPattern(finding.FindingType, rule.FindingTypes) {
				continue
			}
		}

		// Check resource type patterns
		if len(rule.ResourceTypes) > 0 {
			if !matchesAnyPattern(finding.ResourceType, rule.ResourceTypes) {
				continue
			}
		}

		return rule
	}
	return nil
}

// applyRule creates an assessment from a matched rule.
func (cn *ComplexityNormalizer) applyRule(rule *ComplexityRule, _ *ComplexityFinding) *ComplexityAssessment {
	return &ComplexityAssessment{
		Tier:                 rule.Tier,
		AutomationCandidate:  rule.AutomationCandidate,
		RequiresAppTeam:      rule.RequiresAppTeam,
		RequiresNetworkTeam:  rule.RequiresNetworkTeam,
		RequiresDBTeam:       rule.RequiresDBTeam,
		RequiresChangeWindow: rule.RequiresChangeWindow,
		RequiresDowntime:     rule.RequiresDowntime,
		ServiceImpact:        rule.ServiceImpact,
		EstimatedEffortHours: rule.EstimatedEffortHours,
		RecommendedApproach:  rule.RecommendedApproach,
		Rationale:            fmt.Sprintf("Matched rule: %s - %s", rule.ID, rule.Description),
		RuleMatched:          rule.ID,
		AIAssessed:           false,
	}
}

// aiAssess uses LLM to assess complexity for unknown finding types.
func (cn *ComplexityNormalizer) aiAssess(ctx context.Context, finding *ComplexityFinding) (*ComplexityAssessment, error) {
	prompt := fmt.Sprintf(`You are a cloud security remediation expert. Assess the complexity of remediating this security finding.

## Finding
- Type: %s
- Title: %s
- Description: %s
- Resource Type: %s
- Resource ID: %s
- Environment: %s
- Data Classification: %s

## Instructions
Assess remediation complexity considering:
1. Technical complexity of the fix
2. Risk of service disruption
3. Team coordination requirements
4. Testing requirements
5. Rollback complexity

Respond with JSON only:
{
  "tier": 1|2|3,
  "automation_candidate": true|false,
  "automation_blockers": ["blocker1"],
  "requires_app_team": true|false,
  "requires_network_team": true|false,
  "requires_db_team": true|false,
  "requires_change_window": true|false,
  "requires_downtime": true|false,
  "service_impact": "none|minimal|moderate|significant",
  "estimated_downtime_min": 0,
  "estimated_effort_hours": 1.0,
  "recommended_approach": "Brief approach description",
  "rationale": "Brief explanation",
  "complexity_factors": ["factor1", "factor2"]
}

Tier guidelines:
- Tier 1: Simple config changes, no coordination, fully automatable (e.g., enable logging, add tags)
- Tier 2: Requires some coordination or testing, partially automatable (e.g., update IAM, modify SG rules)
- Tier 3: Complex changes, significant coordination, manual execution (e.g., database changes, network redesign)`,
		finding.FindingType,
		finding.Title,
		finding.Description,
		finding.ResourceType,
		finding.ResourceID,
		finding.EnvType,
		finding.DataClassification,
	)

	response, err := cn.llmProvider.Complete(ctx, CompletionRequest{
		Model:       cn.config.AIModelName,
		Messages:    []Message{{Role: "user", Content: prompt}},
		Temperature: cn.config.AITemperature,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, err
	}

	// Parse response
	jsonStart := strings.Index(response.Content, "{")
	jsonEnd := strings.LastIndex(response.Content, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no JSON found in response")
	}

	var parsed struct {
		Tier                 int      `json:"tier"`
		AutomationCandidate  bool     `json:"automation_candidate"`
		AutomationBlockers   []string `json:"automation_blockers"`
		RequiresAppTeam      bool     `json:"requires_app_team"`
		RequiresNetworkTeam  bool     `json:"requires_network_team"`
		RequiresDBTeam       bool     `json:"requires_db_team"`
		RequiresChangeWindow bool     `json:"requires_change_window"`
		RequiresDowntime     bool     `json:"requires_downtime"`
		ServiceImpact        string   `json:"service_impact"`
		EstimatedDowntimeMin int      `json:"estimated_downtime_min"`
		EstimatedEffortHours float64  `json:"estimated_effort_hours"`
		RecommendedApproach  string   `json:"recommended_approach"`
		Rationale            string   `json:"rationale"`
		ComplexityFactors    []string `json:"complexity_factors"`
	}

	if err := json.Unmarshal([]byte(response.Content[jsonStart:jsonEnd+1]), &parsed); err != nil {
		return nil, err
	}

	return &ComplexityAssessment{
		Tier:                 ComplexityTier(parsed.Tier),
		AutomationCandidate:  parsed.AutomationCandidate,
		AutomationBlockers:   parsed.AutomationBlockers,
		RequiresAppTeam:      parsed.RequiresAppTeam,
		RequiresNetworkTeam:  parsed.RequiresNetworkTeam,
		RequiresDBTeam:       parsed.RequiresDBTeam,
		RequiresChangeWindow: parsed.RequiresChangeWindow,
		RequiresDowntime:     parsed.RequiresDowntime,
		ServiceImpact:        parsed.ServiceImpact,
		EstimatedDowntimeMin: parsed.EstimatedDowntimeMin,
		EstimatedEffortHours: parsed.EstimatedEffortHours,
		RecommendedApproach:  parsed.RecommendedApproach,
		Rationale:            parsed.Rationale,
		ComplexityFactors:    parsed.ComplexityFactors,
		AIAssessed:           true,
	}, nil
}

// conservativeAssessment returns a conservative default assessment.
func (cn *ComplexityNormalizer) conservativeAssessment(_ *ComplexityFinding) *ComplexityAssessment {
	return &ComplexityAssessment{
		Tier:                 Tier2,
		AutomationCandidate:  false,
		AutomationBlockers:   []string{"Unknown finding type - manual review required"},
		RequiresAppTeam:      true,
		RequiresChangeWindow: true,
		ServiceImpact:        "moderate",
		EstimatedEffortHours: 4.0,
		RecommendedApproach:  "Manual review and remediation by security team with app team coordination",
		Rationale:            "Conservative estimate for unknown finding type",
		AIAssessed:           false,
	}
}

// applyBumps adjusts tier based on environment and resource characteristics.
func (cn *ComplexityNormalizer) applyBumps(ctx context.Context, assessment *ComplexityAssessment, finding *ComplexityFinding) {
	var factors []string

	// Prod environment bump
	if cn.config.ProdEnvironmentBump && finding.EnvType == "prod" {
		if assessment.Tier < Tier3 {
			assessment.Tier++
			factors = append(factors, "Production environment (+1 tier)")
		}
		assessment.RequiresChangeWindow = true
	}

	// Stateful resource bump
	if cn.config.StatefulResourceBump && cn.metadataProvider != nil {
		isStateful, err := cn.metadataProvider.IsStateful(ctx, finding.ResourceID, finding.ResourceType)
		if err == nil && isStateful {
			if assessment.Tier < Tier3 {
				assessment.Tier++
				factors = append(factors, "Stateful resource (+1 tier)")
			}
			assessment.RequiresDowntime = true
		}
	}

	// High dependency bump
	if cn.config.HighDependencyBump && cn.metadataProvider != nil {
		depCount, err := cn.metadataProvider.GetDependencyCount(ctx, finding.ResourceID)
		if err == nil && depCount > 5 {
			if assessment.Tier < Tier3 {
				assessment.Tier++
				factors = append(factors, fmt.Sprintf("High dependencies (%d) (+1 tier)", depCount))
			}
		}
	}

	// Shared resource minimum tier
	if cn.metadataProvider != nil {
		isShared, err := cn.metadataProvider.IsSharedResource(ctx, finding.ResourceID)
		if err == nil && isShared {
			if assessment.Tier < cn.config.SharedResourceMinTier {
				assessment.Tier = cn.config.SharedResourceMinTier
				factors = append(factors, fmt.Sprintf("Shared resource (min Tier%d)", cn.config.SharedResourceMinTier))
			}
			assessment.AutomationCandidate = false
			assessment.AutomationBlockers = append(assessment.AutomationBlockers, "Shared resource requires coordination")
		}
	}

	// Sensitive data bump
	if finding.DataClassification == "PCI" || finding.DataClassification == "PII" || finding.DataClassification == "PHI" {
		assessment.RequiresChangeWindow = true
		if assessment.Tier < Tier2 {
			assessment.Tier = Tier2
			factors = append(factors, fmt.Sprintf("%s data classification (min Tier2)", finding.DataClassification))
		}
	}

	if len(factors) > 0 {
		assessment.ComplexityFactors = append(assessment.ComplexityFactors, factors...)
	}
}

// calculateScore computes a 1-100 complexity score.
func (cn *ComplexityNormalizer) calculateScore(assessment *ComplexityAssessment) int {
	// Base score from tier
	var score int
	switch assessment.Tier {
	case Tier1:
		score = 20
	case Tier2:
		score = 50
	case Tier3:
		score = 80
	}

	// Adjust for coordination requirements
	if assessment.RequiresAppTeam {
		score += 5
	}
	if assessment.RequiresNetworkTeam {
		score += 5
	}
	if assessment.RequiresDBTeam {
		score += 5
	}
	if assessment.RequiresChangeWindow {
		score += 5
	}
	if assessment.RequiresDowntime {
		score += 10
	}

	// Adjust for service impact
	switch assessment.ServiceImpact {
	case "minimal":
		score += 2
	case "moderate":
		score += 5
	case "significant":
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// extractCloudProvider extracts cloud provider from source string.
func (cn *ComplexityNormalizer) extractCloudProvider(source string) string {
	source = strings.ToLower(source)
	if strings.Contains(source, "aws") || strings.Contains(source, "securityhub") {
		return "aws"
	}
	if strings.Contains(source, "azure") || strings.Contains(source, "defender") {
		return "azure"
	}
	if strings.Contains(source, "gcp") || strings.Contains(source, "scc") {
		return "gcp"
	}
	return ""
}

// matchesAnyPattern checks if value matches any glob pattern.
func matchesAnyPattern(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchGlob(pattern, value) {
			return true
		}
	}
	return false
}

// matchGlob performs simple glob matching with * wildcard.
func matchGlob(pattern, value string) bool {
	// Convert glob to regex
	regexStr := "^" + regexp.QuoteMeta(pattern) + "$"
	regexStr = strings.ReplaceAll(regexStr, `\*`, ".*")
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return pattern == value
	}
	return re.MatchString(value)
}

// defaultComplexityRules returns the default rule set.
func defaultComplexityRules() []ComplexityRule {
	return []ComplexityRule{
		// ===========================================
		// AWS Tier 1 - Full Automation Candidates
		// ===========================================
		{
			ID:                   "aws-s3-public-access",
			Name:                 "S3 Public Access Block",
			Description:          "Enable S3 public access block settings",
			FindingTypes:         []string{"S3_BUCKET_PUBLIC_*", "*PublicAccess*"},
			ResourceTypes:        []string{"AWS::S3::Bucket", "AwsS3Bucket"},
			CloudProvider:        "aws",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.25,
			RecommendedApproach:  "Apply S3 Block Public Access settings via API",
		},
		{
			ID:                   "aws-s3-logging",
			Name:                 "S3 Access Logging",
			Description:          "Enable S3 server access logging",
			FindingTypes:         []string{"*S3*LOGGING*", "*ServerAccessLogging*"},
			ResourceTypes:        []string{"AWS::S3::Bucket", "AwsS3Bucket"},
			CloudProvider:        "aws",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.5,
			RecommendedApproach:  "Configure logging bucket and enable access logging",
		},
		{
			ID:                   "aws-ec2-imdsv2",
			Name:                 "EC2 IMDSv2 Required",
			Description:          "Require IMDSv2 for EC2 instances",
			FindingTypes:         []string{"*IMDSv1*", "*IMDS*", "*MetadataService*"},
			ResourceTypes:        []string{"AWS::EC2::Instance", "AwsEc2Instance"},
			CloudProvider:        "aws",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "minimal",
			EstimatedEffortHours: 0.5,
			RecommendedApproach:  "Update instance metadata options to require IMDSv2",
		},
		{
			ID:                   "aws-resource-tags",
			Name:                 "Missing Resource Tags",
			Description:          "Add required tags to resources",
			FindingTypes:         []string{"*MISSING_TAG*", "*RequiredTags*", "*Tagging*"},
			CloudProvider:        "aws",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.25,
			RecommendedApproach:  "Apply required tags via AWS Resource Groups Tagging API",
		},
		{
			ID:                   "aws-cloudtrail-logging",
			Name:                 "CloudTrail Logging",
			Description:          "Enable CloudTrail logging",
			FindingTypes:         []string{"*CloudTrail*Logging*", "*CLOUDTRAIL*"},
			CloudProvider:        "aws",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.5,
			RecommendedApproach:  "Create or update CloudTrail trail configuration",
		},

		// ===========================================
		// AWS Tier 2 - Partial Automation
		// ===========================================
		{
			ID:                   "aws-sg-open-ports",
			Name:                 "Security Group Open Ports",
			Description:          "Restrict overly permissive security group rules",
			FindingTypes:         []string{"*SecurityGroup*", "*SG*OPEN*", "*UnrestrictedAccess*"},
			ResourceTypes:        []string{"AWS::EC2::SecurityGroup", "AwsEc2SecurityGroup"},
			CloudProvider:        "aws",
			Tier:                 Tier2,
			AutomationCandidate:  true,
			RequiresAppTeam:      true,
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 2.0,
			RecommendedApproach:  "Review active connections, update rules with specific CIDR blocks",
		},
		{
			ID:                   "aws-iam-policies",
			Name:                 "IAM Policy Restrictions",
			Description:          "Tighten overly permissive IAM policies",
			FindingTypes:         []string{"*IAM*POLICY*", "*OverlyPermissive*", "*AdminAccess*"},
			ResourceTypes:        []string{"AWS::IAM::*"},
			CloudProvider:        "aws",
			Tier:                 Tier2,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			AutomationBlockers:   []string{"Requires understanding of application permissions"},
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 4.0,
			RecommendedApproach:  "Analyze CloudTrail for actual permissions used, apply least privilege",
		},
		{
			ID:                   "aws-encryption-transit",
			Name:                 "Encryption in Transit",
			Description:          "Enable TLS/SSL for services",
			FindingTypes:         []string{"*TLS*", "*SSL*", "*Encryption*Transit*"},
			CloudProvider:        "aws",
			Tier:                 Tier2,
			AutomationCandidate:  true,
			RequiresAppTeam:      true,
			RequiresChangeWindow: true,
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 4.0,
			RecommendedApproach:  "Update listener configurations, ensure clients support TLS",
		},
		{
			ID:                   "aws-patching",
			Name:                 "OS/Software Patching",
			Description:          "Apply security patches",
			FindingTypes:         []string{"*CVE-*", "*Vulnerability*", "*Patch*"},
			ResourceTypes:        []string{"AWS::EC2::Instance", "AwsEc2Instance"},
			CloudProvider:        "aws",
			Tier:                 Tier2,
			AutomationCandidate:  true,
			RequiresAppTeam:      true,
			RequiresChangeWindow: true,
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 2.0,
			RecommendedApproach:  "Use SSM Patch Manager with maintenance windows",
		},

		// ===========================================
		// AWS Tier 3 - Manual Execution Required
		// ===========================================
		{
			ID:                   "aws-rds-config",
			Name:                 "RDS Configuration Changes",
			Description:          "Database engine or parameter changes",
			FindingTypes:         []string{"*RDS*CONFIG*", "*Database*Encryption*"},
			ResourceTypes:        []string{"AWS::RDS::*"},
			CloudProvider:        "aws",
			Tier:                 Tier3,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			RequiresDBTeam:       true,
			RequiresChangeWindow: true,
			RequiresDowntime:     true,
			AutomationBlockers:   []string{"Database changes require extensive testing", "Potential data migration"},
			ServiceImpact:        "significant",
			EstimatedEffortHours: 8.0,
			RecommendedApproach:  "Plan migration with snapshot, test in non-prod first",
		},
		{
			ID:                   "aws-network-architecture",
			Name:                 "Network Architecture Changes",
			Description:          "VPC, subnet, or routing changes",
			FindingTypes:         []string{"*VPC*", "*Network*Architecture*", "*Routing*"},
			ResourceTypes:        []string{"AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::RouteTable"},
			CloudProvider:        "aws",
			Tier:                 Tier3,
			AutomationCandidate:  false,
			RequiresNetworkTeam:  true,
			RequiresAppTeam:      true,
			RequiresChangeWindow: true,
			AutomationBlockers:   []string{"Network changes affect multiple services", "Complex rollback"},
			ServiceImpact:        "significant",
			EstimatedEffortHours: 16.0,
			RecommendedApproach:  "Design change with network team, implement in maintenance window",
		},
		{
			ID:                   "aws-critical-patching",
			Name:                 "Critical Vulnerability Patching",
			Description:          "Patches for critical CVEs",
			FindingTypes:         []string{"*CVE-*"},
			CloudProvider:        "aws",
			Tier:                 Tier3,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			RequiresChangeWindow: true,
			RequiresDowntime:     true,
			AutomationBlockers:   []string{"Critical patches require extensive testing"},
			ServiceImpact:        "significant",
			EstimatedEffortHours: 8.0,
			RecommendedApproach:  "Emergency change process, test in staging, rolling deployment",
		},

		// ===========================================
		// Azure Tier 1 - Full Automation Candidates
		// ===========================================
		{
			ID:                   "azure-storage-https",
			Name:                 "Storage Account HTTPS",
			Description:          "Require HTTPS for storage accounts",
			FindingTypes:         []string{"*HTTPS*", "*SecureTransfer*"},
			ResourceTypes:        []string{"Microsoft.Storage/storageAccounts"},
			CloudProvider:        "azure",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "minimal",
			EstimatedEffortHours: 0.5,
			RecommendedApproach:  "Enable supportsHttpsTrafficOnly property",
		},
		{
			ID:                   "azure-diagnostic-logging",
			Name:                 "Diagnostic Logging",
			Description:          "Enable diagnostic settings",
			FindingTypes:         []string{"*Diagnostic*", "*Logging*"},
			CloudProvider:        "azure",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.5,
			RecommendedApproach:  "Configure diagnostic settings to Log Analytics workspace",
		},

		// ===========================================
		// Azure Tier 2 - Partial Automation
		// ===========================================
		{
			ID:                   "azure-nsg-rules",
			Name:                 "NSG Rule Restrictions",
			Description:          "Tighten network security group rules",
			FindingTypes:         []string{"*NSG*", "*NetworkSecurityGroup*", "*UnrestrictedAccess*"},
			ResourceTypes:        []string{"Microsoft.Network/networkSecurityGroups"},
			CloudProvider:        "azure",
			Tier:                 Tier2,
			AutomationCandidate:  true,
			RequiresAppTeam:      true,
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 2.0,
			RecommendedApproach:  "Review NSG flow logs, update rules with specific IP ranges",
		},
		{
			ID:                   "azure-keyvault-access",
			Name:                 "Key Vault Access Policies",
			Description:          "Restrict Key Vault access",
			FindingTypes:         []string{"*KeyVault*Access*", "*SecretManagement*"},
			ResourceTypes:        []string{"Microsoft.KeyVault/vaults"},
			CloudProvider:        "azure",
			Tier:                 Tier2,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			AutomationBlockers:   []string{"Requires understanding of application secret access"},
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 4.0,
			RecommendedApproach:  "Audit access policies, implement RBAC, remove excessive permissions",
		},

		// ===========================================
		// Azure Tier 3 - Manual Execution Required
		// ===========================================
		{
			ID:                   "azure-sql-config",
			Name:                 "Azure SQL Configuration",
			Description:          "Database security configuration changes",
			FindingTypes:         []string{"*SQL*TDE*", "*SQL*Audit*", "*DatabaseEncryption*"},
			ResourceTypes:        []string{"Microsoft.Sql/*"},
			CloudProvider:        "azure",
			Tier:                 Tier3,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			RequiresDBTeam:       true,
			RequiresChangeWindow: true,
			AutomationBlockers:   []string{"Database changes require downtime planning"},
			ServiceImpact:        "significant",
			EstimatedEffortHours: 8.0,
			RecommendedApproach:  "Plan with DBA, test in non-prod, implement in maintenance window",
		},

		// ===========================================
		// GCP Tier 1 - Full Automation Candidates
		// ===========================================
		{
			ID:                   "gcp-bucket-public",
			Name:                 "GCS Public Access",
			Description:          "Remove public access from Cloud Storage buckets",
			FindingTypes:         []string{"*PUBLIC_BUCKET*", "*AllUsers*", "*AllAuthenticatedUsers*"},
			ResourceTypes:        []string{"storage.googleapis.com/*"},
			CloudProvider:        "gcp",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.25,
			RecommendedApproach:  "Update IAM bindings to remove allUsers/allAuthenticatedUsers",
		},
		{
			ID:                   "gcp-audit-logging",
			Name:                 "Audit Logging",
			Description:          "Enable audit logging for GCP services",
			FindingTypes:         []string{"*AUDIT_LOGGING*", "*DataAccess*"},
			CloudProvider:        "gcp",
			Tier:                 Tier1,
			AutomationCandidate:  true,
			ServiceImpact:        "none",
			EstimatedEffortHours: 0.5,
			RecommendedApproach:  "Update audit log config in IAM policy",
		},

		// ===========================================
		// GCP Tier 2 - Partial Automation
		// ===========================================
		{
			ID:                   "gcp-firewall-rules",
			Name:                 "VPC Firewall Rules",
			Description:          "Restrict overly permissive firewall rules",
			FindingTypes:         []string{"*FIREWALL*", "*OPEN_*_PORT*"},
			ResourceTypes:        []string{"compute.googleapis.com/Firewall"},
			CloudProvider:        "gcp",
			Tier:                 Tier2,
			AutomationCandidate:  true,
			RequiresAppTeam:      true,
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 2.0,
			RecommendedApproach:  "Review firewall logs, update rules with specific source ranges",
		},
		{
			ID:                   "gcp-iam-bindings",
			Name:                 "IAM Binding Restrictions",
			Description:          "Remove overly permissive IAM bindings",
			FindingTypes:         []string{"*IAM*", "*OverlyPermissive*", "*PrimitiveRoles*"},
			CloudProvider:        "gcp",
			Tier:                 Tier2,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			AutomationBlockers:   []string{"Requires understanding of application permissions"},
			ServiceImpact:        "moderate",
			EstimatedEffortHours: 4.0,
			RecommendedApproach:  "Analyze access logs, replace primitive roles with predefined roles",
		},

		// ===========================================
		// GCP Tier 3 - Manual Execution Required
		// ===========================================
		{
			ID:                   "gcp-sql-config",
			Name:                 "Cloud SQL Configuration",
			Description:          "Database security configuration changes",
			FindingTypes:         []string{"*SQL*SSL*", "*SQL*PUBLIC*", "*DatabaseEncryption*"},
			ResourceTypes:        []string{"sqladmin.googleapis.com/*"},
			CloudProvider:        "gcp",
			Tier:                 Tier3,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			RequiresDBTeam:       true,
			RequiresChangeWindow: true,
			RequiresDowntime:     true,
			AutomationBlockers:   []string{"Database changes require instance restart"},
			ServiceImpact:        "significant",
			EstimatedEffortHours: 8.0,
			RecommendedApproach:  "Plan maintenance window, configure with read replica failover",
		},
		{
			ID:                   "gcp-gke-config",
			Name:                 "GKE Cluster Configuration",
			Description:          "Kubernetes cluster security changes",
			FindingTypes:         []string{"*GKE*", "*Kubernetes*", "*CLUSTER_*"},
			ResourceTypes:        []string{"container.googleapis.com/*"},
			CloudProvider:        "gcp",
			Tier:                 Tier3,
			AutomationCandidate:  false,
			RequiresAppTeam:      true,
			RequiresChangeWindow: true,
			AutomationBlockers:   []string{"Cluster changes may require node pool recreation"},
			ServiceImpact:        "significant",
			EstimatedEffortHours: 16.0,
			RecommendedApproach:  "Plan with platform team, use blue-green node pool upgrade",
		},
	}
}
