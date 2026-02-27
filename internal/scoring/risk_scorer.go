// Package scoring provides AI-powered finding prioritization combining
// contextual risk assessment with remediation complexity analysis.
package scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Finding represents a security finding to be scored.
type Finding struct {
	ID           string    `json:"id"`
	Source       string    `json:"source"`       // aws-securityhub, azure-defender, gcp-scc
	Severity     string    `json:"severity"`     // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	FindingType  string    `json:"finding_type"` // e.g., S3_BUCKET_PUBLIC_READ, CVE-2024-1234
	ResourceID   string    `json:"resource_id"`
	ResourceType string    `json:"resource_type"` // e.g., AWS::S3::Bucket
	Region       string    `json:"region"`
	AccountID    string    `json:"account_id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	FirstSeen    time.Time `json:"first_seen"`
	DaysOpen     int       `json:"days_open"`

	// Context populated by enricher
	Context FindingContext `json:"context"`
}

// FindingContext provides business and technical context for risk assessment.
type FindingContext struct {
	// Asset classification
	AssetTier          string `json:"asset_tier"`          // Tier1-Prod, Tier2-NonProd, Tier3-Dev
	EnvType            string `json:"env_type"`            // prod, staging, dev, sandbox
	DataClassification string `json:"data_classification"` // PCI, PII, PHI, Public, Internal

	// Network exposure
	InternetFacing   bool   `json:"internet_facing"`
	VPCType          string `json:"vpc_type"` // isolated, shared, transit
	IngressPorts     []int  `json:"ingress_ports,omitempty"`
	EgressRestricted bool   `json:"egress_restricted"`

	// Compensating controls
	WAFEnabled          bool `json:"waf_enabled"`
	EDREnabled          bool `json:"edr_enabled"`
	DLPEnabled          bool `json:"dlp_enabled"`
	EncryptionAtRest    bool `json:"encryption_at_rest"`
	EncryptionInTransit bool `json:"encryption_in_transit"`
	MFARequired         bool `json:"mfa_required"`
	PrivateEndpoint     bool `json:"private_endpoint"`

	// Vulnerability context (for CVE findings)
	CVSSScore        float64 `json:"cvss_score,omitempty"`
	ExploitAvailable bool    `json:"exploit_available"`
	ExploitInWild    bool    `json:"exploit_in_wild"`
	PackageInUse     *bool   `json:"package_in_use,omitempty"` // nil = unknown
	PatchAvailable   bool    `json:"patch_available"`

	// Historical patterns
	FalsePositiveHistory int     `json:"false_positive_history"` // Count of FPs for similar findings
	FPRateForType        float64 `json:"fp_rate_for_type"`       // Historical FP rate 0.0-1.0

	// Business context
	BusinessCriticality string   `json:"business_criticality"` // critical, high, medium, low
	ComplianceScopes    []string `json:"compliance_scopes"`    // PCI-DSS, SOC2, HIPAA
	DataResidency       string   `json:"data_residency"`       // us, eu, apac
	CostCenter          string   `json:"cost_center"`
	ApplicationOwner    string   `json:"application_owner"`
	SupportTier         string   `json:"support_tier"` // platinum, gold, silver, bronze

	// Threat intelligence enrichment
	InKEV          bool    `json:"in_kev"`               // CISA Known Exploited Vulnerabilities
	EPSSScore      float64 `json:"epss_score,omitempty"` // 0.0-1.0 exploitation probability
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`

	// Attack path context
	AttackPathScore    float64 `json:"attack_path_score,omitempty"` // 0-100
	IsToxicCombination bool    `json:"is_toxic_combination"`
	BlastRadiusCount   int     `json:"blast_radius_count,omitempty"`

	// Network rule context (for FN escalation rules)
	IngressCIDRs []string `json:"ingress_cidrs,omitempty"` // e.g., ["10.0.0.0/8", "0.0.0.0/0"]

	// Credential context (for FN escalation rules)
	CredentialLastUsedDays int  `json:"credential_last_used_days,omitempty"`
	HasAdminPermissions    bool `json:"has_admin_permissions"`
}

// RiskAssessment is the output of contextual risk scoring.
type RiskAssessment struct {
	// Original and adjusted severity
	OriginalSeverity  string `json:"original_severity"`
	AdjustedSeverity  string `json:"adjusted_severity"`
	SeverityChanged   bool   `json:"severity_changed"`
	SeverityDirection string `json:"severity_direction"` // upgraded, downgraded, unchanged

	// Risk score (1-100)
	RiskScore int `json:"risk_score"`

	// Confidence in assessment
	Confidence float64 `json:"confidence"` // 0.0-1.0

	// Explanation
	Rationale          string   `json:"rationale"`
	MitigatingFactors  []string `json:"mitigating_factors,omitempty"`
	AggravatingFactors []string `json:"aggravating_factors,omitempty"`

	// Recommended action
	RecommendedAction string `json:"recommended_action"` // remediate, accept_risk, investigate, suppress

	// Auto-accept eligibility
	AutoAcceptEligible bool   `json:"auto_accept_eligible"`
	AutoAcceptReason   string `json:"auto_accept_reason,omitempty"`

	// Metadata
	ScoredAt         time.Time `json:"scored_at"`
	ModelUsed        string    `json:"model_used"`
	PromptTokens     int       `json:"prompt_tokens,omitempty"`
	CompletionTokens int       `json:"completion_tokens,omitempty"`
}

// DeterministicRuleResult captures the output of a single deterministic FP or FN rule.
// It contains enough information to build a RiskAssessment without importing pkg/contextual.
type DeterministicRuleResult struct {
	OriginalSeverity   string
	AdjustedSeverity   string
	Applied            bool
	Confidence         float64
	Reason             string
	Pattern            string
	SuggestedRiskScore int
}

// FPEvaluator evaluates deterministic false-positive suppression rules.
// Defined in the consuming package (scoring) per Go interface ownership convention.
type FPEvaluator interface {
	Evaluate(f Finding) (*DeterministicRuleResult, bool)
}

// FNEvaluator evaluates deterministic false-negative escalation rules.
// Defined in the consuming package (scoring) per Go interface ownership convention.
type FNEvaluator interface {
	Evaluate(f Finding) (*DeterministicRuleResult, bool)
}

// RiskScorer performs AI-powered contextual risk assessment.
type RiskScorer struct {
	llmProvider   LLMProvider
	enricher      ContextEnricher
	fpStore       FPHistoryStore
	promptBuilder *RiskScorerPromptBuilder
	config        RiskScorerConfig
	fpRuleEngine  FPEvaluator
	fnRuleEngine  FNEvaluator
}

// RiskScorerConfig holds configuration for the risk scorer.
type RiskScorerConfig struct {
	// Model settings
	ModelName   string
	Temperature float64
	MaxTokens   int

	// Business rules
	NeverDowngradeCriticalProdInternetFacing bool
	MinimumSeverityForPCIPII                 string
	AutoAcceptLowInSandbox                   bool
	CapConfidenceWhenPackageUsageUnknown     float64

	// Thresholds
	HighFPRateThreshold float64 // Above this, consider downgrade
	LowFPRateThreshold  float64 // Below this, trust the severity
}

// DefaultRiskScorerConfig returns sensible defaults.
func DefaultRiskScorerConfig() RiskScorerConfig {
	return RiskScorerConfig{
		ModelName:                                "claude-opus-4-6",
		Temperature:                              0.1,
		MaxTokens:                                1024,
		NeverDowngradeCriticalProdInternetFacing: true,
		MinimumSeverityForPCIPII:                 "MEDIUM",
		AutoAcceptLowInSandbox:                   true,
		CapConfidenceWhenPackageUsageUnknown:     0.7,
		HighFPRateThreshold:                      0.3,
		LowFPRateThreshold:                       0.05,
	}
}

// NewRiskScorer creates a new contextual risk scorer.
// The FP and FN rule engines default to nil (disabled). Use WithRuleEngines to
// wire in deterministic rule evaluation.
func NewRiskScorer(
	llm LLMProvider,
	enricher ContextEnricher,
	fpStore FPHistoryStore,
	config RiskScorerConfig,
) *RiskScorer {
	return &RiskScorer{
		llmProvider:   llm,
		enricher:      enricher,
		fpStore:       fpStore,
		promptBuilder: NewRiskScorerPromptBuilder(),
		config:        config,
	}
}

// WithRuleEngines attaches deterministic FP suppression and FN escalation engines
// to the scorer. Call this after NewRiskScorer when the contextual rule engines
// are available (typically at the application wiring layer to avoid import cycles).
func (rs *RiskScorer) WithRuleEngines(fp FPEvaluator, fn FNEvaluator) *RiskScorer {
	rs.fpRuleEngine = fp
	rs.fnRuleEngine = fn
	return rs
}

// ScoreFinding performs contextual risk assessment on a finding.
func (rs *RiskScorer) ScoreFinding(ctx context.Context, finding *Finding) (*RiskAssessment, error) {
	// Step 1: Enrich context if not already populated
	if finding.Context.AssetTier == "" {
		if err := rs.enricher.EnrichContext(ctx, finding); err != nil {
			slog.Warn("context enrichment failed, continuing with limited context",
				"finding_id", finding.ID, "error", err)
		}
	}

	// Step 2: Load FP history
	if rs.fpStore != nil {
		fpCount, fpRate, _ := rs.fpStore.GetFPStats(ctx, finding.FindingType, finding.ResourceType)
		finding.Context.FalsePositiveHistory = fpCount
		finding.Context.FPRateForType = fpRate
	}

	// Step 3: Check for auto-accept scenarios (skip LLM)
	if assessment := rs.checkAutoAccept(finding); assessment != nil {
		return assessment, nil
	}

	// Step 3.5: Check deterministic FP/FN rules
	if assessment := rs.checkDeterministicRules(finding); assessment != nil {
		return assessment, nil
	}

	// Step 4: Build prompt
	prompt := rs.promptBuilder.BuildPrompt(finding)

	// Step 5: Call LLM (clone request to prevent shared mutable state)
	req := CompletionRequest{
		Model:       rs.config.ModelName,
		Messages:    []Message{{Role: "user", Content: prompt}},
		Temperature: rs.config.Temperature,
		MaxTokens:   rs.config.MaxTokens,
	}
	response, err := rs.llmProvider.Complete(ctx, req.Clone())
	if err != nil {
		return nil, fmt.Errorf("LLM completion failed: %w", err)
	}

	// Step 6: Parse response
	assessment, err := rs.parseResponse(response.Content, finding)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	// Step 7: Apply guardrails
	rs.applyGuardrails(assessment, finding)

	// Step 8: Set metadata
	assessment.ScoredAt = time.Now()
	assessment.ModelUsed = rs.config.ModelName
	assessment.PromptTokens = response.Usage.PromptTokens
	assessment.CompletionTokens = response.Usage.CompletionTokens

	return assessment, nil
}

// checkAutoAccept determines if finding qualifies for automatic risk acceptance.
func (rs *RiskScorer) checkAutoAccept(finding *Finding) *RiskAssessment {
	// Auto-accept LOW severity in sandbox environments
	if rs.config.AutoAcceptLowInSandbox &&
		finding.Severity == "LOW" &&
		finding.Context.EnvType == "sandbox" {
		return &RiskAssessment{
			OriginalSeverity:   finding.Severity,
			AdjustedSeverity:   "LOW",
			SeverityChanged:    false,
			SeverityDirection:  "unchanged",
			RiskScore:          15,
			Confidence:         0.95,
			Rationale:          "LOW severity finding in sandbox environment auto-accepted per policy",
			RecommendedAction:  "accept_risk",
			AutoAcceptEligible: true,
			AutoAcceptReason:   "sandbox_low_severity",
			ScoredAt:           time.Now(),
			ModelUsed:          "rule_based",
		}
	}

	// Auto-accept if high FP rate and non-critical
	if finding.Context.FPRateForType > rs.config.HighFPRateThreshold &&
		finding.Severity != "CRITICAL" &&
		finding.Context.FalsePositiveHistory >= 3 {
		return &RiskAssessment{
			OriginalSeverity:   finding.Severity,
			AdjustedSeverity:   "LOW",
			SeverityChanged:    true,
			SeverityDirection:  "downgraded",
			RiskScore:          20,
			Confidence:         0.85,
			Rationale:          fmt.Sprintf("Finding type has %.0f%% historical false positive rate with %d prior FPs", finding.Context.FPRateForType*100, finding.Context.FalsePositiveHistory),
			MitigatingFactors:  []string{"High false positive rate", "Historical pattern"},
			RecommendedAction:  "accept_risk",
			AutoAcceptEligible: true,
			AutoAcceptReason:   "high_fp_rate",
			ScoredAt:           time.Now(),
			ModelUsed:          "rule_based",
		}
	}

	return nil
}

// checkDeterministicRules runs the FP and FN rule engines in priority order.
// FP suppression is checked first; if a rule matches, the finding is returned
// immediately without escalation checks. FN escalation is checked second.
// A rule may match without changing severity (Applied==false) when the finding
// severity is already at the target level; this still short-circuits the LLM
// to prevent the model from re-escalating a correctly-assessed finding.
// Returns nil when no rule matches (caller should proceed to LLM scoring).
func (rs *RiskScorer) checkDeterministicRules(finding *Finding) *RiskAssessment {
	// FP rules have priority — suppress before escalating.
	if rs.fpRuleEngine != nil {
		if result, matched := rs.fpRuleEngine.Evaluate(*finding); matched {
			riskScore := result.SuggestedRiskScore
			if riskScore == 0 {
				riskScore = severityToMinScore(result.AdjustedSeverity)
			}
			dir := "downgraded"
			if !result.Applied {
				dir = "unchanged"
			}
			assessment := &RiskAssessment{
				OriginalSeverity:   finding.Severity,
				AdjustedSeverity:   result.AdjustedSeverity,
				SeverityChanged:    result.Applied,
				SeverityDirection:  dir,
				RiskScore:          riskScore,
				Confidence:         result.Confidence,
				Rationale:          result.Reason,
				MitigatingFactors:  []string{result.Pattern},
				RecommendedAction:  "accept_risk",
				AutoAcceptEligible: true,
				AutoAcceptReason:   result.Pattern,
				ScoredAt:           time.Now(),
				ModelUsed:          "rule_based",
			}
			rs.applyGuardrails(assessment, finding)
			return assessment
		}
	}

	// FN rules escalate findings the LLM might under-rate.
	if rs.fnRuleEngine != nil {
		if result, matched := rs.fnRuleEngine.Evaluate(*finding); matched {
			riskScore := result.SuggestedRiskScore
			if riskScore == 0 {
				riskScore = severityToMinScore(result.AdjustedSeverity)
			}
			dir := "upgraded"
			if !result.Applied {
				dir = "unchanged"
			}
			assessment := &RiskAssessment{
				OriginalSeverity:   finding.Severity,
				AdjustedSeverity:   result.AdjustedSeverity,
				SeverityChanged:    result.Applied,
				SeverityDirection:  dir,
				RiskScore:          riskScore,
				Confidence:         result.Confidence,
				Rationale:          result.Reason,
				AggravatingFactors: []string{result.Reason},
				RecommendedAction:  "remediate",
				ScoredAt:           time.Now(),
				ModelUsed:          "rule_based",
			}
			rs.applyGuardrails(assessment, finding)
			return assessment
		}
	}

	return nil
}

// parseResponse extracts RiskAssessment from LLM response.
func (rs *RiskScorer) parseResponse(content string, finding *Finding) (*RiskAssessment, error) {
	// Extract JSON from response
	jsonStart := strings.Index(content, "{")
	jsonEnd := strings.LastIndex(content, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := content[jsonStart : jsonEnd+1]

	var response struct {
		AdjustedSeverity   string   `json:"adjusted_severity"`
		RiskScore          int      `json:"risk_score"`
		Confidence         float64  `json:"confidence"`
		Rationale          string   `json:"rationale"`
		MitigatingFactors  []string `json:"mitigating_factors"`
		AggravatingFactors []string `json:"aggravating_factors"`
		RecommendedAction  string   `json:"recommended_action"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	assessment := &RiskAssessment{
		OriginalSeverity:   finding.Severity,
		AdjustedSeverity:   response.AdjustedSeverity,
		RiskScore:          response.RiskScore,
		Confidence:         response.Confidence,
		Rationale:          response.Rationale,
		MitigatingFactors:  response.MitigatingFactors,
		AggravatingFactors: response.AggravatingFactors,
		RecommendedAction:  response.RecommendedAction,
	}

	// Determine if severity changed
	assessment.SeverityChanged = assessment.OriginalSeverity != assessment.AdjustedSeverity
	if assessment.SeverityChanged {
		if severityToInt(assessment.AdjustedSeverity) < severityToInt(assessment.OriginalSeverity) {
			assessment.SeverityDirection = "upgraded"
		} else {
			assessment.SeverityDirection = "downgraded"
		}
	} else {
		assessment.SeverityDirection = "unchanged"
	}

	return assessment, nil
}

// applyGuardrails enforces business rules on the assessment.
func (rs *RiskScorer) applyGuardrails(assessment *RiskAssessment, finding *Finding) {
	// Rule 1: Never downgrade CRITICAL on Tier1-Prod + internet-facing
	if rs.config.NeverDowngradeCriticalProdInternetFacing {
		if finding.Severity == "CRITICAL" &&
			finding.Context.AssetTier == "Tier1-Prod" &&
			finding.Context.InternetFacing {
			if severityToInt(assessment.AdjustedSeverity) > severityToInt("CRITICAL") {
				assessment.AdjustedSeverity = "CRITICAL"
				assessment.SeverityChanged = false
				assessment.SeverityDirection = "unchanged"
				assessment.AggravatingFactors = append(assessment.AggravatingFactors,
					"Guardrail: CRITICAL severity preserved for Tier1-Prod internet-facing asset")
			}
		}
	}

	// Rule 2: Minimum severity for PCI/PII data
	if rs.config.MinimumSeverityForPCIPII != "" {
		if finding.Context.DataClassification == "PCI" || finding.Context.DataClassification == "PII" {
			minSev := severityToInt(rs.config.MinimumSeverityForPCIPII)
			if severityToInt(assessment.AdjustedSeverity) > minSev {
				assessment.AdjustedSeverity = rs.config.MinimumSeverityForPCIPII
				assessment.AggravatingFactors = append(assessment.AggravatingFactors,
					fmt.Sprintf("Guardrail: Minimum %s severity for %s data", rs.config.MinimumSeverityForPCIPII, finding.Context.DataClassification))
			}
		}
	}

	// Rule 3: Cap confidence when package usage unknown
	if finding.Context.PackageInUse == nil && rs.config.CapConfidenceWhenPackageUsageUnknown > 0 {
		if assessment.Confidence > rs.config.CapConfidenceWhenPackageUsageUnknown {
			assessment.Confidence = rs.config.CapConfidenceWhenPackageUsageUnknown
			assessment.Rationale += " (Confidence capped: package usage unknown)"
		}
	}

	// Rule 4: Ensure risk score aligns with severity
	minScore := severityToMinScore(assessment.AdjustedSeverity)
	maxScore := severityToMaxScore(assessment.AdjustedSeverity)
	if assessment.RiskScore < minScore {
		assessment.RiskScore = minScore
	}
	if assessment.RiskScore > maxScore {
		assessment.RiskScore = maxScore
	}
}

// Helper functions

// envSeverityMultiplier returns the severity adjustment multiplier for the
// given environment string. Mirrors the logic in pkg/contextual.EnvironmentTier.
func envSeverityMultiplier(envType string) float64 {
	switch envType {
	case "prod", "production":
		return 1.0
	case "staging", "stg", "preprod":
		return 0.8
	case "dev", "development":
		return 0.5
	case "sandbox", "sbx", "test", "qa", "uat":
		return 0.3
	default:
		return 1.0 // unknown — treat conservatively
	}
}

func severityToInt(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 1
	case "HIGH":
		return 2
	case "MEDIUM":
		return 3
	case "LOW":
		return 4
	case "INFORMATIONAL":
		return 5
	default:
		return 5
	}
}

func severityToMinScore(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 85
	case "HIGH":
		return 65
	case "MEDIUM":
		return 40
	case "LOW":
		return 15
	default:
		return 1
	}
}

func severityToMaxScore(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 100
	case "HIGH":
		return 84
	case "MEDIUM":
		return 64
	case "LOW":
		return 39
	default:
		return 14
	}
}

// RiskScorerPromptBuilder constructs prompts for risk assessment.
type RiskScorerPromptBuilder struct{}

// NewRiskScorerPromptBuilder creates a new prompt builder.
func NewRiskScorerPromptBuilder() *RiskScorerPromptBuilder {
	return &RiskScorerPromptBuilder{}
}

// BuildPrompt constructs the prompt for risk assessment.
func (pb *RiskScorerPromptBuilder) BuildPrompt(finding *Finding) string {
	ctx := finding.Context

	sanitize := func(s string) string {
		// Strip markdown/prompt injection patterns
		for _, pat := range []string{"```", "## ", "# ", "---", "<script", "{{", "}}", "${", "SYSTEM:", "ASSISTANT:"} {
			s = strings.ReplaceAll(s, pat, "")
		}
		// Remove control characters (keep printable ASCII + valid UTF-8)
		s = strings.Map(func(r rune) rune {
			if r < 0x20 && r != '\n' && r != '\t' {
				return -1
			}
			return r
		}, s)
		// Rune-safe truncation
		runes := []rune(s)
		if len(runes) > 500 {
			s = string(runes[:500])
		}
		return s
	}

	prompt := fmt.Sprintf(`You are a security risk analyst. Assess this finding and provide contextual risk adjustment.

## Finding
- ID: %s
- Type: %s
- Title: %s
- Original Severity: %s
- Resource: %s (%s)
- Account: %s
- Days Open: %d

## Asset Context
- Asset Tier: %s
- Environment: %s
- Data Classification: %s
- Business Criticality: %s
- Compliance Scopes: %v

## Network Exposure
- Internet Facing: %t
- VPC Type: %s
- Egress Restricted: %t

## Compensating Controls
- WAF: %t
- EDR: %t
- DLP: %t
- Encryption at Rest: %t
- Encryption in Transit: %t
- MFA Required: %t
- Private Endpoint: %t
`,
		sanitize(finding.ID),
		sanitize(finding.FindingType),
		sanitize(finding.Title),
		sanitize(finding.Severity),
		sanitize(finding.ResourceID),
		sanitize(finding.ResourceType),
		sanitize(finding.AccountID),
		finding.DaysOpen,
		ctx.AssetTier,
		ctx.EnvType,
		ctx.DataClassification,
		ctx.BusinessCriticality,
		ctx.ComplianceScopes,
		ctx.InternetFacing,
		ctx.VPCType,
		ctx.EgressRestricted,
		ctx.WAFEnabled,
		ctx.EDREnabled,
		ctx.DLPEnabled,
		ctx.EncryptionAtRest,
		ctx.EncryptionInTransit,
		ctx.MFARequired,
		ctx.PrivateEndpoint,
	)

	// Add vulnerability context if present
	if ctx.CVSSScore > 0 {
		prompt += fmt.Sprintf(`
## Vulnerability Context
- CVSS Score: %.1f
- Exploit Available: %t
- Exploit in Wild: %t
- Package in Use: %v
- Patch Available: %t
`,
			ctx.CVSSScore,
			ctx.ExploitAvailable,
			ctx.ExploitInWild,
			ctx.PackageInUse,
			ctx.PatchAvailable,
		)
	}

	// Add FP history if present
	if ctx.FalsePositiveHistory > 0 {
		prompt += fmt.Sprintf(`
## Historical Pattern
- False Positive Count: %d
- FP Rate for Type: %.1f%%
`,
			ctx.FalsePositiveHistory,
			ctx.FPRateForType*100,
		)
	}

	// Add threat intelligence context if present
	if ctx.InKEV || ctx.EPSSScore > 0 || ctx.AttackPathScore > 0 {
		prompt += fmt.Sprintf(`
## Threat Intelligence
- In CISA KEV: %t
- EPSS Score: %.4f (percentile: %.2f)
- Attack Path Score: %.1f
- Toxic Combination: %t
- Blast Radius (reachable resources): %d
`,
			ctx.InKEV,
			ctx.EPSSScore,
			ctx.EPSSPercentile,
			ctx.AttackPathScore,
			ctx.IsToxicCombination,
			ctx.BlastRadiusCount,
		)
	}

	// Add high-signal threat intelligence alerts as prominent standalone lines.
	// These appear unconditionally when the relevant data is populated so the LLM
	// cannot miss them when adjusting severity.
	if ctx.EPSSScore > 0 {
		prompt += fmt.Sprintf("EPSS exploitation probability: %.4f (percentile: %.2f)\n",
			ctx.EPSSScore, ctx.EPSSPercentile)
	}
	if ctx.InKEV {
		prompt += "WARNING: This CVE is in the CISA Known Exploited Vulnerabilities catalog\n"
	}
	if ctx.EnvType != "" {
		prompt += fmt.Sprintf("Environment: %s (severity multiplier: %.1fx)\n",
			ctx.EnvType, envSeverityMultiplier(ctx.EnvType))
	}
	if ctx.IsToxicCombination {
		prompt += "ALERT: This finding is part of a toxic combination pattern\n"
	}

	prompt += `
## Instructions
Based on the context above, provide a risk assessment. Consider:
1. Does the asset tier and environment justify the original severity?
2. Do compensating controls reduce the actual risk?
3. Is the network exposure a significant factor?
4. For vulnerabilities: Is the package actually in use? Is exploit available?
5. Historical false positive patterns
6. Threat intelligence signals (KEV, EPSS, attack paths) when available

Respond with JSON only:
{
  "adjusted_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
  "risk_score": 1-100,
  "confidence": 0.0-1.0,
  "rationale": "Brief explanation",
  "mitigating_factors": ["factor1", "factor2"],
  "aggravating_factors": ["factor1", "factor2"],
  "recommended_action": "remediate|accept_risk|investigate|suppress"
}`

	return prompt
}

// ContextEnricher populates finding context from external sources.
type ContextEnricher interface {
	EnrichContext(ctx context.Context, finding *Finding) error
}

// FPHistoryStore tracks false positive patterns.
type FPHistoryStore interface {
	GetFPStats(ctx context.Context, findingType, resourceType string) (count int, rate float64, err error)
	RecordFP(ctx context.Context, findingType, resourceType string) error
}

// LLMProvider defines the interface for LLM completions.
type LLMProvider interface {
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error)
	CountTokens(ctx context.Context, text string) (int, error)
	ModelName() string
	MaxContextLength() int
	IsAvailable(ctx context.Context) bool
}

// CompletionRequest represents a request to the LLM.
type CompletionRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
	System      string    `json:"system,omitempty"`
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Clone creates a deep copy of CompletionRequest with a new Messages slice.
// This prevents shared mutable state when passing requests to LLM providers.
func (r CompletionRequest) Clone() CompletionRequest {
	clone := CompletionRequest{
		Model:       r.Model,
		Temperature: r.Temperature,
		MaxTokens:   r.MaxTokens,
		System:      r.System,
	}
	if r.Messages != nil {
		clone.Messages = make([]Message, len(r.Messages))
		copy(clone.Messages, r.Messages)
	}
	return clone
}

// CompletionResponse represents an LLM response.
type CompletionResponse struct {
	Content string `json:"content"`
	Usage   Usage  `json:"usage"`
}

// Usage tracks token consumption.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// StreamChunk represents a streaming response chunk.
type StreamChunk struct {
	Content string `json:"content"`
	Done    bool   `json:"done"`
	Error   error  `json:"error,omitempty"`
}
