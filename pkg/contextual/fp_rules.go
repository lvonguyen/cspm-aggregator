package contextual

import (
	"strings"

	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
)

// NVDStatusChecker abstracts NVD CVE status lookups.
// Implementations can call the live NVD API or return fixture data in tests.
type NVDStatusChecker interface {
	// GetCVEStatus returns the NVD status string for a CVE ID.
	// Common values: "ACTIVE", "ANALYZED", "REJECTED", "DISPUTED", "MODIFIED".
	GetCVEStatus(cveID string) (string, error)
}

// FPRuleResult extends SeverityAdjustment with an optional risk score override.
type FPRuleResult struct {
	SeverityAdjustment
	// SuggestedRiskScore is the recommended risk score (1-100) when the rule
	// suppresses or significantly downgrades a finding. Zero means "no override".
	SuggestedRiskScore int
}

// fpRule is a function that evaluates one deterministic FP elimination rule.
// It returns (result, true) when the rule matches, or (nil, false) otherwise.
type fpRule func(f scoring.Finding) (*FPRuleResult, bool)

// FPRuleEngine holds an ordered slice of deterministic FP rules.
// Rules are evaluated in order; the first match is returned.
type FPRuleEngine struct {
	rules []fpRule
}

// NewFPRuleEngine constructs an engine with MP-04 through MP-11 in priority order.
// Pass a non-nil NVDStatusChecker to enable MP-07; pass nil to skip it.
func NewFPRuleEngine(nvd NVDStatusChecker) *FPRuleEngine {
	e := &FPRuleEngine{}
	e.rules = []fpRule{
		ruleMP04EnvTierDampener,
		ruleMP05WAFCompensatedOpenSG,
		ruleMP06StaleRDSPublicAttr,
		buildRuleMP07CVEStatusValidator(nvd),
		ruleMP08KMSAsymmetricRotation,
		ruleMP11ICSProtocolPort,
	}
	return e
}

// Evaluate runs each rule in priority order and returns the first match.
// Returns (nil, false) when no rule matches.
func (e *FPRuleEngine) Evaluate(f scoring.Finding) (*FPRuleResult, bool) {
	for _, rule := range e.rules {
		if result, matched := rule(f); matched {
			return result, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// MP-04: Environment Tier Dampener
//
// Trigger: EnvType is NOT prod/production/prd (i.e., any non-production env)
//          AND Severity in {HIGH, CRITICAL}
//          AND NOT DataClassification in {PCI, PII, PHI}
// Effect:  Downgrade 2 levels, confidence 0.90
// EC codes: EC-09, EC-21
// ---------------------------------------------------------------------------

// mp04ProdEnvs are environment values that are explicitly production.
// Anything NOT in this set is treated as non-production for dampening purposes.
// This is safer than maintaining an ever-growing non-prod list because new
// env names (qa-east, uat-02, perf-test, etc.) are automatically covered.
var mp04ProdEnvs = map[string]bool{
	"prod":       true,
	"production": true,
	"prd":        true,
}

var mp04SensitiveClassifications = map[string]bool{
	"PCI": true,
	"PII": true,
	"PHI": true,
}

func ruleMP04EnvTierDampener(f scoring.Finding) (*FPRuleResult, bool) {
	env := strings.ToLower(f.Context.EnvType)
	if env == "" || mp04ProdEnvs[env] {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	if sev != "HIGH" && sev != "CRITICAL" {
		return nil, false
	}

	dc := strings.ToUpper(f.Context.DataClassification)
	if mp04SensitiveClassifications[dc] {
		return nil, false
	}

	adjusted := downgradeSeverity(f.Severity, 2)
	return &FPRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: adjusted,
			Reason:           "non-production environment; severity dampened per MP-04 (EC-09, EC-21)",
			Confidence:       0.90,
			Pattern:          "MP-04",
			Applied:          adjusted != f.Severity,
		},
	}, true
}

// ---------------------------------------------------------------------------
// MP-05: WAF-Compensated Open SG Suppressor
//
// Trigger: FindingType contains OPEN_SECURITY_GROUP or SECURITY_GROUP_INGRESS
//          AND WAFEnabled == true
//          AND ResourceType contains ALB or LoadBalancer or CloudFront
// Effect:  Downgrade 2 levels, confidence 0.85
// EC codes: EC-05, EC-17
// ---------------------------------------------------------------------------

func ruleMP05WAFCompensatedOpenSG(f scoring.Finding) (*FPRuleResult, bool) {
	ft := strings.ToUpper(f.FindingType)
	if !strings.Contains(ft, "OPEN_SECURITY_GROUP") && !strings.Contains(ft, "SECURITY_GROUP_INGRESS") {
		return nil, false
	}

	if !f.Context.WAFEnabled {
		return nil, false
	}

	rt := strings.ToUpper(f.ResourceType)
	if !strings.Contains(rt, "ALB") &&
		!strings.Contains(rt, "LOADBALANCER") &&
		!strings.Contains(rt, "CLOUDFRONT") {
		return nil, false
	}

	adjusted := downgradeSeverity(f.Severity, 2)
	return &FPRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: adjusted,
			Reason:           "WAF compensates for open security group on load balancer / CDN; MP-05 (EC-05, EC-17)",
			Confidence:       0.85,
			Pattern:          "MP-05",
			Applied:          adjusted != f.Severity,
		},
	}, true
}

// ---------------------------------------------------------------------------
// MP-06: Stale RDS Public Attribute Detector
//
// Trigger: FindingType contains RDS_PUBLIC or PUBLICLY_ACCESSIBLE
//          AND InternetFacing == false
//          AND (PrivateEndpoint == true OR VPCType == "isolated")
// Effect:  Downgrade to LOW, RiskScore=20, confidence 0.90
// EC codes: EC-37
// ---------------------------------------------------------------------------

func ruleMP06StaleRDSPublicAttr(f scoring.Finding) (*FPRuleResult, bool) {
	ft := strings.ToUpper(f.FindingType)
	if !strings.Contains(ft, "RDS_PUBLIC") && !strings.Contains(ft, "PUBLICLY_ACCESSIBLE") {
		return nil, false
	}

	if f.Context.InternetFacing {
		return nil, false
	}

	hasPrivateCompensation := f.Context.PrivateEndpoint ||
		strings.EqualFold(f.Context.VPCType, "isolated")
	if !hasPrivateCompensation {
		return nil, false
	}

	return &FPRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: "LOW",
			Reason:           "RDS publiclyAccessible attribute is stale; resource is not internet-facing and has private endpoint or isolated VPC; MP-06 (EC-37)",
			Confidence:       0.90,
			Pattern:          "MP-06",
			Applied:          true,
		},
		SuggestedRiskScore: 20,
	}, true
}

// ---------------------------------------------------------------------------
// MP-07: CVE Status Validator
//
// Trigger: FindingType starts with "CVE-" (or title/description contains it)
//          AND CVE status is REJECTED or DISPUTED
// Effect:  Suppress (downgrade to INFORMATIONAL), RiskScore=5, confidence 0.95
// EC codes: EC-46
//
// The rule is a no-op when the NVDStatusChecker is nil.
// ---------------------------------------------------------------------------

// cveIDFromFinding extracts a CVE ID from the FindingType field.
// Returns empty string if no CVE ID is found.
func cveIDFromFinding(f scoring.Finding) string {
	ft := strings.ToUpper(f.FindingType)
	if strings.HasPrefix(ft, "CVE-") {
		return f.FindingType
	}
	return ""
}

func buildRuleMP07CVEStatusValidator(nvd NVDStatusChecker) fpRule {
	return func(f scoring.Finding) (*FPRuleResult, bool) {
		if nvd == nil {
			return nil, false
		}

		cveID := cveIDFromFinding(f)
		if cveID == "" {
			return nil, false
		}

		status, err := nvd.GetCVEStatus(cveID)
		if err != nil {
			// Non-fatal — skip rule on lookup error
			return nil, false
		}

		st := strings.ToUpper(status)
		if st != "REJECTED" && st != "DISPUTED" {
			return nil, false
		}

		return &FPRuleResult{
			SeverityAdjustment: SeverityAdjustment{
				OriginalSeverity: f.Severity,
				AdjustedSeverity: "INFORMATIONAL",
				Reason:           "CVE status is " + status + "; finding suppressed per MP-07 (EC-46)",
				Confidence:       0.95,
				Pattern:          "MP-07",
				Applied:          true,
			},
			SuggestedRiskScore: 5,
		}, true
	}
}

// ---------------------------------------------------------------------------
// MP-08: KMS Asymmetric Key Rotation Suppressor
//
// Trigger: FindingType contains KEY_ROTATION_DISABLED or KMS_KEY_ROTATION
//          AND ResourceType contains KMS or kms_key
//          AND (Title or Description) contains "asymmetric", "RSA", "ECC", or "SM2"
// Effect:  Suppress (INFORMATIONAL), RiskScore=5, confidence 0.95
// EC codes: EC-25
// ---------------------------------------------------------------------------

var mp08AsymmetricKeywords = []string{"asymmetric", "rsa", "ecc", "sm2"}

func containsAsymmetricKeyword(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range mp08AsymmetricKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func ruleMP08KMSAsymmetricRotation(f scoring.Finding) (*FPRuleResult, bool) {
	ft := strings.ToUpper(f.FindingType)
	if !strings.Contains(ft, "KEY_ROTATION_DISABLED") && !strings.Contains(ft, "KMS_KEY_ROTATION") {
		return nil, false
	}

	rt := strings.ToUpper(f.ResourceType)
	if !strings.Contains(rt, "KMS") {
		return nil, false
	}

	if !containsAsymmetricKeyword(f.Title) && !containsAsymmetricKeyword(f.Description) {
		return nil, false
	}

	return &FPRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: "INFORMATIONAL",
			Reason:           "AWS does not support rotation for asymmetric KMS keys; finding suppressed per MP-08 (EC-25)",
			Confidence:       0.95,
			Pattern:          "MP-08",
			Applied:          true,
		},
		SuggestedRiskScore: 5,
	}, true
}

// ---------------------------------------------------------------------------
// MP-11: ICS Protocol Port Contextualizer
//
// Trigger: FindingType contains OPEN_SECURITY_GROUP
//          AND Context.IngressPorts intersects the ICS protocol port table
// Effect:  Downgrade 1 level, confidence 0.75
// Pattern: MP-11
// EC codes: EC-08
// ---------------------------------------------------------------------------

// mp11ICSPorts maps known ICS/OT protocol ports to their protocol names.
// TCP 102  = S7comm (Siemens S7 PLC)
// TCP 8883 = MQTT over TLS
// TCP 4840 = OPC-UA
// TCP 20000 = DNP3
// TCP 2404  = IEC 104
// TCP 44818 = EtherNet/IP
var mp11ICSPorts = map[int]bool{
	102:   true,
	8883:  true,
	4840:  true,
	20000: true,
	2404:  true,
	44818: true,
}

// hasICSPort returns true when any port in ports is in the mp11ICSPorts table.
func hasICSPort(ports []int) bool {
	for _, p := range ports {
		if mp11ICSPorts[p] {
			return true
		}
	}
	return false
}

func ruleMP11ICSProtocolPort(f scoring.Finding) (*FPRuleResult, bool) {
	ft := strings.ToUpper(f.FindingType)
	if !strings.Contains(ft, "OPEN_SECURITY_GROUP") {
		return nil, false
	}

	if !hasICSPort(f.Context.IngressPorts) {
		return nil, false
	}

	adjusted := downgradeSeverity(f.Severity, 1)
	return &FPRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: adjusted,
			Reason:           "ICS/IoT protocol port — verify application-layer auth; MP-11 (EC-08)",
			Confidence:       0.75,
			Pattern:          "MP-11",
			Applied:          adjusted != f.Severity,
		},
	}, true
}
