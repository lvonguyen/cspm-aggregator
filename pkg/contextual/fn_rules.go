package contextual

import (
	"net"
	"regexp"
	"strings"

	"github.com/lvonguyen/cspm-aggregator/internal/scoring"
)

// cidrPattern matches IPv4 CIDR notation within a string (e.g., "10.0.0.0/8").
var cidrPattern = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})`)

// mp09PrivateRanges are the RFC1918 address blocks used for containment checks.
var mp09PrivateRanges = func() []*net.IPNet {
	cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}()

// mp10PrivilegeKeywords are identifiers that indicate elevated/privileged access.
var mp10PrivilegeKeywords = []string{
	"admin", "root", "administrator", "poweruser", "privileged", "superuser",
}

// mp10TriggerTypes are the FindingType substrings that qualify for MP-10.
var mp10TriggerTypes = []string{
	"STALE_ACCESS_KEY",
	"INACTIVE_USER",
	"NO_MFA",
}

// FNRuleResult extends SeverityAdjustment with an optional risk score suggestion.
type FNRuleResult struct {
	SeverityAdjustment
	// SuggestedRiskScore is the recommended risk score (1-100) when the rule
	// escalates a finding. Zero means "no override".
	SuggestedRiskScore int
}

// fnRule is a function that evaluates one deterministic FN escalation rule.
// It returns (result, true) when the rule matches, or (nil, false) otherwise.
type fnRule func(f scoring.Finding) (*FNRuleResult, bool)

// FNRuleEngine holds an ordered slice of deterministic FN escalation rules.
// Rules are evaluated in order; the first match is returned.
type FNRuleEngine struct {
	rules []fnRule
}

// NewFNRuleEngine constructs an engine with MP-09 and MP-10 in priority order.
func NewFNRuleEngine() *FNRuleEngine {
	return &FNRuleEngine{
		rules: []fnRule{
			ruleMP09PrivateCIDRWidthEscalator,
			ruleMP10DormantPrivilegedCredential,
		},
	}
}

// Evaluate runs each rule in priority order and returns the first match.
// Returns (nil, false) when no rule matches.
func (e *FNRuleEngine) Evaluate(f scoring.Finding) (*FNRuleResult, bool) {
	for _, rule := range e.rules {
		if result, matched := rule(f); matched {
			return result, true
		}
	}
	return nil, false
}

// upgradeSeverity raises the severity by n levels, clamped at CRITICAL.
// This is the inverse of downgradeSeverity.
func upgradeSeverity(sev string, levels int) string {
	idx := severityIndex(sev)
	if idx < 0 {
		return sev
	}
	newIdx := idx - levels
	if newIdx < 0 {
		newIdx = 0
	}
	return severityLevels[newIdx]
}

// ---------------------------------------------------------------------------
// MP-09: Private CIDR Width Escalator
//
// Trigger: FindingType contains SECURITY_GROUP
//          AND source CIDR is RFC1918
//          AND CIDR prefix length <= 12
//          AND BusinessCriticality in {critical, high}
// Effect:  Upgrade 1 level, confidence 0.80
// EC codes: EC-48
// ---------------------------------------------------------------------------

func ruleMP09PrivateCIDRWidthEscalator(f scoring.Finding) (*FNRuleResult, bool) {
	ft := strings.ToUpper(f.FindingType)
	if !strings.Contains(ft, "SECURITY_GROUP") {
		return nil, false
	}

	bc := strings.ToLower(f.Context.BusinessCriticality)
	if bc != "critical" && bc != "high" {
		return nil, false
	}

	cidr := extractCIDR(f.Description + " " + f.Title)
	if cidr == "" {
		return nil, false
	}

	if !isBroadPrivateCIDR(cidr) {
		return nil, false
	}

	adjusted := upgradeSeverity(f.Severity, 1)
	return &FNRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: adjusted,
			Reason:           "overly broad private CIDR on critical asset; MP-09 (EC-48)",
			Confidence:       0.80,
			Pattern:          "MP-09",
			Applied:          adjusted != f.Severity,
		},
	}, true
}

// extractCIDR returns the first IPv4 CIDR found in s, or empty string.
func extractCIDR(s string) string {
	return cidrPattern.FindString(s)
}

// isBroadPrivateCIDR returns true when the CIDR is RFC1918 and its prefix
// length is <= 12 (i.e., the network covers a very large address space).
func isBroadPrivateCIDR(cidr string) bool {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Only consider broad networks (prefix <= 12).
	ones, _ := network.Mask.Size()
	if ones > 12 {
		return false
	}

	// Verify the IP falls within an RFC1918 range.
	for _, private := range mp09PrivateRanges {
		if private.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// MP-10: Dormant Privileged Credential Escalator
//
// Trigger: FindingType contains STALE_ACCESS_KEY or INACTIVE_USER or NO_MFA
//          AND Severity is LOW or INFORMATIONAL
//          AND (Title or Description) contains a privilege keyword
// Effect:  Upgrade to HIGH, confidence 0.85
// EC codes: EC-48
// ---------------------------------------------------------------------------

func ruleMP10DormantPrivilegedCredential(f scoring.Finding) (*FNRuleResult, bool) {
	ft := strings.ToUpper(f.FindingType)
	hasTriggerType := false
	for _, t := range mp10TriggerTypes {
		if strings.Contains(ft, t) {
			hasTriggerType = true
			break
		}
	}
	if !hasTriggerType {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	if sev != "LOW" && sev != "INFORMATIONAL" {
		return nil, false
	}

	if !containsPrivilegeKeyword(f.Title) && !containsPrivilegeKeyword(f.Description) {
		return nil, false
	}

	return &FNRuleResult{
		SeverityAdjustment: SeverityAdjustment{
			OriginalSeverity: f.Severity,
			AdjustedSeverity: "HIGH",
			Reason:           "dormant privileged credential is high-value attack target; MP-10 (EC-48)",
			Confidence:       0.85,
			Pattern:          "MP-10",
			Applied:          f.Severity != "HIGH",
		},
	}, true
}

// containsPrivilegeKeyword returns true when s contains any known privilege keyword.
func containsPrivilegeKeyword(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range mp10PrivilegeKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
