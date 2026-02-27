// Package contextual provides environment classification and meta-pattern
// evaluation for contextual risk adjustment in CSPM findings.
package contextual

import (
	"regexp"
	"strings"
)

// EnvironmentTier classifies the operational tier of a cloud resource.
type EnvironmentTier int

const (
	Unknown EnvironmentTier = iota // Unknown — treated conservatively as prod
	Prod                           // Production workloads
	Staging                        // Staging / pre-production
	Dev                            // Development
	Sandbox                        // Sandbox / test / QA
)

// String returns the human-readable name of the tier.
func (e EnvironmentTier) String() string {
	switch e {
	case Prod:
		return "prod"
	case Staging:
		return "staging"
	case Dev:
		return "dev"
	case Sandbox:
		return "sandbox"
	default:
		return "unknown"
	}
}

// SeverityMultiplier returns the severity adjustment multiplier for this tier.
// Prod and Unknown keep severity unchanged (1.0x). Lower environments reduce it.
func (e EnvironmentTier) SeverityMultiplier() float64 {
	switch e {
	case Prod:
		return 1.0
	case Staging:
		return 0.8
	case Dev:
		return 0.5
	case Sandbox:
		return 0.3
	default: // Unknown — treat conservatively as prod
		return 1.0
	}
}

// compiled regexes for environment detection (case-insensitive matching applied at call site)
var (
	reProd    = regexp.MustCompile(`(?i)\b(prod|prd|production)\b`)
	reStaging = regexp.MustCompile(`(?i)\b(staging|stg|preprod|pre-prod|pre_prod)\b`)
	reDev     = regexp.MustCompile(`(?i)\b(dev|development)\b`)
	reSandbox = regexp.MustCompile(`(?i)\b(sandbox|sbx|test|qa|uat)\b`)
)

// tagKeys are the tag key names checked when classifying by resource tags, in priority order.
var tagKeys = []string{"environment", "env", "stage", "tier", "deployment_environment"}

// ClassifyEnvironment determines the EnvironmentTier for a resource using a
// three-level detection strategy:
//
//  1. Explicit resource tags (highest priority)
//  2. Resource name patterns
//  3. Project / account name patterns
func ClassifyEnvironment(resourceName string, tags map[string]string, projectID string) EnvironmentTier {
	// Priority 1: Explicit tags
	if tier := classifyByTags(tags); tier != Unknown {
		return tier
	}

	// Priority 2: Resource name
	if tier := classifyByPattern(resourceName); tier != Unknown {
		return tier
	}

	// Priority 3: Project / account identifier
	if tier := classifyByPattern(projectID); tier != Unknown {
		return tier
	}

	return Unknown
}

// classifyByTags inspects known environment tag keys for a tier hint.
func classifyByTags(tags map[string]string) EnvironmentTier {
	if len(tags) == 0 {
		return Unknown
	}

	for _, key := range tagKeys {
		// Check exact key (case-insensitive lookup by normalising both sides)
		for tagKey, tagVal := range tags {
			if strings.EqualFold(tagKey, key) {
				if tier := matchTierString(tagVal); tier != Unknown {
					return tier
				}
			}
		}
	}
	return Unknown
}

// classifyByPattern applies regex patterns against a single string.
// Staging is checked before Prod because staging patterns like "preprod" and
// "pre-prod" are substrings that would otherwise match the prod regex first.
func classifyByPattern(s string) EnvironmentTier {
	if s == "" {
		return Unknown
	}
	// Staging must be evaluated before Prod: "pre-prod" contains "prod" as a
	// substring, so matching staging first prevents a false Prod classification.
	switch {
	case reStaging.MatchString(s):
		return Staging
	case reProd.MatchString(s):
		return Prod
	case reDev.MatchString(s):
		return Dev
	case reSandbox.MatchString(s):
		return Sandbox
	}
	return Unknown
}

// matchTierString maps a tag value string to an EnvironmentTier.
func matchTierString(val string) EnvironmentTier {
	return classifyByPattern(val)
}
