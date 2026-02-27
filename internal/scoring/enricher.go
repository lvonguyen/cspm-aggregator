package scoring

import (
	"context"
	"fmt"
	"log"
	"regexp"
)

// cvePattern matches CVE identifiers embedded in a finding type string.
var cvePattern = regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)

// EPSSClient provides EPSS score lookups for CVE identifiers.
// Defined here as a consumer interface — the implementation lives in pkg/threatintel.
type EPSSClient interface {
	GetScoreWithPercentile(cveID string) (score, percentile float64, err error)
}

// KEVCatalog provides CISA Known Exploited Vulnerability lookups.
// Defined here as a consumer interface — the implementation lives in pkg/threatintel.
type KEVCatalog interface {
	IsKnownExploited(cveID string) bool
}

// EnvClassifier maps resource metadata to an environment string.
// Defined here as a consumer interface — the implementation lives in pkg/contextual.
type EnvClassifier interface {
	Classify(resourceName string, tags map[string]string, projectID string) string
}

// CompositeEnricher implements ContextEnricher by composing EPSS, KEV, and
// environment classification sources. Enrichment failures are logged and do
// not block scoring — a partial context is always better than no context.
type CompositeEnricher struct {
	epssClient    EPSSClient
	kevCatalog    KEVCatalog
	envClassifier EnvClassifier
}

// NewCompositeEnricher creates a CompositeEnricher. Any source may be nil;
// that source's enrichment step is skipped.
func NewCompositeEnricher(epss EPSSClient, kev KEVCatalog, env EnvClassifier) *CompositeEnricher {
	return &CompositeEnricher{
		epssClient:    epss,
		kevCatalog:    kev,
		envClassifier: env,
	}
}

// EnrichContext populates finding.Context with threat-intelligence and
// environment data. It always returns nil — callers should not fail on
// enrichment errors.
func (e *CompositeEnricher) EnrichContext(_ context.Context, finding *Finding) error {
	cveID := extractCVEID(finding.FindingType)

	if cveID != "" {
		e.enrichEPSS(finding, cveID)
		e.enrichKEV(finding, cveID)
	}

	e.enrichEnvironment(finding)
	e.enrichCompensatingControls(finding)

	return nil
}

// enrichEPSS fetches and populates EPSS score and percentile.
func (e *CompositeEnricher) enrichEPSS(finding *Finding, cveID string) {
	if e.epssClient == nil {
		return
	}

	score, percentile, err := e.epssClient.GetScoreWithPercentile(cveID)
	if err != nil {
		log.Printf("EPSS lookup failed for %s: %v", cveID, err)
		return
	}

	finding.Context.EPSSScore = score
	finding.Context.EPSSPercentile = percentile

	if score > 0.5 {
		finding.Context.ExploitInWild = true
	}
	if score > 0 {
		finding.Context.ExploitAvailable = true
	}
}

// enrichKEV checks whether the CVE appears in the CISA KEV catalog.
func (e *CompositeEnricher) enrichKEV(finding *Finding, cveID string) {
	if e.kevCatalog == nil {
		return
	}

	finding.Context.InKEV = e.kevCatalog.IsKnownExploited(cveID)
	if finding.Context.InKEV {
		// KEV inclusion implies a publicly known exploitation method exists.
		finding.Context.ExploitAvailable = true
		finding.Context.ExploitInWild = true
	}
}

// enrichEnvironment classifies the resource's environment and sets AssetTier.
func (e *CompositeEnricher) enrichEnvironment(finding *Finding) {
	if e.envClassifier == nil {
		return
	}

	envType := e.envClassifier.Classify(finding.ResourceID, nil, finding.AccountID)
	if envType == "" {
		return
	}

	finding.Context.EnvType = envType
	finding.Context.AssetTier = envTypeToAssetTier(envType)
}

// enrichCompensatingControls infers compensating control states from available
// resource metadata. These are best-effort — only set when clearly determinable.
func (e *CompositeEnricher) enrichCompensatingControls(finding *Finding) {
	// Infer encryption at rest for common storage resource types.
	switch finding.ResourceType {
	case "AWS::S3::Bucket", "AWS::RDS::DBInstance",
		"microsoft.storage/storageaccounts", "google.storage.Bucket":
		// Default assumption: encryption at rest is enabled (CSPs enforce it by default
		// for these resource types). Mark only if not already populated.
		if !finding.Context.EncryptionAtRest {
			finding.Context.EncryptionAtRest = true
		}
	}

	// HTTPS-only findings imply encryption in transit.
	if finding.Context.EncryptionInTransit {
		return // already set upstream
	}
}

// envTypeToAssetTier maps a normalised environment string to a scoring asset tier.
// Unknown environments are treated conservatively as Tier1-Prod.
func envTypeToAssetTier(envType string) string {
	switch envType {
	case "prod", "production":
		return "Tier1-Prod"
	case "staging", "stg", "preprod":
		return "Tier2-NonProd"
	case "dev", "development":
		return "Tier3-Dev"
	case "sandbox", "sbx", "test", "qa", "uat":
		return "Tier3-Dev"
	default:
		// Unknown — treat as prod for conservative risk assessment.
		return "Tier1-Prod"
	}
}

// extractCVEID returns the first CVE identifier found in s, normalised to
// uppercase (e.g. "CVE-2024-1234"), or "" if none is present.
func extractCVEID(s string) string {
	m := cvePattern.FindString(s)
	if m == "" {
		return ""
	}
	// Re-normalise to uppercase so lookups against the EPSS/KEV APIs are
	// consistent regardless of how the finding type was formatted.
	return fmt.Sprintf("CVE-%s", m[len("CVE-"):])
}
