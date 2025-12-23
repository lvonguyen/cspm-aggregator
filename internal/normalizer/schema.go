package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
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

// Finding represents a normalized cross-cloud security finding
type Finding struct {
	// Core identification
	FindingID      string `json:"finding_id"`
	FindingIDShort string `json:"finding_id_short"` // Dedupe key (hash)
	CSP            string `json:"csp"`              // aws, azure, gcp
	AccountID      string `json:"account_id"`       // AWS account, Azure subscription, GCP project
	ResourceID     string `json:"resource_id"`

	// Finding details
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Status      string `json:"status"`   // ACTIVE, RESOLVED, SUPPRESSED

	// Control mapping
	ControlID string `json:"control_id"`
	Standard  string `json:"standard"` // CIS, FSBP, MCSB

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
	Period           string         `json:"period"`            // Monthly/Weekly
	GeneratedAt      time.Time      `json:"generated_at"`
	TotalFindings    int            `json:"total_findings"`
	NewFindings      int            `json:"new_findings"`
	ClosedFindings   int            `json:"closed_findings"`
	ReopenedFindings int            `json:"reopened_findings"`
	NetChange        int            `json:"net_change"`   // New - Closed
	ClosureRate      float64        `json:"closure_rate"` // Closed / Previous Total
	MTTR             float64        `json:"mttr_days"`    // Mean Time To Remediate

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

// NormalizeAWSFinding converts an AWS Security Hub finding
func (n *Normalizer) NormalizeAWSFinding(f interface{}) Finding {
	// TODO: Implement AWS-specific normalization
	return Finding{CSP: "aws"}
}

// NormalizeAzureFinding converts an Azure Defender finding
func (n *Normalizer) NormalizeAzureFinding(f interface{}) Finding {
	// TODO: Implement Azure-specific normalization
	return Finding{CSP: "azure"}
}

// NormalizeGCPFinding converts a GCP SCC finding
func (n *Normalizer) NormalizeGCPFinding(f interface{}) Finding {
	// TODO: Implement GCP-specific normalization
	return Finding{CSP: "gcp"}
}
