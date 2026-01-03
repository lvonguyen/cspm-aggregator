// Package scoring provides AI-powered finding prioritization combining
// contextual risk assessment with remediation complexity analysis.
package scoring

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Priority represents the remediation priority level (P1 = highest).
type Priority string

const (
	P1 Priority = "P1" // Critical risk + any complexity OR High risk + Tier1 → Immediate action
	P2 Priority = "P2" // High risk + Tier2 OR Critical risk already queued → Next maintenance window
	P3 Priority = "P3" // High risk + Tier3 OR Medium risk + Tier1 → Scheduled remediation
	P4 Priority = "P4" // Medium risk + Tier2/3 OR Low risk + Tier1 → Normal queue
	P5 Priority = "P5" // Low risk + Tier2/3 → Backlog
)

// PriorityConfig holds configuration for priority calculation.
type PriorityConfig struct {
	// AutoRemediateP1Tier1 automatically triggers remediation for P1 + Tier1
	AutoRemediateP1Tier1 bool

	// AutoRemediateP2Tier1 automatically triggers remediation for P2 + Tier1
	AutoRemediateP2Tier1 bool

	// ProdEnvironmentEscalation escalates all prod findings by one priority level
	ProdEnvironmentEscalation bool

	// PCI/PII data escalation
	SensitiveDataEscalation bool

	// SLA overrides - findings past SLA get escalated
	SLAEscalation bool
}

// DefaultPriorityConfig returns sensible defaults.
func DefaultPriorityConfig() PriorityConfig {
	return PriorityConfig{
		AutoRemediateP1Tier1:      true,
		AutoRemediateP2Tier1:      true,
		ProdEnvironmentEscalation: true,
		SensitiveDataEscalation:   true,
		SLAEscalation:             true,
	}
}

// PriorityMatrix combines risk and complexity assessments into prioritized findings.
type PriorityMatrix struct {
	riskScorer   *RiskScorer
	complexity   *ComplexityNormalizer
	config       PriorityConfig
}

// NewPriorityMatrix creates a new priority matrix service.
func NewPriorityMatrix(
	riskScorer *RiskScorer,
	complexity *ComplexityNormalizer,
	config PriorityConfig,
) *PriorityMatrix {
	return &PriorityMatrix{
		riskScorer: riskScorer,
		complexity: complexity,
		config:     config,
	}
}

// PrioritizedFinding contains the full assessment for a finding.
type PrioritizedFinding struct {
	// Original finding
	Finding *Finding `json:"finding"`

	// Risk assessment
	RiskAssessment *RiskAssessment `json:"risk_assessment"`

	// Complexity assessment
	ComplexityAssessment *ComplexityAssessment `json:"complexity_assessment"`

	// Final priority
	Priority           Priority `json:"priority"`
	PriorityScore      int      `json:"priority_score"`       // 1-100 for sorting within priority
	PriorityRationale  string   `json:"priority_rationale"`

	// Action recommendations
	AutoRemediationReady   bool     `json:"auto_remediation_ready"`
	RecommendedAction      string   `json:"recommended_action"`
	RecommendedTimeline    string   `json:"recommended_timeline"`
	EscalationReasons      []string `json:"escalation_reasons,omitempty"`

	// SLA tracking
	SLADeadline    time.Time `json:"sla_deadline"`
	SLAStatus      string    `json:"sla_status"`      // on_track, at_risk, overdue
	DaysUntilSLA   int       `json:"days_until_sla"`

	// Workflow routing
	AssignedQueue     string `json:"assigned_queue"`      // auto_remediation, security_review, app_team, change_board
	RequiresApproval  bool   `json:"requires_approval"`
	ApprovalLevel     string `json:"approval_level,omitempty"` // security_analyst, security_admin, ciso

	// Metadata
	AssessedAt time.Time `json:"assessed_at"`
}

// PrioritizeFinding performs full assessment and prioritization of a single finding.
func (pm *PriorityMatrix) PrioritizeFinding(ctx context.Context, finding *Finding) (*PrioritizedFinding, error) {
	result := &PrioritizedFinding{
		Finding:    finding,
		AssessedAt: time.Now(),
	}

	// Step 1: Risk assessment
	riskAssessment, err := pm.riskScorer.ScoreFinding(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("risk scoring failed: %w", err)
	}
	result.RiskAssessment = riskAssessment

	// Step 2: Complexity assessment
	complexityAssessment, err := pm.complexity.AssessFinding(ctx, &ComplexityFinding{
		ID:                 finding.ID,
		Source:             finding.Source,
		Severity:           riskAssessment.AdjustedSeverity, // Use adjusted severity
		FindingType:        finding.FindingType,
		ResourceID:         finding.ResourceID,
		ResourceType:       finding.ResourceType,
		Region:             finding.Region,
		AccountID:          finding.AccountID,
		Title:              finding.Title,
		Description:        finding.Description,
		EnvType:            finding.Context.EnvType,
		AssetTier:          finding.Context.AssetTier,
		DataClassification: finding.Context.DataClassification,
	})
	if err != nil {
		return nil, fmt.Errorf("complexity assessment failed: %w", err)
	}
	result.ComplexityAssessment = complexityAssessment

	// Step 3: Calculate priority from risk + complexity
	result.Priority, result.PriorityRationale = pm.calculatePriority(
		riskAssessment.AdjustedSeverity,
		complexityAssessment.Tier,
		finding,
	)

	// Step 4: Apply escalations
	result.EscalationReasons = pm.applyEscalations(finding, riskAssessment, result)

	// Step 5: Calculate priority score for sorting within same priority
	result.PriorityScore = pm.calculatePriorityScore(result)

	// Step 6: Determine auto-remediation eligibility
	result.AutoRemediationReady = pm.isAutoRemediationReady(result)

	// Step 7: Set action recommendations
	pm.setActionRecommendations(result)

	// Step 8: Calculate SLA
	pm.calculateSLA(result, finding)

	// Step 9: Route to appropriate queue
	pm.routeToQueue(result)

	return result, nil
}

// PrioritizeFindings batch processes multiple findings.
func (pm *PriorityMatrix) PrioritizeFindings(ctx context.Context, findings []*Finding) ([]*PrioritizedFinding, error) {
	results := make([]*PrioritizedFinding, 0, len(findings))

	for _, finding := range findings {
		result, err := pm.PrioritizeFinding(ctx, finding)
		if err != nil {
			// Log error but continue processing
			continue
		}
		results = append(results, result)
	}

	// Sort by priority and score
	sort.Slice(results, func(i, j int) bool {
		if results[i].Priority != results[j].Priority {
			return priorityToInt(results[i].Priority) < priorityToInt(results[j].Priority)
		}
		return results[i].PriorityScore > results[j].PriorityScore
	})

	return results, nil
}

// calculatePriority determines priority from risk severity and complexity tier.
func (pm *PriorityMatrix) calculatePriority(severity string, tier ComplexityTier, _ *Finding) (Priority, string) {
	/*
	Priority Matrix:
	
	                 | Tier 1 (Low)  | Tier 2 (Med)  | Tier 3 (High) |
	-----------------|---------------|---------------|---------------|
	CRITICAL         | P1            | P1            | P2            |
	HIGH             | P1            | P2            | P3            |
	MEDIUM           | P3            | P4            | P4            |
	LOW              | P4            | P5            | P5            |
	INFORMATIONAL    | P5            | P5            | P5            |
	*/

	var priority Priority
	var rationale string

	switch severity {
	case "CRITICAL":
		if tier <= Tier2 {
			priority = P1
			rationale = fmt.Sprintf("CRITICAL severity with %s complexity requires immediate action", tier)
		} else {
			priority = P2
			rationale = fmt.Sprintf("CRITICAL severity but %s complexity requires coordination", tier)
		}

	case "HIGH":
		switch tier {
		case Tier1:
			priority = P1
			rationale = "HIGH severity with low complexity - quick win for immediate remediation"
		case Tier2:
			priority = P2
			rationale = "HIGH severity with medium complexity - schedule for next maintenance window"
		default:
			priority = P3
			rationale = "HIGH severity but high complexity requires change management process"
		}

	case "MEDIUM":
		if tier == Tier1 {
			priority = P3
			rationale = "MEDIUM severity with low complexity - good candidate for batch remediation"
		} else {
			priority = P4
			rationale = "MEDIUM severity - address in normal remediation cycle"
		}

	case "LOW":
		if tier == Tier1 {
			priority = P4
			rationale = "LOW severity with low complexity - automate when convenient"
		} else {
			priority = P5
			rationale = "LOW severity with coordination needs - backlog item"
		}

	default: // INFORMATIONAL
		priority = P5
		rationale = "Informational finding - address as time permits"
	}

	return priority, rationale
}

// applyEscalations checks for conditions that escalate priority.
func (pm *PriorityMatrix) applyEscalations(
	finding *Finding,
	risk *RiskAssessment,
	result *PrioritizedFinding,
) []string {
	var reasons []string

	// Production environment escalation
	if pm.config.ProdEnvironmentEscalation && finding.Context.EnvType == "prod" {
		if result.Priority > P1 {
			result.Priority = escalatePriority(result.Priority)
			reasons = append(reasons, "Production environment")
		}
	}

	// Sensitive data escalation
	if pm.config.SensitiveDataEscalation {
		if finding.Context.DataClassification == "PCI" || finding.Context.DataClassification == "PII" {
			if result.Priority > P2 {
				result.Priority = escalatePriority(result.Priority)
				reasons = append(reasons, fmt.Sprintf("%s data classification", finding.Context.DataClassification))
			}
		}
	}

	// Internet-facing escalation
	if finding.Context.InternetFacing && result.Priority > P2 {
		result.Priority = escalatePriority(result.Priority)
		reasons = append(reasons, "Internet-facing resource")
	}

	// SLA escalation
	if pm.config.SLAEscalation && finding.DaysOpen > 0 {
		slaDeadline := pm.getSLADays(risk.AdjustedSeverity)
		if finding.DaysOpen > slaDeadline {
			if result.Priority > P1 {
				result.Priority = escalatePriority(result.Priority)
				reasons = append(reasons, fmt.Sprintf("SLA overdue by %d days", finding.DaysOpen-slaDeadline))
			}
		}
	}

	return reasons
}

// calculatePriorityScore generates a fine-grained score for sorting within priority.
func (pm *PriorityMatrix) calculatePriorityScore(result *PrioritizedFinding) int {
	// Base score from risk score (1-100)
	score := result.RiskAssessment.RiskScore

	// Adjust for complexity (lower complexity = higher score within priority)
	switch result.ComplexityAssessment.Tier {
	case Tier1:
		score += 20
	case Tier2:
		score += 10
	}

	// Adjust for auto-remediation readiness
	if result.ComplexityAssessment.AutomationCandidate {
		score += 15
	}

	// Adjust for SLA pressure
	if result.Finding.DaysOpen > 0 {
		slaDeadline := pm.getSLADays(result.RiskAssessment.AdjustedSeverity)
		daysRemaining := slaDeadline - result.Finding.DaysOpen
		if daysRemaining < 0 {
			score += 25 // Overdue
		} else if daysRemaining < 3 {
			score += 15 // At risk
		} else if daysRemaining < 7 {
			score += 5 // Approaching
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// isAutoRemediationReady determines if finding can be auto-remediated.
func (pm *PriorityMatrix) isAutoRemediationReady(result *PrioritizedFinding) bool {
	// Must be Tier1 complexity
	if result.ComplexityAssessment.Tier != Tier1 {
		return false
	}

	// Must be automation candidate
	if !result.ComplexityAssessment.AutomationCandidate {
		return false
	}

	// Must have no automation blockers
	if len(result.ComplexityAssessment.AutomationBlockers) > 0 {
		return false
	}

	// Check priority thresholds
	switch result.Priority {
	case P1:
		return pm.config.AutoRemediateP1Tier1
	case P2:
		return pm.config.AutoRemediateP2Tier1
	default:
		// Lower priorities can be batched
		return true
	}
}

// setActionRecommendations sets the recommended actions based on assessment.
func (pm *PriorityMatrix) setActionRecommendations(result *PrioritizedFinding) {
	if result.AutoRemediationReady {
		result.RecommendedAction = "auto_remediate"
		switch result.Priority {
		case P1:
			result.RecommendedTimeline = "immediate"
		case P2:
			result.RecommendedTimeline = "next_maintenance_window"
		default:
			result.RecommendedTimeline = "batch_queue"
		}
		return
	}

	// Manual remediation recommendations
	switch result.Priority {
	case P1:
		result.RecommendedAction = "emergency_remediation"
		result.RecommendedTimeline = "24h"
		result.RequiresApproval = result.ComplexityAssessment.Tier == Tier3
		if result.RequiresApproval {
			result.ApprovalLevel = "security_admin"
		}

	case P2:
		result.RecommendedAction = "scheduled_remediation"
		result.RecommendedTimeline = "7d"
		result.RequiresApproval = result.ComplexityAssessment.RequiresChangeWindow
		if result.RequiresApproval {
			result.ApprovalLevel = "security_analyst"
		}

	case P3:
		result.RecommendedAction = "planned_remediation"
		result.RecommendedTimeline = "14d"

	case P4:
		result.RecommendedAction = "normal_queue"
		result.RecommendedTimeline = "30d"

	case P5:
		result.RecommendedAction = "backlog"
		result.RecommendedTimeline = "90d"
	}
}

// calculateSLA sets SLA tracking fields.
func (pm *PriorityMatrix) calculateSLA(result *PrioritizedFinding, finding *Finding) {
	slaDays := pm.getSLADays(result.RiskAssessment.AdjustedSeverity)
	
	// SLA starts from first detection
	if !finding.FirstSeen.IsZero() {
		result.SLADeadline = finding.FirstSeen.AddDate(0, 0, slaDays)
	} else {
		result.SLADeadline = time.Now().AddDate(0, 0, slaDays)
	}

	daysRemaining := int(time.Until(result.SLADeadline).Hours() / 24)
	result.DaysUntilSLA = daysRemaining

	if daysRemaining < 0 {
		result.SLAStatus = "overdue"
	} else if daysRemaining < 3 {
		result.SLAStatus = "at_risk"
	} else {
		result.SLAStatus = "on_track"
	}
}

// routeToQueue assigns finding to appropriate workflow queue.
func (pm *PriorityMatrix) routeToQueue(result *PrioritizedFinding) {
	if result.AutoRemediationReady {
		result.AssignedQueue = "auto_remediation"
		return
	}

	switch {
	case result.Priority == P1 && result.ComplexityAssessment.Tier == Tier3:
		result.AssignedQueue = "change_board"
	case result.ComplexityAssessment.RequiresAppTeam:
		result.AssignedQueue = "app_team"
	case result.Priority <= P2:
		result.AssignedQueue = "security_review"
	default:
		result.AssignedQueue = "remediation_queue"
	}
}

// getSLADays returns SLA deadline in days based on severity.
func (pm *PriorityMatrix) getSLADays(severity string) int {
	switch severity {
	case "CRITICAL":
		return 7
	case "HIGH":
		return 14
	case "MEDIUM":
		return 30
	case "LOW":
		return 90
	default:
		return 90
	}
}

// Helper functions

func priorityToInt(p Priority) int {
	switch p {
	case P1:
		return 1
	case P2:
		return 2
	case P3:
		return 3
	case P4:
		return 4
	case P5:
		return 5
	default:
		return 5
	}
}

func escalatePriority(p Priority) Priority {
	switch p {
	case P2:
		return P1
	case P3:
		return P2
	case P4:
		return P3
	case P5:
		return P4
	default:
		return p
	}
}

// QueueSummary provides aggregate statistics by queue.
type QueueSummary struct {
	Queue              string `json:"queue"`
	TotalFindings      int    `json:"total_findings"`
	AutoRemediationReady int  `json:"auto_remediation_ready"`
	ByPriority         map[Priority]int `json:"by_priority"`
	BySeverity         map[string]int   `json:"by_severity"`
	OverdueSLA         int    `json:"overdue_sla"`
}

// GenerateQueueSummaries creates summary statistics for each queue.
func GenerateQueueSummaries(findings []*PrioritizedFinding) map[string]*QueueSummary {
	summaries := make(map[string]*QueueSummary)

	for _, f := range findings {
		queue := f.AssignedQueue
		if _, ok := summaries[queue]; !ok {
			summaries[queue] = &QueueSummary{
				Queue:      queue,
				ByPriority: make(map[Priority]int),
				BySeverity: make(map[string]int),
			}
		}

		s := summaries[queue]
		s.TotalFindings++
		s.ByPriority[f.Priority]++
		s.BySeverity[f.RiskAssessment.AdjustedSeverity]++
		
		if f.AutoRemediationReady {
			s.AutoRemediationReady++
		}
		if f.SLAStatus == "overdue" {
			s.OverdueSLA++
		}
	}

	return summaries
}

// ActionableSummary provides a high-level summary for dashboards.
type ActionableSummary struct {
	GeneratedAt           time.Time `json:"generated_at"`
	TotalFindings         int       `json:"total_findings"`
	
	// By priority
	P1Count              int `json:"p1_count"`
	P2Count              int `json:"p2_count"`
	P3Count              int `json:"p3_count"`
	P4Count              int `json:"p4_count"`
	P5Count              int `json:"p5_count"`
	
	// Automation
	AutoRemediationReady int `json:"auto_remediation_ready"`
	AutoRemediationPct   float64 `json:"auto_remediation_pct"`
	
	// SLA
	OnTrackSLA           int `json:"on_track_sla"`
	AtRiskSLA            int `json:"at_risk_sla"`
	OverdueSLA           int `json:"overdue_sla"`
	
	// Risk reduction opportunity
	QuickWins            int `json:"quick_wins"` // P1-P2 + Tier1
	QuickWinRiskReduction float64 `json:"quick_win_risk_reduction"` // % of total risk
}

// GenerateActionableSummary creates dashboard-ready summary.
func GenerateActionableSummary(findings []*PrioritizedFinding) *ActionableSummary {
	summary := &ActionableSummary{
		GeneratedAt: time.Now(),
	}

	var totalRiskScore, quickWinRiskScore float64

	for _, f := range findings {
		summary.TotalFindings++
		totalRiskScore += float64(f.RiskAssessment.RiskScore)

		// Priority counts
		switch f.Priority {
		case P1:
			summary.P1Count++
		case P2:
			summary.P2Count++
		case P3:
			summary.P3Count++
		case P4:
			summary.P4Count++
		case P5:
			summary.P5Count++
		}

		// Automation
		if f.AutoRemediationReady {
			summary.AutoRemediationReady++
		}

		// SLA
		switch f.SLAStatus {
		case "on_track":
			summary.OnTrackSLA++
		case "at_risk":
			summary.AtRiskSLA++
		case "overdue":
			summary.OverdueSLA++
		}

		// Quick wins: P1-P2 with Tier1 complexity
		if (f.Priority == P1 || f.Priority == P2) && f.ComplexityAssessment.Tier == Tier1 {
			summary.QuickWins++
			quickWinRiskScore += float64(f.RiskAssessment.RiskScore)
		}
	}

	// Calculate percentages
	if summary.TotalFindings > 0 {
		summary.AutoRemediationPct = float64(summary.AutoRemediationReady) / float64(summary.TotalFindings) * 100
	}
	if totalRiskScore > 0 {
		summary.QuickWinRiskReduction = quickWinRiskScore / totalRiskScore * 100
	}

	return summary
}

