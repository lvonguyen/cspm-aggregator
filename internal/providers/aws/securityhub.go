package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// SecurityHubProvider queries findings from AWS Security Hub
type SecurityHubProvider struct {
	client    *securityhub.Client
	accountID string
}

// NewSecurityHubProvider creates a new Security Hub provider
func NewSecurityHubProvider(cfg aws.Config, accountID string) *SecurityHubProvider {
	return &SecurityHubProvider{
		client:    securityhub.NewFromConfig(cfg),
		accountID: accountID,
	}
}

// Finding represents a normalized security finding
type Finding struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Status      string
	ResourceID  string
	AccountID   string
	Region      string
	Control     string
	Standard    string
}

// GetFindings retrieves active findings from Security Hub
func (p *SecurityHubProvider) GetFindings(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	// Filter for active findings with Critical/High/Medium severity
	filters := &types.AwsSecurityFindingFilters{
		WorkflowStatus: []types.StringFilter{
			{Value: aws.String("NEW"), Comparison: types.StringFilterComparisonEquals},
			{Value: aws.String("NOTIFIED"), Comparison: types.StringFilterComparisonEquals},
		},
		RecordState: []types.StringFilter{
			{Value: aws.String("ACTIVE"), Comparison: types.StringFilterComparisonEquals},
		},
		SeverityLabel: []types.StringFilter{
			{Value: aws.String("CRITICAL"), Comparison: types.StringFilterComparisonEquals},
			{Value: aws.String("HIGH"), Comparison: types.StringFilterComparisonEquals},
			{Value: aws.String("MEDIUM"), Comparison: types.StringFilterComparisonEquals},
		},
	}

	paginator := securityhub.NewGetFindingsPaginator(p.client, &securityhub.GetFindingsInput{
		Filters:    filters,
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get findings page: %w", err)
		}

		for _, f := range page.Findings {
			finding := Finding{
				ID:          aws.ToString(f.Id),
				Title:       aws.ToString(f.Title),
				Description: aws.ToString(f.Description),
				Severity:    string(f.Severity.Label),
				Status:      string(f.Workflow.Status),
				AccountID:   aws.ToString(f.AwsAccountId),
				Region:      aws.ToString(f.Region),
			}

			// Extract resource ID
			if len(f.Resources) > 0 {
				finding.ResourceID = aws.ToString(f.Resources[0].Id)
			}

			// Extract control from generator ID
			if f.GeneratorId != nil {
				finding.Control = aws.ToString(f.GeneratorId)
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// Name returns the provider name
func (p *SecurityHubProvider) Name() string {
	return "aws-securityhub"
}
