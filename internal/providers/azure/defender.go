package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// DefenderProvider queries findings from Azure Defender for Cloud
type DefenderProvider struct {
	client         *armresourcegraph.Client
	subscriptionID string
}

// NewDefenderProvider creates a new Defender for Cloud provider
func NewDefenderProvider(cred *azidentity.DefaultAzureCredential, subscriptionID string) (*DefenderProvider, error) {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource graph client: %w", err)
	}

	return &DefenderProvider{
		client:         client,
		subscriptionID: subscriptionID,
	}, nil
}

// Finding represents a normalized security finding
type Finding struct {
	ID             string
	Title          string
	Description    string
	Severity       string
	Status         string
	ResourceID     string
	SubscriptionID string
	Control        string
	Standard       string
}

// GetFindings retrieves unhealthy assessments from Defender for Cloud
func (p *DefenderProvider) GetFindings(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	// Resource Graph query for unhealthy security assessments
	query := `
		securityresources
		| where type == "microsoft.security/assessments"
		| where properties.status.code == "Unhealthy"
		| where properties.metadata.severity in ("High", "Medium", "Low")
		| project
			id,
			name,
			subscriptionId,
			resourceGroup,
			severity = tostring(properties.metadata.severity),
			title = tostring(properties.displayName),
			description = tostring(properties.metadata.description),
			resourceId = tostring(properties.resourceDetails.Id),
			control = tostring(properties.metadata.assessmentKey),
			standard = tostring(properties.metadata.policyDefinitionId)
	`

	subscriptions := []*string{&p.subscriptionID}

	result, err := p.client.Resources(ctx, armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: subscriptions,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query resource graph: %w", err)
	}

	// Parse results
	if result.Data != nil {
		data, ok := result.Data.([]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected result format")
		}

		for _, item := range data {
			row, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			finding := Finding{
				ID:             getString(row, "id"),
				Title:          getString(row, "title"),
				Description:    getString(row, "description"),
				Severity:       getString(row, "severity"),
				Status:         "Unhealthy",
				ResourceID:     getString(row, "resourceId"),
				SubscriptionID: getString(row, "subscriptionId"),
				Control:        getString(row, "control"),
				Standard:       getString(row, "standard"),
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// Name returns the provider name
func (p *DefenderProvider) Name() string {
	return "azure-defender"
}

// getString safely extracts a string from a map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		// Try JSON marshal for complex types
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
	}
	return ""
}
