package gcp

import (
	"context"
	"fmt"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/api/iterator"
)

// SCCProvider queries findings from GCP Security Command Center
type SCCProvider struct {
	client *securitycenter.Client
	orgID  string
}

// NewSCCProvider creates a new Security Command Center provider
func NewSCCProvider(ctx context.Context, orgID string) (*SCCProvider, error) {
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCC client: %w", err)
	}

	return &SCCProvider{
		client: client,
		orgID:  orgID,
	}, nil
}

// Finding represents a normalized security finding
type Finding struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Status      string
	ResourceID  string
	ProjectID   string
	Control     string
	Standard    string
}

// GetFindings retrieves active findings from Security Command Center
func (p *SCCProvider) GetFindings(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	parent := fmt.Sprintf("organizations/%s/sources/-", p.orgID)

	// Filter for active findings with Critical/High/Medium severity
	filter := `state="ACTIVE" AND (severity="CRITICAL" OR severity="HIGH" OR severity="MEDIUM")`

	req := &securitycenterpb.ListFindingsRequest{
		Parent: parent,
		Filter: filter,
	}

	it := p.client.ListFindings(ctx, req)
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate findings: %w", err)
		}

		f := result.Finding
		finding := Finding{
			ID:          f.Name,
			Title:       f.Category,
			Description: f.Description,
			Severity:    f.Severity.String(),
			Status:      f.State.String(),
			ResourceID:  f.ResourceName,
			Control:     f.Category,
		}

		// Extract project ID from resource name
		if f.ResourceName != "" {
			finding.ProjectID = extractProjectID(f.ResourceName)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// Close closes the SCC client
func (p *SCCProvider) Close() error {
	return p.client.Close()
}

// Name returns the provider name
func (p *SCCProvider) Name() string {
	return "gcp-scc"
}

// extractProjectID extracts project ID from a resource name
func extractProjectID(resourceName string) string {
	// Resource names follow pattern: //cloudresourcemanager.googleapis.com/projects/{project-id}
	// or //compute.googleapis.com/projects/{project-id}/...
	// This is a simplified extraction
	return resourceName
}
