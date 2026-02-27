package contextual

import (
	"testing"
)

func TestClassifyEnvironment_TagPriority(t *testing.T) {
	tests := []struct {
		name         string
		resourceName string
		tags         map[string]string
		projectID    string
		want         EnvironmentTier
	}{
		// Tag-based classification (highest priority)
		{
			name: "tag environment=prod",
			tags: map[string]string{"environment": "prod"},
			want: Prod,
		},
		{
			name: "tag env=production",
			tags: map[string]string{"env": "production"},
			want: Prod,
		},
		{
			name: "tag stage=staging",
			tags: map[string]string{"stage": "staging"},
			want: Staging,
		},
		{
			name: "tag stage=stg",
			tags: map[string]string{"stage": "stg"},
			want: Staging,
		},
		{
			name: "tag environment=dev",
			tags: map[string]string{"environment": "dev"},
			want: Dev,
		},
		{
			name: "tag environment=development",
			tags: map[string]string{"environment": "development"},
			want: Dev,
		},
		{
			name: "tag environment=sandbox",
			tags: map[string]string{"environment": "sandbox"},
			want: Sandbox,
		},
		{
			name: "tag environment=sbx",
			tags: map[string]string{"environment": "sbx"},
			want: Sandbox,
		},
		{
			name: "tag environment=test",
			tags: map[string]string{"environment": "test"},
			want: Sandbox,
		},
		{
			name: "tag environment=qa",
			tags: map[string]string{"environment": "qa"},
			want: Sandbox,
		},
		// Tag takes precedence over resource name
		{
			name:         "tag prod overrides dev resource name",
			resourceName: "dev-api-server",
			tags:         map[string]string{"environment": "prod"},
			want:         Prod,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyEnvironment(tc.resourceName, tc.tags, tc.projectID)
			if got != tc.want {
				t.Errorf("ClassifyEnvironment(%q, %v, %q) = %v, want %v",
					tc.resourceName, tc.tags, tc.projectID, got, tc.want)
			}
		})
	}
}

func TestClassifyEnvironment_ResourceNamePatterns(t *testing.T) {
	tests := []struct {
		resourceName string
		want         EnvironmentTier
	}{
		{"prod-api-gateway", Prod},
		{"prd-database-01", Prod},
		{"production-cluster", Prod},
		{"api-production", Prod},

		{"staging-worker-1", Staging},
		{"stg-redis-cluster", Staging},
		{"preprod-bastion", Staging},
		{"pre-prod-vpc", Staging},

		{"dev-frontend-service", Dev},
		{"development-bucket", Dev},
		{"my-dev-instance", Dev},

		{"sandbox-experiment", Sandbox},
		{"sbx-load-balancer", Sandbox},
		{"test-runner-pool", Sandbox},
		{"qa-environment-42", Sandbox},
		{"uat-backend", Sandbox},

		// Unknown — no pattern match
		{"generic-service-name", Unknown},
		{"", Unknown},
	}

	for _, tc := range tests {
		t.Run(tc.resourceName, func(t *testing.T) {
			got := ClassifyEnvironment(tc.resourceName, nil, "")
			if got != tc.want {
				t.Errorf("ClassifyEnvironment(%q) = %v, want %v", tc.resourceName, got, tc.want)
			}
		})
	}
}

func TestClassifyEnvironment_ProjectIDFallback(t *testing.T) {
	tests := []struct {
		projectID string
		want      EnvironmentTier
	}{
		{"my-company-prod", Prod},
		{"acme-staging-project", Staging},
		{"team-dev-123", Dev},
		{"sandbox-gcp-project", Sandbox},
		{"unrelated-project", Unknown},
	}

	for _, tc := range tests {
		t.Run(tc.projectID, func(t *testing.T) {
			got := ClassifyEnvironment("", nil, tc.projectID)
			if got != tc.want {
				t.Errorf("ClassifyEnvironment projectID=%q = %v, want %v", tc.projectID, got, tc.want)
			}
		})
	}
}

func TestClassifyEnvironment_AllUnknown(t *testing.T) {
	got := ClassifyEnvironment("", nil, "")
	if got != Unknown {
		t.Errorf("expected Unknown for all-empty inputs, got %v", got)
	}
}

func TestEnvironmentTier_SeverityMultiplier(t *testing.T) {
	tests := []struct {
		tier EnvironmentTier
		want float64
	}{
		{Prod, 1.0},
		{Unknown, 1.0},
		{Staging, 0.8},
		{Dev, 0.5},
		{Sandbox, 0.3},
	}

	for _, tc := range tests {
		t.Run(tc.tier.String(), func(t *testing.T) {
			got := tc.tier.SeverityMultiplier()
			if got != tc.want {
				t.Errorf("%v.SeverityMultiplier() = %f, want %f", tc.tier, got, tc.want)
			}
		})
	}
}

func TestEnvironmentTier_String(t *testing.T) {
	tests := []struct {
		tier EnvironmentTier
		want string
	}{
		{Prod, "prod"},
		{Staging, "staging"},
		{Dev, "dev"},
		{Sandbox, "sandbox"},
		{Unknown, "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.tier.String(); got != tc.want {
				t.Errorf("%v.String() = %q, want %q", tc.tier, got, tc.want)
			}
		})
	}
}

func TestClassifyEnvironment_CaseInsensitiveTags(t *testing.T) {
	tests := []struct {
		tagKey string
		tagVal string
		want   EnvironmentTier
	}{
		{"ENVIRONMENT", "PROD", Prod},
		{"Environment", "Production", Prod},
		{"ENV", "Staging", Staging},
		{"Stage", "DEV", Dev},
	}

	for _, tc := range tests {
		t.Run(tc.tagKey+"="+tc.tagVal, func(t *testing.T) {
			got := ClassifyEnvironment("", map[string]string{tc.tagKey: tc.tagVal}, "")
			if got != tc.want {
				t.Errorf("ClassifyEnvironment(tags{%q:%q}) = %v, want %v", tc.tagKey, tc.tagVal, got, tc.want)
			}
		})
	}
}
