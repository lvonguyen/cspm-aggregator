// Package config provides configuration loading and validation for CSPM Aggregator.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete application configuration.
type Config struct {
	Providers ProviderConfig `yaml:"providers"`
	Filters   FilterConfig   `yaml:"filters"`
	Asana     AsanaConfig    `yaml:"asana"`
	Email     EmailConfig    `yaml:"email"`
	Reports   ReportConfig   `yaml:"reports"`
	Schedule  ScheduleConfig `yaml:"schedule"`
	AI        AIConfig       `yaml:"ai"`
}

// ProviderConfig holds cloud provider settings.
type ProviderConfig struct {
	AWS   AWSProviderConfig   `yaml:"aws"`
	Azure AzureProviderConfig `yaml:"azure"`
	GCP   GCPProviderConfig   `yaml:"gcp"`
}

// AWSProviderConfig holds AWS-specific settings.
type AWSProviderConfig struct {
	Enabled bool     `yaml:"enabled"`
	UseOIDC bool     `yaml:"use_oidc"`
	RoleARN string   `yaml:"role_arn"`
	Regions []string `yaml:"regions"`
}

// AzureProviderConfig holds Azure-specific settings.
type AzureProviderConfig struct {
	Enabled            bool     `yaml:"enabled"`
	UseManagedIdentity bool     `yaml:"use_managed_identity"`
	TenantID           string   `yaml:"tenant_id"`
	Subscriptions      []string `yaml:"subscriptions"`
}

// GCPProviderConfig holds GCP-specific settings.
type GCPProviderConfig struct {
	Enabled       bool   `yaml:"enabled"`
	UseWIF        bool   `yaml:"use_wif"`
	OrganizationID string `yaml:"organization_id"`
	WIFConfigPath string `yaml:"wif_config_path"`
}

// FilterConfig defines which findings to include.
type FilterConfig struct {
	Severities     []string `yaml:"severities"`
	ExcludePreview bool     `yaml:"exclude_preview"`
	MaxAgeDays     int      `yaml:"max_age_days"`
}

// AsanaConfig holds Asana integration settings.
type AsanaConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ProjectGID string `yaml:"project_gid"`
}

// EmailConfig holds email notification settings.
type EmailConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Sender     string            `yaml:"sender"`
	Recipients EmailRecipients   `yaml:"recipients"`
}

// EmailRecipients maps team names to email addresses.
type EmailRecipients struct {
	InfoSec  []string `yaml:"infosec"`
	AWSops   []string `yaml:"aws_ops"`
	AzureOps []string `yaml:"azure_ops"`
	GCPOps   []string `yaml:"gcp_ops"`
}

// ReportConfig holds report generation settings.
type ReportConfig struct {
	OutputDir     string   `yaml:"output_dir"`
	Formats       []string `yaml:"formats"`
	IncludeCharts bool     `yaml:"include_charts"`
}

// ScheduleConfig holds scheduling settings (for reference).
type ScheduleConfig struct {
	MonthlyReport string `yaml:"monthly_report"`
	Timezone      string `yaml:"timezone"`
}

// AIConfig holds AI/LLM scoring settings.
type AIConfig struct {
	ModelName   string  `yaml:"model_name"`
	Temperature float64 `yaml:"temperature"`
	MaxTokens   int     `yaml:"max_tokens"`
	APIKeyEnv   string  `yaml:"api_key_env"` // Environment variable name for API key
}

// Load reads and parses configuration from the specified file path.
// Environment variables override YAML values where applicable.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Expand environment variables in YAML
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply environment variable overrides
	cfg.applyEnvOverrides()

	// Set defaults
	cfg.applyDefaults()

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// applyEnvOverrides applies environment variable overrides to config.
func (c *Config) applyEnvOverrides() {
	// AWS
	if v := os.Getenv("AWS_ROLE_ARN"); v != "" {
		c.Providers.AWS.RoleARN = v
	}

	// Azure
	if v := os.Getenv("AZURE_TENANT_ID"); v != "" {
		c.Providers.Azure.TenantID = v
	}

	// GCP
	if v := os.Getenv("GCP_ORG_ID"); v != "" {
		c.Providers.GCP.OrganizationID = v
	}
	if v := os.Getenv("GCP_WIF_CONFIG_PATH"); v != "" {
		c.Providers.GCP.WIFConfigPath = v
	}

	// Asana
	if v := os.Getenv("ASANA_PROJECT_GID"); v != "" {
		c.Asana.ProjectGID = v
	}

	// Email
	if v := os.Getenv("MAIL_SENDER_ADDRESS"); v != "" {
		c.Email.Sender = v
	}
}

// applyDefaults sets sensible defaults for unspecified values.
func (c *Config) applyDefaults() {
	// AI defaults
	if c.AI.ModelName == "" {
		c.AI.ModelName = "claude-opus-4-6"
	}
	if c.AI.Temperature == 0 {
		c.AI.Temperature = 0.1
	}
	if c.AI.MaxTokens == 0 {
		c.AI.MaxTokens = 1024
	}
	if c.AI.APIKeyEnv == "" {
		c.AI.APIKeyEnv = "ANTHROPIC_API_KEY"
	}

	// Filter defaults
	if len(c.Filters.Severities) == 0 {
		c.Filters.Severities = []string{"CRITICAL", "HIGH", "MEDIUM"}
	}
	if c.Filters.MaxAgeDays == 0 {
		c.Filters.MaxAgeDays = 90
	}

	// Report defaults
	if c.Reports.OutputDir == "" {
		c.Reports.OutputDir = "./reports"
	}
	if len(c.Reports.Formats) == 0 {
		c.Reports.Formats = []string{"html", "csv"}
	}
}

// Validate checks configuration for required values and consistency.
func (c *Config) Validate() error {
	// At least one provider must be enabled
	if !c.Providers.AWS.Enabled && !c.Providers.Azure.Enabled && !c.Providers.GCP.Enabled {
		return fmt.Errorf("at least one cloud provider must be enabled")
	}

	// AWS validation
	if c.Providers.AWS.Enabled {
		if c.Providers.AWS.UseOIDC && c.Providers.AWS.RoleARN == "" {
			return fmt.Errorf("AWS OIDC enabled but role_arn not set (use AWS_ROLE_ARN env var)")
		}
		if len(c.Providers.AWS.Regions) == 0 {
			return fmt.Errorf("AWS enabled but no regions specified")
		}
	}

	// Azure validation
	if c.Providers.Azure.Enabled {
		if c.Providers.Azure.UseManagedIdentity && c.Providers.Azure.TenantID == "" {
			return fmt.Errorf("Azure managed identity enabled but tenant_id not set (use AZURE_TENANT_ID env var)")
		}
	}

	// GCP validation
	if c.Providers.GCP.Enabled && c.Providers.GCP.UseWIF {
		if c.Providers.GCP.OrganizationID == "" {
			return fmt.Errorf("GCP WIF enabled but organization_id not set (use GCP_ORG_ID env var)")
		}
	}

	return nil
}

// EnabledProviders returns a list of enabled cloud provider names.
func (c *Config) EnabledProviders() []string {
	var providers []string
	if c.Providers.AWS.Enabled {
		providers = append(providers, "aws")
	}
	if c.Providers.Azure.Enabled {
		providers = append(providers, "azure")
	}
	if c.Providers.GCP.Enabled {
		providers = append(providers, "gcp")
	}
	return providers
}

// MaxFindingAge returns the maximum finding age as a duration.
func (c *Config) MaxFindingAge() time.Duration {
	return time.Duration(c.Filters.MaxAgeDays) * 24 * time.Hour
}
