// Package main provides the entry point for CSPM Aggregator.
// This tool queries findings from AWS Security Hub, Azure Defender, and GCP SCC,
// normalizes them to a common schema, applies AI-powered risk scoring,
// and routes them to Asana with email notifications.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/lvonguyen/cspm-aggregator/internal/config"
	"github.com/lvonguyen/cspm-aggregator/internal/normalizer"
	awsprovider "github.com/lvonguyen/cspm-aggregator/internal/providers/aws"
	// azureprovider "github.com/lvonguyen/cspm-aggregator/internal/providers/azure"
	// gcpprovider "github.com/lvonguyen/cspm-aggregator/internal/providers/gcp"
	// "github.com/lvonguyen/cspm-aggregator/internal/scoring"
	// "github.com/lvonguyen/cspm-aggregator/internal/asana"
	// "github.com/lvonguyen/cspm-aggregator/internal/email"
	// "github.com/lvonguyen/cspm-aggregator/internal/reporter"
)

// Version information (injected at build time via ldflags)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Parse command-line flags
	dryRun := flag.Bool("dry-run", false, "Run without sending emails or updating Asana")
	cloud := flag.String("cloud", "all", "Cloud to query: aws, azure, gcp, or all")
	configPath := flag.String("config", "configs/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version and exit
	if *showVersion {
		fmt.Printf("CSPM Aggregator %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		os.Exit(0)
	}

	// Initialize logger
	logger, err := initLogger()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("Starting CSPM Aggregator",
		zap.String("version", Version),
		zap.Bool("dry_run", *dryRun),
		zap.String("cloud", *cloud),
		zap.String("config", *configPath),
	)

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}
	logger.Info("Configuration loaded",
		zap.Strings("enabled_providers", cfg.EnabledProviders()),
		zap.String("ai_model", cfg.AI.ModelName),
	)

	// Run the aggregation pipeline
	if err := run(ctx, logger, cfg, *cloud, *dryRun); err != nil {
		logger.Fatal("Aggregation failed", zap.Error(err))
	}

	logger.Info("CSPM Aggregator complete")
}

// run executes the main aggregation pipeline
func run(ctx context.Context, logger *zap.Logger, cfg *config.Config, cloudFilter string, dryRun bool) error {
	startTime := time.Now()

	// Step 1: Initialize providers based on config and filter
	providers := initProviders(ctx, logger, cfg, cloudFilter)
	if len(providers) == 0 {
		return fmt.Errorf("no providers initialized for cloud filter: %s", cloudFilter)
	}
	logger.Info("Initialized providers", zap.Int("count", len(providers)))

	// Step 2: Query findings from each provider
	var allFindings []normalizer.Finding
	for _, p := range providers {
		logger.Info("Querying provider", zap.String("provider", p.Name()))

		findings, err := queryProvider(ctx, p)
		if err != nil {
			logger.Error("Failed to query provider",
				zap.String("provider", p.Name()),
				zap.Error(err),
			)
			continue // Continue with other providers
		}

		logger.Info("Retrieved findings",
			zap.String("provider", p.Name()),
			zap.Int("count", len(findings)),
		)
		allFindings = append(allFindings, findings...)
	}

	logger.Info("Total findings collected",
		zap.Int("count", len(allFindings)),
		zap.Duration("query_duration", time.Since(startTime)),
	)

	if len(allFindings) == 0 {
		logger.Info("No findings to process")
		return nil
	}

	// Step 3: Load previous state for delta detection
	// TODO: Load from Azure Blob / S3 / GCS
	var previousState *normalizer.State

	// Step 4: Normalize and enrich findings
	norm := normalizer.NewNormalizer(loadAccountMappings(cfg), previousState)
	for i := range allFindings {
		norm.EnrichFinding(&allFindings[i])
	}

	// Detect closed findings
	closedFindings := norm.DetectClosedFindings(allFindings)
	allFindings = append(allFindings, closedFindings...)

	// Count by delta status
	stats := countByDelta(allFindings)
	logger.Info("Delta analysis complete",
		zap.Int("new", stats["NEW"]),
		zap.Int("existing", stats["EXISTING"]),
		zap.Int("closed", stats["CLOSED"]),
		zap.Int("reopened", stats["REOPENED"]),
	)

	// Step 5: Apply AI risk scoring (if enabled)
	// TODO: Initialize AI scorer and score findings
	// scorer := scoring.NewRiskScorer(llmProvider, enricher, fpStore, scoring.DefaultRiskScorerConfig())
	// for i := range allFindings {
	//     assessment, err := scorer.ScoreFinding(ctx, &allFindings[i])
	//     ...
	// }

	// Step 6: Apply complexity assessment
	// TODO: Assess remediation complexity
	// complexityNorm := scoring.NewComplexityNormalizer(llmProvider, metadata, scoring.DefaultComplexityConfig())

	// Step 7: Calculate priority matrix
	// TODO: Combine risk score + complexity → priority

	// Step 8: Sync to Asana (if not dry-run)
	if cfg.Asana.Enabled && !dryRun {
		logger.Info("Syncing to Asana", zap.String("project_gid", cfg.Asana.ProjectGID))
		// TODO: asanaClient.SyncFindings(ctx, allFindings)
	} else if dryRun {
		logger.Info("Dry-run: skipping Asana sync")
	}

	// Step 9: Generate reports
	if len(cfg.Reports.Formats) > 0 {
		logger.Info("Generating reports",
			zap.Strings("formats", cfg.Reports.Formats),
			zap.String("output_dir", cfg.Reports.OutputDir),
		)
		// TODO: reporter.GenerateReports(allFindings, cfg.Reports)
	}

	// Step 10: Send email notifications (if not dry-run)
	if cfg.Email.Enabled && !dryRun {
		logger.Info("Sending email notifications")
		// TODO: emailClient.SendReport(ctx, allFindings, cfg.Email)
	} else if dryRun {
		logger.Info("Dry-run: skipping email notifications")
	}

	// Step 11: Save state for next run
	// TODO: Save to Azure Blob / S3 / GCS

	logger.Info("Pipeline complete",
		zap.Duration("total_duration", time.Since(startTime)),
		zap.Int("total_findings", len(allFindings)),
	)

	return nil
}

// Provider is the interface for cloud security providers
type Provider interface {
	Name() string
	GetFindings(ctx context.Context) ([]normalizer.Finding, error)
}

// AWSProviderAdapter wraps the AWS provider to implement Provider interface
type AWSProviderAdapter struct {
	provider *awsprovider.SecurityHubProvider
}

func (a *AWSProviderAdapter) Name() string {
	return a.provider.Name()
}

func (a *AWSProviderAdapter) GetFindings(ctx context.Context) ([]normalizer.Finding, error) {
	awsFindings, err := a.provider.GetFindings(ctx)
	if err != nil {
		return nil, err
	}

	// Convert to normalized findings
	findings := make([]normalizer.Finding, 0, len(awsFindings))
	for _, f := range awsFindings {
		findings = append(findings, normalizer.Finding{
			FindingID:   f.ID,
			CSP:         "aws",
			AccountID:   f.AccountID,
			ResourceID:  f.ResourceID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			Status:      f.Status,
			ControlID:   f.Control,
			Standard:    f.Standard,
		})
	}
	return findings, nil
}

// initProviders initializes cloud providers based on config
func initProviders(ctx context.Context, logger *zap.Logger, cfg *config.Config, cloudFilter string) []Provider {
	var providers []Provider
	clouds := parseCloudFilter(cloudFilter, cfg)

	for _, cloud := range clouds {
		switch cloud {
		case "aws":
			if cfg.Providers.AWS.Enabled {
				logger.Info("Initializing AWS Security Hub provider",
					zap.Strings("regions", cfg.Providers.AWS.Regions),
					zap.Bool("use_oidc", cfg.Providers.AWS.UseOIDC),
				)
				// TODO: Initialize AWS SDK config with OIDC
				// awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Providers.AWS.Regions[0]))
				// providers = append(providers, &AWSProviderAdapter{provider: awsprovider.NewSecurityHubProvider(awsCfg, "")})
			}

		case "azure":
			if cfg.Providers.Azure.Enabled {
				logger.Info("Initializing Azure Defender provider",
					zap.String("tenant_id", cfg.Providers.Azure.TenantID),
					zap.Bool("use_managed_identity", cfg.Providers.Azure.UseManagedIdentity),
				)
				// TODO: Initialize Azure provider
			}

		case "gcp":
			if cfg.Providers.GCP.Enabled {
				logger.Info("Initializing GCP Security Command Center provider",
					zap.String("organization_id", cfg.Providers.GCP.OrganizationID),
					zap.Bool("use_wif", cfg.Providers.GCP.UseWIF),
				)
				// TODO: Initialize GCP provider
			}
		}
	}

	return providers
}

// parseCloudFilter determines which clouds to query
func parseCloudFilter(filter string, cfg *config.Config) []string {
	if filter == "all" {
		return cfg.EnabledProviders()
	}
	return strings.Split(filter, ",")
}

// queryProvider retrieves findings from a provider with timeout
func queryProvider(ctx context.Context, p Provider) ([]normalizer.Finding, error) {
	// Add timeout for provider queries
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	return p.GetFindings(queryCtx)
}

// loadAccountMappings loads account metadata from config or external source
func loadAccountMappings(cfg *config.Config) []normalizer.AccountInfo {
	// TODO: Load from config file or external API (ServiceNow CMDB, etc.)
	return []normalizer.AccountInfo{}
}

// countByDelta counts findings by delta status
func countByDelta(findings []normalizer.Finding) map[string]int {
	counts := map[string]int{
		"NEW":      0,
		"EXISTING": 0,
		"CLOSED":   0,
		"REOPENED": 0,
	}
	for _, f := range findings {
		counts[string(f.DeltaStatus)]++
	}
	return counts
}

// initLogger creates a production-ready zap logger
func initLogger() (*zap.Logger, error) {
	// Use JSON logging in production, console in development
	env := os.Getenv("APP_ENV")
	if env == "production" || env == "prod" {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}
