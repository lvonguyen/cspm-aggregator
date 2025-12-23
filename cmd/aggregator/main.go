package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

func main() {
	// Parse flags
	dryRun := flag.Bool("dry-run", false, "Run without sending emails or updating Asana")
	cloud := flag.String("cloud", "all", "Cloud to query: aws, azure, gcp, or all")
	configPath := flag.String("config", "configs/config.yaml", "Path to config file")
	flag.Parse()

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("Starting CSPM Aggregator",
		zap.Bool("dry_run", *dryRun),
		zap.String("cloud", *cloud),
		zap.String("config", *configPath),
	)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	// Suppress unused variable warning
	_ = ctx

	// TODO: Load config
	// TODO: Initialize providers based on --cloud flag
	// TODO: Query findings from each provider
	// TODO: Normalize findings to common schema
	// TODO: Sync to Asana (if not dry-run)
	// TODO: Generate report
	// TODO: Send email (if not dry-run)

	logger.Info("CSPM Aggregator complete")
}
