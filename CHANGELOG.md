# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.4.0] - 2026-02-26

### Fixed
- Updated Anthropic model references from `claude-opus-4-5-20250514` to `claude-opus-4-6`

### Added
- MIT License

## [0.3.1] - 2026-02-16

### Changed
- Updated Claude agents symlink path for shared config

## [0.3.0] - 2026-01-14

### Added
- RunPod 2x B200 SSH config with 1Password integration for GPU workloads

### Changed
- Refreshed contributors cache

## [0.2.0] - 2026-01-08

### Added
- HLD and DDD documentation with architecture and DFD diagrams
- `Clone()` method to `CompletionRequest` to prevent shared mutable state bugs

### Changed
- Removed STAR stories from README (consolidated into star-stories repo)

## [0.1.1] - 2026-01-04

### Added
- Claude rules for AI-assisted development workflows
- Fixed import paths

## [0.1.0] - 2026-01-03

### Added
- AI scoring package for contextual risk prioritization
- Risk scorer with LLM-powered contextual severity adjustment
- Remediation complexity tiers (Tier 1 auto-remediate / Tier 2 partial / Tier 3 manual)
- Priority matrix P1-P5 with SLA tracking
- False positive detection via historical pattern analysis
- Quick wins identification for immediate impact findings

### Fixed
- Removed unused finding parameters in scoring functions
- Added missing `AutomationBlockers` field to `ComplexityRule` struct
- Removed duplicate source files from repo root

### Changed
- Upgraded LLM model to Claude Opus 4.5

## [0.0.1] - 2026-01-02

### Added
- Initial project structure with Go module dependencies
- AWS Security Hub, Azure Defender for Cloud, and GCP SCC providers
- Finding normalization to common schema
- Asana task sync integration
- Email notification support
- Zero stored credentials via OIDC / Managed Identity / Workload Identity Federation
