# CSPM Aggregator

**Last Updated:** 2024-12-22
**Version:** 1.0
**Author/Owner:** Liem Vo-Nguyen
**Status:** Draft

---

Cross-cloud CSPM automation platform for aggregating security findings from AWS Security Hub, Azure Defender for Cloud, and GCP Security Command Center.

## Purpose

Automate monthly CSPM reporting and remediation tracking:

- Query findings from AWS, Azure, and GCP security services
- Normalize findings to common schema with severity, CBU, and environment classification
- Sync findings to Asana for remediation task tracking
- Generate HTML/CSV reports and distribute via email
- Eliminate manual CSV export and email distribution

## Architecture

```
+-----------------------------------------------------------------------------+
|                           CSPM Aggregator                                    |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +------------------+    +------------------+    +------------------+        |
|  | AWS Security Hub |    | Azure Defender   |    | GCP Security     |        |
|  | (FSBP + CIS)     |    | for Cloud (MCSB) |    | Command Center   |        |
|  +--------+---------+    +--------+---------+    +--------+---------+        |
|           |                       |                       |                  |
|           v                       v                       v                  |
|  +--------+---------+    +--------+---------+    +--------+---------+        |
|  | OIDC Federation  |    | Managed Identity |    | Workload Identity|        |
|  +--------+---------+    +--------+---------+    | Federation       |        |
|           |                       |              +--------+---------+        |
|           |                       |                       |                  |
|           +-----------------------+-----------------------+                  |
|                                   |                                          |
|                                   v                                          |
|                    +-----------------------------+                           |
|                    | Go Aggregator Service       |                           |
|                    +-----------------------------+                           |
|                                   |                                          |
|                    +--------------+--------------+                           |
|                    |              |              |                           |
|                    v              v              v                           |
|              +----------+  +----------+  +---------------+                   |
|              | Asana    |  | Email    |  | Reports       |                   |
|              | (Tasks)  |  | (Graph)  |  | (HTML/CSV)    |                   |
|              +----------+  +----------+  +---------------+                   |
|                                                                              |
+-----------------------------------------------------------------------------+
```

## Component Summary

| Component | Purpose | Technology |
|-----------|---------|------------|
| AWS Provider | Query Security Hub | AWS SDK v2, OIDC Federation |
| Azure Provider | Query Defender for Cloud | Azure SDK, Managed Identity |
| GCP Provider | Query Security Command Center | GCP SDK, Workload Identity Federation |
| Normalizer | Common finding schema | Go structs |
| Reporter | Generate HTML/CSV reports | Go templates |
| Asana Sync | Create/update tasks | Asana REST API |
| Email | Send notifications | Microsoft Graph API |

## Prerequisites

- Go 1.21+
- AWS account with Security Hub enabled
- Azure subscription with Defender for Cloud
- GCP project with Security Command Center
- Asana workspace with project for tracking

## Quick Start

```bash
# Clone repository
git clone https://github.com/lvonguyen/cspm-aggregator.git
cd cspm-aggregator

# Build
go build -o bin/aggregator ./cmd/aggregator

# Configure (see configs/config.yaml)
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/cspm-reader
export AZURE_TENANT_ID=xxx
export GCP_ORG_ID=xxx
export ASANA_PAT=xxx

# Run dry-run
./bin/aggregator --dry-run --cloud all

# Run specific cloud
./bin/aggregator --cloud aws
```

## Project Structure

```
cspm-aggregator/
├── cmd/aggregator/              # Application entrypoint
├── internal/
│   ├── providers/
│   │   ├── aws/securityhub.go   # AWS Security Hub client
│   │   ├── azure/defender.go    # Azure Defender client
│   │   └── gcp/scc.go           # GCP SCC client
│   ├── normalizer/schema.go     # Common finding schema
│   ├── reporter/                # Report generation
│   ├── asana/                   # Asana task sync
│   └── email/                   # Email notifications
├── configs/
│   └── config.yaml              # Configuration
├── infrastructure/
│   ├── azure-automation/        # Azure Automation Account setup
│   ├── aws-oidc/                # AWS OIDC federation
│   └── gcp-wif/                 # GCP Workload Identity Federation
├── docs/
│   └── HLD.md                   # High-Level Design
└── README.md
```

## Authentication

### AWS (OIDC Federation)

Azure AD App Registration configured as OIDC provider in AWS IAM. IAM Role with SecurityAudit policy trusts the Azure AD issuer.

```bash
# Environment variables
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/cspm-reader
export AWS_REGION=us-east-1
```

### Azure (Managed Identity)

System-assigned managed identity with Reader role at management group or subscription scope.

```bash
# Environment variables
export AZURE_TENANT_ID=xxx
export AZURE_USE_MSI=true
```

### GCP (Workload Identity Federation)

Workload Identity Pool with Azure AD as OIDC provider. Service account impersonation grants securitycenter.findingsViewer role.

```bash
# Environment variables
export GCP_ORG_ID=123456789
export GCP_WIF_CONFIG_PATH=/path/to/wif-config.json
```

## Security Considerations

- All credentials via environment variables or cloud identity federation
- OIDC federation for AWS (no stored IAM keys)
- Managed Identity for Azure (no secrets)
- Workload Identity Federation for GCP (no service account keys)
- Read-only access to all cloud security services

## Data Flow

1. Aggregator queries each cloud provider for active findings
2. Findings normalized to common schema with CBU/Tier/EnvType
3. New findings synced to Asana (deduplicated by finding ID)
4. Summary HTML/CSV report generated
5. Email sent to distribution lists via Microsoft Graph

## Future Enhancements

| Enhancement | Benefit | Complexity |
|-------------|---------|------------|
| Automated Remediation | Auto-fix common misconfigurations | High |
| Splunk Integration | Centralized logging and dashboards | Medium |
| ServiceNow Integration | Enterprise ITSM workflow | Medium |
| Delta Detection | Alert on reopened findings | Low |

## Contact

**Author:** Liem Vo-Nguyen
**Email:** liem@vonguyen.io
**LinkedIn:** linkedin.com/in/liemvn
