# High-Level Design: Cross-Cloud CSPM Automation Platform

| Property | Value |
| --- | --- |
| Version | 3.0 |
| Author | Liem Vo-Nguyen |
| Date | December 22, 2024 |
| Status | Draft |

---

## 1. Executive Summary

This document describes the architecture for an automated Cross-Cloud Security Posture Management (CSPM) reporting and remediation tracking platform. The solution uses a Go-based aggregator service orchestrated by Azure Automation Account to query security findings from AWS Security Hub, Azure Defender for Cloud, and GCP Security Command Center, normalize findings to a common schema, synchronize to Asana for remediation tracking, and distribute monthly summary reports to stakeholders.

### 1.1 Business Drivers

- Automate monthly CSPM findings reports to InfoSec and Operations teams
- Eliminate manual CSV export and email distribution process
- Provide consistent cross-cloud visibility (AWS, Azure, GCP)
- Enable automated Asana task creation for new findings
- Track remediation progress with delta detection and trend analysis
- Support CSPM compliance reporting requirements across all business units

---

## 2. Architecture Overview

The solution uses Azure Automation Account as the orchestration layer, executing a compiled Go binary on a scheduled basis. An Azure AD App Registration serves as the central identity for cross-cloud authentication via OIDC federation (AWS) and Workload Identity Federation (GCP).

### 2.1 Architecture Diagram

```
+-----------------------------------------------------------------------------+
|                           CSPM Aggregator Platform                           |
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
|  | (AWS SDK v2)     |    | (Azure SDK)      |    | Federation (GCP) |        |
|  +--------+---------+    +--------+---------+    +--------+---------+        |
|           |                       |                       |                  |
|           +-----------------------+-----------------------+                  |
|                                   |                                          |
|                                   v                                          |
|              +--------------------------------------------+                  |
|              |        Go Aggregator Binary                |                  |
|              |  +----------------+  +------------------+  |                  |
|              |  | Provider Layer |  | Normalizer/ETL   |  |                  |
|              |  +----------------+  +------------------+  |                  |
|              |  +----------------+  +------------------+  |                  |
|              |  | State Store    |  | Reporter         |  |                  |
|              |  +----------------+  +------------------+  |                  |
|              +--------------------------------------------+                  |
|                                   |                                          |
|              +--------------------+--------------------+                     |
|              |                    |                    |                     |
|              v                    v                    v                     |
|        +----------+        +----------+        +---------------+             |
|        | Asana    |        | Email    |        | Reports       |             |
|        | (Tasks)  |        | (Graph)  |        | (HTML/CSV)    |             |
|        +----------+        +----------+        +---------------+             |
|                                                                              |
+-----------------------------------------------------------------------------+
```

### 2.2 Component Summary

| Component | Purpose | Technology |
| --- | --- | --- |
| Orchestration Engine | Schedule and execute Go binary | Azure Automation Account (Hybrid Worker) |
| Central Identity | Cross-cloud auth + email capabilities | Azure AD App Registration |
| Azure Findings Query | Pull Defender for Cloud assessments | Azure SDK for Go + Managed Identity |
| AWS Findings Query | Pull Security Hub findings | AWS SDK v2 for Go + OIDC Federation |
| GCP Findings Query | Pull Security Command Center findings | GCP SDK for Go + Workload Identity Federation |
| Normalizer/ETL | Transform and enrich findings | Go structs + state comparison |
| State Store | Track finding history for delta detection | Azure Blob Storage (JSON) |
| Task Management | Create/update remediation tasks | Asana REST API |
| Email Distribution | Send reports + remediation notices | Microsoft Graph API |

---

## 3. Normalization ETL Pipeline

### 3.1 ETL Overview

The normalizer transforms provider-specific findings into a common schema, enriches with organizational metadata, and performs delta detection against previous state.

```
+-------------------+     +-------------------+     +-------------------+
| Provider Findings |---->| Normalize Schema  |---->| Enrich Metadata   |
| (AWS/Azure/GCP)   |     | (Common Format)   |     | (CBU/Tier/Owner)  |
+-------------------+     +-------------------+     +-------------------+
                                                            |
                                                            v
+-------------------+     +-------------------+     +-------------------+
| Output Actions    |<----| Delta Detection   |<----| Load Prev State   |
| (Asana/Email/Rpt) |     | (New/Closed/Reop) |     | (Blob Storage)    |
+-------------------+     +-------------------+     +-------------------+
```

### 3.2 Normalized Finding Schema

```go
type Finding struct {
    // Core identification
    FindingID      string    `json:"finding_id"`       // Provider-specific ID
    FindingIDShort string    `json:"finding_id_short"` // Dedupe key (hash)
    CSP            string    `json:"csp"`              // aws | azure | gcp
    AccountID      string    `json:"account_id"`       // Account/Sub/Project
    ResourceID     string    `json:"resource_id"`      // Affected resource ARN/ID
    
    // Finding details
    Title          string    `json:"title"`
    Description    string    `json:"description"`
    Severity       string    `json:"severity"`         // CRITICAL | HIGH | MEDIUM | LOW
    Status         string    `json:"status"`           // ACTIVE | RESOLVED | SUPPRESSED
    
    // Control mapping
    ControlID      string    `json:"control_id"`       // Control identifier
    Standard       string    `json:"standard"`         // CIS | FSBP | MCSB
    
    // Organizational classification
    CBU            string    `json:"cbu"`              // Business unit
    Tier           string    `json:"tier"`             // Tier 1 | Tier 2 | Tier 3
    EnvType        string    `json:"env_type"`         // DEV | STG | PROD
    Owner          string    `json:"owner"`            // Team or individual owner
    
    // Timestamps
    FirstSeen      time.Time `json:"first_seen"`
    LastSeen       time.Time `json:"last_seen"`
    
    // Remediation tracking
    AsanaTaskID    string    `json:"asana_task_id,omitempty"`
    RemediationSLA time.Time `json:"remediation_sla,omitempty"`
    
    // Delta tracking
    DeltaStatus    string    `json:"delta_status"`     // NEW | EXISTING | CLOSED | REOPENED
    DaysOpen       int       `json:"days_open"`
}
```

### 3.3 Delta Detection Logic

The ETL pipeline compares current findings against previous state to detect changes:

| Delta Status | Condition | Action |
| --- | --- | --- |
| NEW | Finding ID not in previous state | Create Asana task, include in "New Findings" report section |
| EXISTING | Finding ID in both current and previous state | Update LastSeen timestamp, calculate DaysOpen |
| CLOSED | Finding ID in previous state but not current | Mark Asana task complete, include in "Closed Findings" section |
| REOPENED | Finding ID was CLOSED in previous run, now ACTIVE | Reopen Asana task, flag for attention, include in "Reopened" section |

### 3.4 State Management

Finding state is persisted to Azure Blob Storage as JSON for cross-run comparison:

```
storage-account/
└── cspm-state/
    ├── aws/
    │   └── findings-2024-12-22.json
    ├── azure/
    │   └── findings-2024-12-22.json
    ├── gcp/
    │   └── findings-2024-12-22.json
    └── aggregated/
        ├── current.json          # Latest aggregated state
        └── history/
            └── 2024-12-22.json   # Historical snapshots
```

### 3.5 Trend Analysis

The ETL calculates trend metrics for reporting:

```go
type TrendMetrics struct {
    Period           string    `json:"period"`           // Monthly/Weekly
    TotalFindings    int       `json:"total_findings"`
    NewFindings      int       `json:"new_findings"`
    ClosedFindings   int       `json:"closed_findings"`
    ReopenedFindings int       `json:"reopened_findings"`
    NetChange        int       `json:"net_change"`       // New - Closed
    ClosureRate      float64   `json:"closure_rate"`     // Closed / (Previous Total)
    MTTR             float64   `json:"mttr_days"`        // Mean Time To Remediate
    
    // By severity
    BySeverity       map[string]int `json:"by_severity"`
    
    // By CSP
    ByCSP            map[string]int `json:"by_csp"`
    
    // SLA compliance
    WithinSLA        int       `json:"within_sla"`
    OverdueSLA       int       `json:"overdue_sla"`
}
```

---

## 4. Configuration Prerequisites

### 4.1 Azure AD App Registration (Central Identity)

A single App Registration serves multiple purposes: GCP Workload Identity Federation, AWS OIDC Federation, and Microsoft Graph email sending.

| Requirement | Configuration | Notes |
| --- | --- | --- |
| Application Name | cspm-automation | Created in Azure AD |
| Application Type | Daemon/Service Account | No user interaction |
| Supported Account Types | Single tenant | Organization tenant only |
| Application ID URI | api://{client-id} | Used as audience claim for GCP/AWS |
| Client Secret | Store in Key Vault | 24-month expiration |

**API Permissions Required (Application-level, Admin Consent Required):**

| Permission | Type | Purpose |
| --- | --- | --- |
| Mail.Send | Application | Send emails on behalf of service account |
| User.Read.All | Application | Validate email recipients |

### 4.2 Azure Automation Account

| Requirement | Configuration | Notes |
| --- | --- | --- |
| Automation Account | aa-cspm-automation | System-assigned MI enabled |
| Managed Identity Role | Reader | At Management Group or subscription scope |
| Hybrid Worker | Required for Go binary | Linux VM with Go runtime |
| Variables (Encrypted) | See table below | Stored securely in AA Variables |

**Required Environment Variables:**

| Variable Name | Purpose | Source |
| --- | --- | --- |
| AZURE_CLIENT_ID | App Registration client ID | Azure AD |
| AZURE_TENANT_ID | Azure AD tenant ID | Azure AD |
| AZURE_CLIENT_SECRET | App Registration secret | Key Vault reference |
| AWS_ROLE_ARN | IAM Role for OIDC | AWS IAM |
| GCP_WIF_CONFIG_PATH | Path to WIF credential config | Local file on Hybrid Worker |
| GCP_ORG_ID | GCP Organization ID | GCP Console |
| ASANA_PAT | Asana Personal Access Token | Key Vault reference |
| ASANA_PROJECT_GID | Target Asana project | Asana |
| MAIL_SENDER_ADDRESS | From address for notifications | Shared mailbox |
| STATE_STORAGE_ACCOUNT | Azure Storage account name | Azure Portal |
| STATE_CONTAINER | Blob container for state | Azure Portal |

### 4.3 AWS Security Hub Access (OIDC Federation)

| Requirement | Configuration | Notes |
| --- | --- | --- |
| OIDC Provider | Azure AD issuer URL | In Management Account IAM |
| IAM Role | cspm-reader-role | Trust policy for Azure AD |
| IAM Policy | SecurityAudit (managed) | Read-only Security Hub access |
| Location | Management Account | Centralized delegated admin |

**IAM Role Trust Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::{account}:oidc-provider/sts.windows.net/{tenant-id}/"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "sts.windows.net/{tenant-id}/:aud": "api://{azure-app-client-id}"
      }
    }
  }]
}
```

### 4.4 Azure Defender for Cloud Access

| Requirement | Configuration | Notes |
| --- | --- | --- |
| Authentication | System-assigned Managed Identity | No secrets required |
| Role Assignment | Reader | At Management Group scope |
| API | Azure Resource Graph | Queries microsoft.security/assessments |

### 4.5 GCP Security Command Center Access (Workload Identity Federation)

| Requirement | Configuration | Notes |
| --- | --- | --- |
| Authentication | Workload Identity Federation | No service account keys |
| Identity Provider | Azure AD App Registration | OIDC from Azure |
| WIF Pool | azure-cspm-pool | At GCP org level |
| Service Account | Existing SA for impersonation | With SCC viewer role |
| Role | securitycenter.findingsViewer | At organization scope |

**WIF Setup Commands:**

```bash
# Create pool
gcloud iam workload-identity-pools create azure-cspm-pool \
  --location="global" \
  --description="Azure AD federation for CSPM"

# Create OIDC provider
gcloud iam workload-identity-pools providers create-oidc azure-provider \
  --location="global" \
  --workload-identity-pool="azure-cspm-pool" \
  --issuer-uri="https://sts.windows.net/{tenant-id}/" \
  --allowed-audiences="api://{azure-app-client-id}" \
  --attribute-mapping="google.subject=assertion.sub"

# Generate credential config
gcloud iam workload-identity-pools create-cred-config \
  projects/{project-number}/locations/global/workloadIdentityPools/azure-cspm-pool/providers/azure-provider \
  --service-account="{sa}@{project}.iam.gserviceaccount.com" \
  --output-file="gcp_wif_config.json" \
  --azure
```

---

## 5. Data Flow

### 5.1 Monthly Execution Flow

```
1. Azure Automation triggers Go binary on schedule (1st of month, 8:00 AM)
   |
2. Load previous state from Azure Blob Storage
   |
3. Query each cloud provider in parallel:
   ├── AWS: Security Hub via OIDC federation
   ├── Azure: Defender for Cloud via Managed Identity  
   └── GCP: SCC via Workload Identity Federation
   |
4. Normalize findings to common schema
   |
5. Enrich with organizational metadata (CBU, Tier, Owner)
   |
6. Perform delta detection (New/Existing/Closed/Reopened)
   |
7. Calculate trend metrics
   |
8. Sync to Asana:
   ├── Create tasks for NEW findings
   ├── Update tasks for EXISTING findings
   ├── Complete tasks for CLOSED findings
   └── Reopen tasks for REOPENED findings
   |
9. Generate reports (HTML + CSV)
   |
10. Send emails via Microsoft Graph:
    ├── Summary to InfoSec team
    └── Cloud-specific to Ops teams
    |
11. Save current state to Azure Blob Storage
```

### 5.2 Report Sections

| Section | Content |
| --- | --- |
| Executive Summary | Total findings, net change, closure rate |
| Trend Chart | Month-over-month finding counts |
| New Findings | Findings detected this period |
| Reopened Findings | Previously closed, now active again |
| Closed Findings | Remediated since last report |
| Overdue SLA | Findings past remediation deadline |
| By Severity | Breakdown by CRITICAL/HIGH/MEDIUM/LOW |
| By Cloud | Breakdown by AWS/Azure/GCP |
| By Business Unit | Breakdown by CBU |

---

## 6. Security Considerations

### 6.1 Credential Management

| Credential Type | Storage | Rotation |
| --- | --- | --- |
| Azure AD Client Secret | Azure Key Vault | 24 months, with 60-day reminder |
| Asana PAT | Azure Key Vault | Annual |
| AWS IAM | OIDC Federation | No static credentials |
| GCP SA Key | WIF Federation | No static credentials |

### 6.2 Access Principles

- All cloud access is read-only (SecurityAudit / Reader roles)
- OIDC/WIF federation eliminates stored cloud credentials
- Managed Identity for Azure resources
- Secrets retrieved at runtime from Key Vault

---

## 7. Future Enhancements

| Enhancement | Benefit | Complexity |
| --- | --- | --- |
| Automated Remediation | Auto-fix common misconfigs | High |
| Splunk Integration | Centralized dashboards | Medium |
| ServiceNow Integration | ITSM workflow | Medium |
| Slack Notifications | Real-time alerts | Low |
| Custom SLA Rules | Per-severity deadlines | Low |
| Historical Trend API | Query past metrics | Medium |

---

## 8. Reference

### 8.1 Technology Stack

| Layer | Technology |
| --- | --- |
| Language | Go 1.21+ |
| AWS SDK | github.com/aws/aws-sdk-go-v2 |
| Azure SDK | github.com/Azure/azure-sdk-for-go |
| GCP SDK | cloud.google.com/go |
| Logging | go.uber.org/zap |
| Config | gopkg.in/yaml.v3 |

### 8.2 Reference Links

- AWS OIDC Federation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- GCP Workload Identity: https://cloud.google.com/iam/docs/workload-identity-federation
- Microsoft Graph Mail.Send: https://learn.microsoft.com/en-us/graph/api/user-sendmail
- Azure Resource Graph: https://learn.microsoft.com/en-us/azure/governance/resource-graph/
- AWS Security Hub: https://docs.aws.amazon.com/securityhub/latest/userguide/
- GCP SCC: https://cloud.google.com/security-command-center/docs

---

## Contact

**Author:** Liem Vo-Nguyen  
**Email:** liem@vonguyen.io  
**LinkedIn:** linkedin.com/in/liemvn
