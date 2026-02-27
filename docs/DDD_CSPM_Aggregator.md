# CSPM Aggregator - Detailed Design Document (DDD)

---

## Document Control

| Version | Date | Author | Role | Contact |
|---------|------|--------|------|---------|
| 1.0 | 8 January 2026 | Liem Vo-Nguyen | Security Architect | <liem@vonguyen.io> |

---

## Table of Contents

| Section | Page |
|---------|------|
| [Architecture Decision Records](#architecture-decision-records) | 1 |
| [Data Flow Diagrams](#data-flow-diagrams) | 6 |
| [Component Design](#component-design) | 7 |
| [API Specifications](#api-specifications) | 9 |
| [Data Models](#data-models) | 11 |
| [AI Scoring Design](#ai-scoring-design) | 13 |
| [Security Design](#security-design) | 16 |
| [Appendix: Technology References](#appendix-technology-references) | 18 |

---

## Architecture Decision Records

### ADR-001: Language Selection

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to choose a language for the aggregator service that handles multi-cloud API calls, JSON processing, and LLM integration.

**Options**:

| Option | Pros | Cons |
|--------|------|------|
| Go | Single binary, fast startup, strong typing, excellent concurrency | Verbose error handling |
| Python | Rich AI/ML ecosystem, rapid prototyping | Slower startup, dependency management |
| Rust | Memory safety, performance | Steep learning curve, slower development |

**Decision**: **Go**

**Rationale**:
- Single binary deployment simplifies container images
- Fast cold start ideal for CronJob workloads
- Strong typing catches errors at compile time
- Excellent cloud SDK support (AWS, Azure, GCP)
- Go 1.23+ generics improve code reuse

---

### ADR-002: AI Provider Selection

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need an LLM provider for contextual risk scoring and complexity assessment fallback.

**Options**:

| Option | Pros | Cons |
|--------|------|------|
| Anthropic Claude | Superior reasoning, JSON mode, safety | API-only, no self-host |
| OpenAI GPT-4 | Wide adoption, function calling | Rate limits, cost |
| AWS Bedrock | Managed, multiple models | AWS lock-in, complexity |
| Self-hosted (Llama) | No API costs, privacy | Ops overhead, quality gap |

**Decision**: **Anthropic Claude (claude-opus-4-6)**

**Rationale**:
- Best-in-class reasoning for complex security context
- Native JSON output mode reduces parsing errors
- Consistent, deterministic output at low temperature (0.1)
- Strong safety alignment for security-sensitive prompts

---

### ADR-003: Authentication Strategy

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to authenticate to three cloud providers without storing credentials.

**Decision**: **Federated Identity (OIDC/MSI/WIF)**

| Cloud | Method | Token Lifetime |
|-------|--------|----------------|
| AWS | OIDC Federation via STS | 1 hour |
| Azure | Managed Identity | Automatic |
| GCP | Workload Identity Federation | 1 hour |

**Rationale**:
- Zero credential storage eliminates secret rotation burden
- Audit trail via cloud-native identity logs
- Automatic token refresh handled by SDKs
- Aligned with zero-trust architecture

---

### ADR-004: Deployment Model

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to run the aggregator on a schedule (monthly) with minimal operational overhead.

**Options**:

| Option | Pros | Cons |
|--------|------|------|
| Kubernetes CronJob | Native scheduling, resource limits | Requires cluster |
| Azure Functions (Timer) | Serverless, pay-per-use | Cold start, 10-min limit |
| AWS Lambda + EventBridge | Serverless | 15-min limit, cross-cloud auth complex |
| VM + cron | Simple | Always-on cost, manual patching |

**Decision**: **Kubernetes CronJob on AKS**

**Rationale**:
- Native Workload Identity integration for Azure
- No execution time limits (job can run 1+ hours)
- Resource limits and pod security policies
- Reuse existing AKS infrastructure

---

### ADR-005: State Storage

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to persist state between runs for delta detection (NEW/EXISTING/CLOSED/REOPENED).

**Options**:

| Option | Cost | Durability | Complexity |
|--------|------|------------|------------|
| Azure Blob Storage | $0.02/GB | 99.999999999% (11 9s) | Low |
| Azure Table Storage | $0.04/GB | 99.999999999% | Low |
| PostgreSQL | $25+/mo | High | Medium |
| Redis | $15+/mo | Medium | Low |

**Decision**: **Azure Blob Storage**

**Rationale**:
- Cheapest option for small state files (<1 MB)
- 11 9s durability with GRS replication
- Simple JSON file read/write (no ORM)
- Managed Identity authentication

---

### ADR-006: Complexity Assessment Strategy

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to classify findings into remediation complexity tiers (Tier1/2/3).

**Decision**: **Rule-based with AI fallback**

**Strategy**:

```
1. Try rule-based matching (25+ predefined rules)
   -> Match found -> Return tier

2. AI fallback for unknown finding types
   -> LLM assesses complexity
   -> Return tier with lower confidence

3. Conservative default
   -> Unknown + AI unavailable -> Tier3
```

**Rationale**:
- Rules provide deterministic, fast classification for known patterns
- AI handles novel/edge cases without manual rule updates
- Conservative default ensures no underestimation of effort

---

### ADR-007: Priority Matrix Design

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to combine risk severity and remediation complexity into actionable priorities.

**Decision**: **2D Matrix with Escalation Rules**

**Base Matrix**:

|             | Tier 1 | Tier 2 | Tier 3 |
|-------------|--------|--------|--------|
| CRITICAL    | P1     | P1     | P2     |
| HIGH        | P1     | P2     | P3     |
| MEDIUM      | P3     | P4     | P4     |
| LOW         | P4     | P5     | P5     |

**Escalation Rules** (can bump priority up):
1. Production environment: +1 priority (max P1)
2. PCI/PII data: +1 priority (max P2)
3. Internet-facing resource: +1 priority (max P2)
4. SLA overdue: +1 priority

**Rationale**:
- Simple mental model for security teams
- Escalations capture business context
- Maps cleanly to SLA timelines (P1=24h, P2=7d, P3=14d, P4=30d, P5=90d)

---

### ADR-008: Container Security

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to secure the container workload running in AKS.

**Decision**: **Defense in Depth**

| Control | Setting |
|---------|---------|
| Non-root user | `runAsUser: 1000` |
| Read-only filesystem | `readOnlyRootFilesystem: true` |
| No privilege escalation | `allowPrivilegeEscalation: false` |
| Drop all capabilities | `capabilities: { drop: [ALL] }` |
| Resource limits | `cpu: 1000m, memory: 1Gi` |

**Rationale**:
- Non-root prevents privilege escalation exploits
- Read-only filesystem limits persistence mechanisms
- Dropped capabilities reduce kernel attack surface
- Resource limits prevent DoS from runaway processes

---

### ADR-009: Network Policy

**Status**: Accepted
**Date**: 8 January 2026

**Context**: Need to restrict network access for the aggregator pod.

**Decision**: **Egress-only to DNS and HTTPS**

```yaml
egress:
  - ports: [53/UDP, 53/TCP]  # DNS
  - ports: [443/TCP]          # HTTPS
    to:
      - ipBlock:
          cidr: 0.0.0.0/0
          except:
            - 10.0.0.0/8
            - 172.16.0.0/12
            - 192.168.0.0/16
```

**Rationale**:
- DNS required for service discovery
- HTTPS required for cloud APIs and LLM
- Exclude private ranges to prevent lateral movement
- No ingress required (batch job, not server)

---

## Data Flow Diagrams

### Scoring Pipeline

![Scoring Pipeline](diagrams/dfd_scoring_pipeline.png)

*Shows: Cloud providers -> Normalizer -> Delta Detection -> AI Scoring -> Priority Matrix -> Outputs*

---

### Priority Matrix Flow

![Priority Matrix](diagrams/dfd_priority_matrix.png)

*Shows: Risk severity + Complexity tier -> Base priority -> Escalation rules -> Final priority + SLA*

---

## Component Design

### Package Structure

```
cspm-aggregator/
├── cmd/aggregator/          # Application entrypoint
│   └── main.go              # CLI flags, pipeline orchestration
├── internal/
│   ├── config/              # Configuration management
│   │   └── config.go        # YAML + env var loading
│   ├── providers/           # Cloud provider clients
│   │   ├── aws/securityhub.go
│   │   ├── azure/defender.go
│   │   └── gcp/scc.go
│   ├── normalizer/          # Common finding schema
│   │   └── schema.go        # Finding struct, delta detection
│   ├── scoring/             # AI scoring layer
│   │   ├── risk_scorer.go   # Contextual risk assessment
│   │   ├── complexity.go    # Remediation tier classification
│   │   └── priority.go      # Priority matrix calculation
│   ├── asana/               # Asana task sync
│   ├── email/               # Email notifications
│   └── reporter/            # Report generation
├── configs/config.yaml      # Configuration template
└── k8s/                     # Kubernetes manifests
```

### Interface Definitions

**Cloud Provider Interface**:

```go
type Provider interface {
    Name() string
    GetFindings(ctx context.Context) ([]normalizer.Finding, error)
}
```

**LLM Provider Interface**:

```go
type LLMProvider interface {
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
    Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error)
    CountTokens(ctx context.Context, text string) (int, error)
    ModelName() string
    MaxContextLength() int
    IsAvailable(ctx context.Context) bool
}
```

**Metadata Provider Interface**:

```go
type ResourceMetadataProvider interface {
    GetDependencyCount(ctx context.Context, resourceID string) (int, error)
    IsStateful(ctx context.Context, resourceID, resourceType string) (bool, error)
    IsSharedResource(ctx context.Context, resourceID string) (bool, error)
    GetSLATier(ctx context.Context, resourceID string) (string, error)
}
```

---

## API Specifications

### CLI Interface

```bash
# Full pipeline execution
./aggregator --config /app/configs/config.yaml

# Dry run (no external writes)
./aggregator --dry-run

# Single cloud provider
./aggregator --cloud aws

# Version info
./aggregator --version
```

### Planned HTTP API (v1.1)

**Get Prioritized Findings**:

```http
GET /api/v1/findings
  ?priority=P1,P2
  &severity=CRITICAL,HIGH
  &tier=Tier1
  &automation_candidate=true
  &queue=auto_remediation
  &sla_status=overdue
  &csp=aws,azure
  &cbu=BRAND1,BRAND2
  &limit=100
  &cursor=xxx

Response:
{
  "findings": [PrioritizedFinding],
  "summary": {
    "total": 150,
    "by_priority": {"P1": 5, "P2": 20, "P3": 45, "P4": 60, "P5": 20},
    "auto_remediation_ready": 12,
    "quick_win_risk_reduction_pct": 35.5
  },
  "next_cursor": "yyy"
}
```

**Dashboard Summary**:

```http
GET /api/v1/dashboard/summary

Response:
{
  "total_findings": 150,
  "p1_count": 5,
  "p2_count": 20,
  "p3_count": 45,
  "p4_count": 60,
  "p5_count": 20,
  "auto_remediation_ready": 12,
  "quick_wins": 8,
  "quick_win_risk_reduction_pct": 35.5,
  "on_track_sla": 120,
  "at_risk_sla": 20,
  "overdue_sla": 10,
  "trend": {
    "new_findings": 25,
    "closed_findings": 40,
    "net_change": -15,
    "closure_rate": 0.62
  }
}
```

**Quick Wins Report**:

```http
GET /api/v1/reports/quick-wins

Response:
{
  "quick_wins": [
    {
      "finding_id": "xxx",
      "title": "S3 bucket public access",
      "priority": "P1",
      "tier": "Tier1",
      "automation_candidate": true,
      "estimated_effort_hours": 0.5,
      "risk_reduction_pct": 5.2
    }
  ],
  "total_risk_reduction_pct": 35.5
}
```

---

## Data Models

### Common Finding Schema

```go
type Finding struct {
    // Core identification
    FindingID       string    `json:"finding_id"`
    FindingIDShort  string    `json:"finding_id_short"`  // SHA256 dedup key
    CSP             string    `json:"csp"`               // aws|azure|gcp
    AccountID       string    `json:"account_id"`
    ResourceID      string    `json:"resource_id"`

    // Details
    Title           string    `json:"title"`
    Description     string    `json:"description"`
    Severity        string    `json:"severity"`          // CRITICAL|HIGH|MEDIUM|LOW
    Status          string    `json:"status"`            // ACTIVE|RESOLVED|SUPPRESSED
    ControlID       string    `json:"control_id"`
    Standard        string    `json:"standard"`          // CIS|FSBP|MCSB

    // Classification (from org metadata)
    CBU             string    `json:"cbu"`               // Cost Business Unit
    Tier            string    `json:"tier"`              // Tier1-Prod|Tier2-NonProd|Tier3-Dev
    EnvType         string    `json:"env_type"`          // DEV|STG|PROD
    Owner           string    `json:"owner"`

    // Timestamps
    FirstSeen       time.Time `json:"first_seen"`
    LastSeen        time.Time `json:"last_seen"`
    RemediationSLA  time.Time `json:"remediation_sla"`

    // Tracking
    AsanaTaskID     string    `json:"asana_task_id,omitempty"`
    DeltaStatus     string    `json:"delta_status"`      // NEW|EXISTING|CLOSED|REOPENED
    DaysOpen        int       `json:"days_open"`
}
```

### Risk Assessment

```go
type RiskAssessment struct {
    OriginalSeverity   string   `json:"original_severity"`
    AdjustedSeverity   string   `json:"adjusted_severity"`
    SeverityDirection  string   `json:"severity_direction"`  // upgraded|downgraded|unchanged
    RiskScore          int      `json:"risk_score"`          // 1-100
    Confidence         float64  `json:"confidence"`          // 0.0-1.0
    Rationale          string   `json:"rationale"`
    MitigatingFactors  []string `json:"mitigating_factors"`
    AggravatingFactors []string `json:"aggravating_factors"`
    RecommendedAction  string   `json:"recommended_action"`  // remediate|accept_risk|investigate|suppress
    AutoAcceptEligible bool     `json:"auto_accept_eligible"`
    AutoAcceptReason   string   `json:"auto_accept_reason,omitempty"`
}
```

### Complexity Assessment

```go
type ComplexityAssessment struct {
    Tier                 int      `json:"tier"`                   // 1|2|3
    ComplexityScore      int      `json:"complexity_score"`       // 1-100
    AutomationCandidate  bool     `json:"automation_candidate"`
    AutomationBlockers   []string `json:"automation_blockers,omitempty"`

    // Coordination requirements
    RequiresAppTeam      bool     `json:"requires_app_team"`
    RequiresNetworkTeam  bool     `json:"requires_network_team"`
    RequiresDBTeam       bool     `json:"requires_db_team"`
    RequiresChangeWindow bool     `json:"requires_change_window"`
    RequiresDowntime     bool     `json:"requires_downtime"`

    // Impact estimates
    ServiceImpact        string   `json:"service_impact"`         // none|minimal|moderate|significant
    EstimatedDowntimeMin int      `json:"estimated_downtime_min"`
    EstimatedEffortHours float64  `json:"estimated_effort_hours"`
    RecommendedApproach  string   `json:"recommended_approach"`
    Rationale            string   `json:"rationale"`
}
```

### Prioritized Finding

```go
type PrioritizedFinding struct {
    Finding              Finding              `json:"finding"`
    RiskAssessment       RiskAssessment       `json:"risk_assessment"`
    ComplexityAssessment ComplexityAssessment `json:"complexity_assessment"`

    // Priority output
    Priority             string   `json:"priority"`              // P1|P2|P3|P4|P5
    EscalationReasons    []string `json:"escalation_reasons,omitempty"`
    Queue                string   `json:"queue"`                 // auto_remediation|security_review|app_team|change_board|remediation_queue
    AutoRemediationReady bool     `json:"auto_remediation_ready"`

    // SLA tracking
    SLADeadline          time.Time `json:"sla_deadline"`
    SLAStatus            string    `json:"sla_status"`           // on_track|at_risk|overdue
    DaysUntilSLA         int       `json:"days_until_sla"`
}
```

---

## AI Scoring Design

### Risk Scorer Architecture

**Context Signals (30+)**:

| Category | Signals |
|----------|---------|
| **Asset Classification** | AssetTier, EnvType, DataClassification, BusinessCriticality |
| **Network Exposure** | InternetFacing, VPCType, IngressPorts, EgressRestricted |
| **Compensating Controls** | WAFEnabled, EDREnabled, DLPEnabled, EncryptionAtRest, EncryptionInTransit, MFARequired, PrivateEndpoint |
| **Vulnerability Context** | CVSSScore, ExploitAvailable, ExploitInWild, PackageInUse, PatchAvailable |
| **Historical Patterns** | FalsePositiveHistory, FPRateForType |
| **Business Context** | ComplianceScopes, DataResidency, CostCenter, ApplicationOwner, SupportTier |

**Risk Scoring Flow**:

```
1. Enrich context from metadata providers
2. Load FP history for finding type
3. Check auto-accept scenarios:
   - LOW severity in sandbox -> auto-accept
   - High FP rate (>30%) + 3+ historical FPs -> auto-accept
4. Build LLM prompt with all context signals
5. Call Claude API (temperature=0.1)
6. Parse JSON response
7. Apply guardrails:
   - Never downgrade CRITICAL on Tier1-Prod + internet-facing
   - Minimum MEDIUM for PCI/PII data
   - Cap confidence at 70% when package usage unknown
   - Ensure risk score aligns with severity
```

### Complexity Normalizer Rules

**Tier 1 (Full Automation)**:

| Cloud | Finding Types |
|-------|---------------|
| AWS | S3 public access, logging disabled, IMDSv2, tagging, CloudTrail |
| Azure | HTTPS only, diagnostic logging |
| GCP | Public bucket access, audit logging |

**Tier 2 (Partial Automation)**:

| Cloud | Finding Types |
|-------|---------------|
| AWS | Security groups, IAM policies, TLS config, patching |
| Azure | NSG rules, Key Vault access |
| GCP | Firewall rules, IAM bindings |

**Tier 3 (Manual Execution)**:

| Cloud | Finding Types |
|-------|---------------|
| AWS | RDS config, network architecture, critical patches |
| Azure | SQL configuration |
| GCP | Cloud SQL, GKE cluster configuration |

**Environment Bumps**:
- Production environment: +1 tier
- Stateful resource (database, queue): +1 tier
- High dependencies (>5): +1 tier
- Shared resource: Minimum Tier2, no automation
- PCI/PII/PHI data: Minimum Tier2, requires change window

---

## Security Design

### Authentication Flow

![System Architecture](diagrams/hld_architecture.png)

*Shows: OIDC/MSI/WIF authentication to cloud providers, Key Vault for secrets*

### Data Access Control

| Data | Read | Write | Delete |
|------|------|-------|--------|
| Cloud findings | Aggregator | N/A | N/A |
| State files | Aggregator | Aggregator | Admin |
| Reports | Aggregator, Users | Aggregator | Admin |
| Config | Aggregator | Admin | Admin |
| Secrets | Aggregator | Admin | Admin |

### Secrets Management

| Secret | Storage | Rotation | Access |
|--------|---------|----------|--------|
| Anthropic API Key | Key Vault | Annual | Aggregator (MSI) |
| Asana PAT | Key Vault | Annual | Aggregator (MSI) |
| Graph Client Secret | Key Vault | Annual | Aggregator (MSI) |

### Audit Logging

| Event | Log Level | Fields |
|-------|-----------|--------|
| Pipeline start | INFO | timestamp, version, config_hash |
| Provider query | INFO | provider, finding_count, duration |
| AI scoring | DEBUG | finding_id, original_severity, adjusted_severity |
| External write | INFO | destination, record_count |
| Error | ERROR | operation, error_message, stack_trace |

---

## Appendix: Technology References

| Technology | Purpose | Documentation |
|------------|---------|---------------|
| [Go 1.23](https://go.dev/doc/) | Language runtime | Official docs |
| [AWS SDK for Go v2](https://aws.github.io/aws-sdk-go-v2/docs/) | AWS API client | AWS docs |
| [Azure SDK for Go](https://docs.microsoft.com/en-us/azure/developer/go/) | Azure API client | Microsoft docs |
| [GCP Go Client Libraries](https://cloud.google.com/go/docs/reference) | GCP API client | Google docs |
| [Anthropic Claude](https://docs.anthropic.com/) | LLM API | Anthropic docs |
| [Zap Logger](https://pkg.go.dev/go.uber.org/zap) | Structured logging | Uber docs |
| [Azure Blob Storage](https://docs.microsoft.com/en-us/azure/storage/blobs/) | State persistence | Microsoft docs |
| [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/) | Secrets management | Microsoft docs |
| [Kubernetes CronJob](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/) | Scheduling | K8s docs |
| [Asana API](https://developers.asana.com/docs/) | Task management | Asana docs |
| [Microsoft Graph](https://docs.microsoft.com/en-us/graph/) | Email API | Microsoft docs |
