# CSPM Aggregator - High-Level Design (HLD)

---

## Document Control

| Version | Date | Author | Role | Contact |
|---------|------|--------|------|---------|
| 1.0 | 8 January 2026 | Liem Vo-Nguyen | Security Architect | <liem@vonguyen.io> |

---

## Table of Contents

| Section | Page |
|---------|------|
| [Executive Summary](#executive-summary) | 1 |
| [Architecture Overview](#architecture-overview) | 2 |
| [Component Descriptions](#component-descriptions) | 3 |
| [Data Flow](#data-flow) | 4 |
| [Security Architecture](#security-architecture) | 5 |
| [Integration Points](#integration-points) | 6 |
| [Build vs Buy Analysis](#build-vs-buy-analysis) | 7 |
| [Cost Analysis](#cost-analysis) | 8 |
| [Deployment Model](#deployment-model) | 9 |
| [DR/BC Architecture](#drbc-architecture) | 10 |
| [Technology Stack](#technology-stack) | 11 |
| [Architecture Decision Records](#architecture-decision-records) | 12 |

---

## Executive Summary

CSPM Aggregator is a **multi-cloud security posture management platform** that aggregates findings from AWS Security Hub, Azure Defender for Cloud, and GCP Security Command Center. It applies **AI-powered contextual risk scoring** and **remediation complexity analysis** to transform raw security findings into actionable, prioritized work items.

**Key Differentiators:**

- **Contextual AI Scoring**: Uses Claude API to analyze 30+ context signals (asset tier, network exposure, compensating controls, vulnerability details) and adjust finding severity beyond raw CSPM output
- **Remediation Complexity Tiers**: Classifies findings into Tier 1 (full automation), Tier 2 (partial automation), Tier 3 (manual) based on 25+ rules plus AI fallback
- **Priority Matrix**: Combines risk severity + complexity tier -> P1-P5 prioritization with SLA tracking
- **Zero Credential Storage**: Uses OIDC (AWS), Managed Identity (Azure), Workload Identity Federation (GCP)

**Target Users**: Security Operations, Cloud Engineering, Compliance Teams
**Deployment**: Kubernetes CronJob on Azure AKS
**Data Store**: Azure Blob Storage (state persistence)
**AI**: Anthropic Claude API (claude-opus-4-5-20250514)

---

## Architecture Overview

### High-Level System Diagram

![System Architecture](diagrams/hld_architecture.png)

### Architecture Principles

| Principle | Implementation |
|-----------|----------------|
| **Multi-Cloud Parity** | Normalized finding schema works across AWS, Azure, GCP |
| **Zero Trust** | OIDC/Managed Identity/WIF - no static credentials |
| **Read-Only Access** | SecurityAudit/Reader roles only |
| **AI-Augmented** | LLM scoring with guardrails and fallbacks |
| **Stateless Processing** | State externalized to Azure Blob Storage |

---

## Component Descriptions

### Cloud Provider Clients

| Provider | Service | Authentication | Data Source |
|----------|---------|----------------|-------------|
| **AWS** | Security Hub | OIDC Federation | Active findings (NEW, NOTIFIED) |
| **Azure** | Defender for Cloud | Managed Identity | Unhealthy assessments |
| **GCP** | Security Command Center | Workload Identity Federation | Active findings |

### Core Processing Pipeline

```
[Cloud Providers] -> [Normalizer] -> [Delta Detection] -> [AI Scoring] -> [Priority Matrix] -> [Output]
      |                   |                |                   |                |              |
   Raw findings     Common schema    NEW/EXISTING/       Risk + Complexity   P1-P5 +      Asana/Email/
                                    CLOSED/REOPENED      assessment          SLA          Reports
```

### AI Scoring Layer

| Component | Purpose | Lines of Code |
|-----------|---------|---------------|
| **Risk Scorer** | LLM-based contextual severity adjustment | 589 |
| **Complexity Normalizer** | Remediation tier classification (25+ rules + AI) | 905 |
| **Priority Calculator** | Risk + Complexity -> P1-P5 with escalations | 638 |

### Integration Services

| Service | Purpose | Authentication |
|---------|---------|----------------|
| **Asana** | Task creation and sync | Personal Access Token |
| **Microsoft Graph** | Email distribution | OAuth 2.0 Client Credentials |
| **Azure Blob Storage** | State persistence | Managed Identity |

---

## Data Flow

### Finding Ingestion Flow

![Scoring Pipeline](diagrams/dfd_scoring_pipeline.png)

### Data Transformation Stages

| Stage | Input | Output | Latency |
|-------|-------|--------|---------|
| **1. Query** | Cloud API credentials | Raw findings | 30-60s per provider |
| **2. Normalize** | Raw findings | Common schema | <1s |
| **3. Enrich** | Common schema | + Org metadata (CBU, Tier, Owner) | <1s |
| **4. Delta** | Current + Previous state | + DeltaStatus field | <5s |
| **5. Risk Score** | Enriched finding | + AI risk assessment | 2-5s per finding |
| **6. Complexity** | Enriched finding | + Complexity tier | 0.5-2s per finding |
| **7. Prioritize** | Risk + Complexity | P1-P5 + SLA + Queue | <1s |

### Priority Matrix

![Priority Matrix](diagrams/dfd_priority_matrix.png)

|             | Tier 1 (Auto) | Tier 2 (Partial) | Tier 3 (Manual) |
|-------------|---------------|------------------|-----------------|
| **CRITICAL**| P1            | P1               | P2              |
| **HIGH**    | P1            | P2               | P3              |
| **MEDIUM**  | P3            | P4               | P4              |
| **LOW**     | P4            | P5               | P5              |
| **INFO**    | P5            | P5               | P5              |

---

## Security Architecture

### Authentication Model

| Cloud | Method | Credential Storage | Rotation |
|-------|--------|-------------------|----------|
| **AWS** | OIDC Federation | None (STS) | Automatic |
| **Azure** | Managed Identity | None (MSI) | Automatic |
| **GCP** | Workload Identity Federation | None (WIF) | Automatic |
| **Anthropic** | API Key | Azure Key Vault | Manual (annual) |

### Data Protection

| Data Type | Classification | Protection |
|-----------|---------------|------------|
| **Finding metadata** | Internal | Encrypted at rest (AES-256) |
| **Resource IDs** | Internal | No PII extracted |
| **LLM prompts** | Internal | Sanitized (no PII/secrets) |
| **State files** | Internal | Blob encryption + RBAC |

### Container Security

| Control | Implementation |
|---------|----------------|
| **Non-root user** | UID 1000 |
| **Read-only filesystem** | `readOnlyRootFilesystem: true` |
| **No privilege escalation** | `allowPrivilegeEscalation: false` |
| **Dropped capabilities** | `drop: [ALL]` |
| **Resource limits** | CPU: 1000m, Memory: 1Gi |

### Network Security

```yaml
# NetworkPolicy - Egress only
egress:
  - to: [DNS (53), HTTPS (443)]
  - except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
```

---

## Integration Points

### Upstream (Data Sources)

| Source | Protocol | Rate Limit | Pagination |
|--------|----------|------------|------------|
| AWS Security Hub | HTTPS/REST | 10 TPS | Yes (paginator) |
| Azure Resource Graph | HTTPS/REST | 15 req/5s | Yes (skipToken) |
| GCP Security Command Center | HTTPS/gRPC | 1000 req/min | Yes (iterator) |

### Downstream (Outputs)

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| Asana | HTTPS/REST | Task creation and tracking |
| Microsoft Graph | HTTPS/REST | Email notifications |
| Azure Blob Storage | HTTPS/REST | State persistence |
| Local filesystem | File I/O | HTML/CSV reports |

### AI Integration

| Provider | Model | Temperature | Max Tokens | Use Case |
|----------|-------|-------------|------------|----------|
| Anthropic | claude-opus-4-5-20250514 | 0.1 | 1024 | Risk scoring |
| Anthropic | claude-opus-4-5-20250514 | 0.1 | 512 | Complexity fallback |

---

## Build vs Buy Analysis

| Component | Decision | Rationale |
|-----------|----------|-----------|
| **Cloud Provider Clients** | Build | Custom filtering, normalized output |
| **Finding Normalizer** | Build | Cross-cloud schema alignment |
| **Risk Scoring** | Build + Buy (LLM) | Contextual analysis requires AI |
| **Complexity Rules** | Build | Domain-specific remediation knowledge |
| **Priority Matrix** | Build | Custom escalation logic |
| **Asana Integration** | Build | Simple REST API |
| **Email (Graph)** | Build | Simple REST API |
| **State Storage** | Buy (Azure Blob) | Managed, encrypted, cheap |
| **Secrets** | Buy (Key Vault) | Managed rotation, audit |
| **Container Orchestration** | Buy (AKS) | Managed Kubernetes |

### Alternative Solutions Considered

| Alternative | Pros | Cons | Decision |
|-------------|------|------|----------|
| **Wiz/Orca** | Comprehensive CSPM | $100K+/year, no AI scoring customization | Pass |
| **Prisma Cloud** | Multi-cloud native | Complex licensing, limited priority logic | Pass |
| **Custom LLM (self-hosted)** | No API costs | Ops overhead, model quality | Pass |
| **ServiceNow integration** | Enterprise ITSM | Requires license, complex setup | Future |

---

## Cost Analysis

### Infrastructure Costs (Monthly)

| Component | Usage | Cost | Notes |
|-----------|-------|------|-------|
| **AKS Node** | 1 node (B2s) | $30 | Shared cluster |
| **Azure Blob Storage** | <1 GB | $0.02 | State files only |
| **Key Vault** | 10 secrets | $0.03 | Per-operation pricing |
| **Container Registry** | 1 image | $5 | Basic tier |
| **Egress** | <1 GB | $0.09 | API responses |
| **Subtotal (Infra)** | | **~$35** | |

### AI Costs (Monthly)

| Operation | Volume | Cost/Unit | Cost |
|-----------|--------|-----------|------|
| **Risk scoring** | 500 findings | $0.015/call | $7.50 |
| **Complexity fallback** | 50 findings | $0.008/call | $0.40 |
| **Subtotal (AI)** | | | **~$8** |

### Total Monthly Cost

| Scenario | Findings | Infrastructure | AI | Total |
|----------|----------|----------------|-----|-------|
| **Low** | 200 | $35 | $4 | **$39** |
| **Medium** | 500 | $35 | $8 | **$43** |
| **High** | 2,000 | $35 | $32 | **$67** |

---

## Deployment Model

### Kubernetes Architecture

```
AKS Cluster
├── Namespace: cspm-aggregator
│   ├── CronJob (monthly, 1st @ 8:00 AM PT)
│   │   ├── Pod (1 replica)
│   │   │   ├── Container: aggregator
│   │   │   ├── ServiceAccount + Workload Identity
│   │   │   └── Volume mounts (config, reports, tmp)
│   │   └── Secrets (from Key Vault via ESO)
│   ├── ConfigMap (config.yaml)
│   └── NetworkPolicy (egress-only)
└── Shared Infrastructure
    ├── Azure Key Vault
    └── Azure Blob Storage
```

### Deployment Lifecycle

| Event | Trigger | Action |
|-------|---------|--------|
| **Scheduled run** | CronJob (1st of month, 08:00 PT) | Full pipeline execution |
| **Manual run** | `kubectl create job --from=cronjob/cspm-aggregator` | Ad-hoc execution |
| **Image update** | Git push to main | CI/CD -> Container Registry -> kubectl rollout |

### Resource Configuration

```yaml
resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

---

## DR/BC Architecture

### Recovery Objectives

| Metric | Target | Rationale |
|--------|--------|-----------|
| **RTO** | 4 hours | Monthly batch job, not real-time |
| **RPO** | 30 days | State snapshot per run |
| **MTTR** | 1 hour | Redeploy from CI/CD |

### Failure Scenarios

| Scenario | Impact | Recovery |
|----------|--------|----------|
| **AKS cluster failure** | Job doesn't run | Manual trigger after cluster recovery |
| **Cloud provider API outage** | Partial data | Retry logic, skip unavailable provider |
| **AI API outage** | No scoring | Fallback to rule-based (conservative) |
| **State corruption** | Incorrect deltas | Re-run with `--reset-state` flag |

### Backup Strategy

| Data | Backup Location | Retention | Frequency |
|------|-----------------|-----------|-----------|
| **State files** | Azure Blob (GRS) | 90 days | Per run |
| **Reports** | Azure Blob (GRS) | 1 year | Per run |
| **Config** | Git repository | Indefinite | Per change |
| **Secrets** | Key Vault (soft delete) | 90 days | Manual |

---

## Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Language** | [Go 1.23+](https://go.dev/) | Performance, single binary, strong typing |
| **AI Provider** | [Anthropic Claude](https://www.anthropic.com/claude) | Best-in-class reasoning, JSON mode |
| **Cloud SDKs** | [AWS SDK v2](https://aws.github.io/aws-sdk-go-v2/docs/), [Azure SDK](https://github.com/Azure/azure-sdk-for-go), [GCP SDK](https://cloud.google.com/go/docs/reference) | Official, well-maintained |
| **Logging** | [go.uber.org/zap](https://pkg.go.dev/go.uber.org/zap) | Structured JSON logging |
| **Configuration** | [gopkg.in/yaml.v3](https://pkg.go.dev/gopkg.in/yaml.v3) | Human-readable, env var support |
| **Container** | [Docker](https://www.docker.com/) ([Alpine 3.19](https://www.alpinelinux.org/)) | Minimal attack surface |
| **Orchestration** | [Kubernetes](https://kubernetes.io/) ([AKS](https://azure.microsoft.com/products/kubernetes-service)) | Managed, Workload Identity native |
| **Secrets** | [Azure Key Vault](https://azure.microsoft.com/products/key-vault) | Managed rotation, audit logging |
| **State** | [Azure Blob Storage](https://azure.microsoft.com/products/storage/blobs) | Cheap, durable, encrypted |

---

## Architecture Decision Records

| ADR | Title | Decision | Rationale |
|-----|-------|----------|-----------|
| ADR-001 | Language Selection | Go | Performance, single binary deployment |
| ADR-002 | AI Provider | Anthropic Claude | Superior reasoning, JSON output |
| ADR-003 | Authentication | OIDC/MSI/WIF | Zero credential storage |
| ADR-004 | Deployment Model | Kubernetes CronJob | Scheduled batch, resource efficient |
| ADR-005 | State Storage | Azure Blob | Durable, encrypted, cheap |
| ADR-006 | Complexity Strategy | Rules + AI fallback | Deterministic where possible |
| ADR-007 | Priority Matrix | Risk x Complexity | Actionable prioritization |
| ADR-008 | Container Security | Non-root, read-only | Defense in depth |
| ADR-009 | Network Policy | Egress-only HTTPS | Minimize attack surface |

*Full ADR details in `docs/adr/` directory.*

---

## Future Roadmap

| Phase | Feature | Priority |
|-------|---------|----------|
| **v1.1** | HTTP API for on-demand queries | High |
| **v1.2** | Auto-remediation for Tier1 findings | High |
| **v1.3** | ServiceNow integration | Medium |
| **v2.0** | Real-time streaming (event-driven) | Low |
| **v2.1** | Custom rule engine (user-defined) | Low |
