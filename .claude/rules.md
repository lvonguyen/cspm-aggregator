# CSPM Aggregator - Claude Rules

## Project Context

- **Type**: Portfolio project for Staff/Principal Cloud Architect interviews
- **Language**: Go 1.23+
- **Module**: `github.com/lvonguyen/cspm-aggregator`
- **Status**: Active development

## Code Conventions

### Structure
- Use `cmd/{app}/main.go` for entrypoints
- Use `internal/` for private packages
- Use `configs/` for YAML configuration templates

### Style
- Provider abstraction via interfaces (e.g., `Provider`, `LLMProvider`, `ResourceMetadataProvider`)
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Structured logging with `zap`
- All write operations support `--dry-run` flag

### Security
- Zero stored credentials - use OIDC/WIF federation
- AWS: OIDC federation, no static keys
- Azure: Managed Identity
- GCP: Workload Identity Federation
- LLM API keys from Key Vault at runtime
- No hardcoded secrets, tenant IDs, or internal URLs
- Reference "a large automotive enterprise" not specific company names

## Documentation Standards

### No Emoji
Use ASCII symbols only:
- `[x]` not checkmark emoji
- `[!]` not warning emoji
- `->` not arrow emoji

### File Naming
- `HLD.md` - High-Level Design (markdown)
- `docs/HLD.docx` - High-Level Design (Word)
- `docs/pitch-deck-internal.pptx` - Stakeholder deck
- `docs/pitch-deck-interview.pptx` - Interview prep deck

### STAR Stories
Write STAR stories to shared repository:
- **Path**: `/Users/lvonguyen/repos/remote/gh/star-stories/`
- **Markdown**: `cspm-aggregator.md`
- **Word**: `cspm-aggregator.docx`
- Include quantified outcomes (%, hours saved, risk reduction)
- Reference enterprise patterns (OPA, Temporal, GRC integration)

## When Generating Code

1. Follow existing patterns in codebase
2. Include comprehensive error handling
3. Add structured logging at key points
4. Support configuration via YAML + env vars
5. Include unit test stubs

## When Generating Docs

1. Use Georgia font specifications from project instructions
2. No emoji - ASCII symbols only
3. Include quantified outcomes in STAR stories
4. Reference enterprise patterns

## Architecture Patterns

### Provider Layer
- Each cloud provider implements `Provider` interface
- Providers return normalized `Finding` structs
- Handle pagination internally

### Scoring Layer
- Rule-based first, AI fallback for unknowns
- Guardrails prevent unsafe AI decisions
- Tier 1/2/3 complexity classification

### Priority Matrix
- P1-P5 based on risk + complexity
- SLA tracking per priority level
- Queue routing for auto-remediation candidates

## Key Abstractions

| Interface | Purpose |
|-----------|---------|
| `Provider` | Cloud security findings source |
| `LLMProvider` | AI completion provider |
| `ResourceMetadataProvider` | Resource context enrichment |

## Project-Specific Notes

- AI scoring uses Claude Opus 4.5 for contextual risk assessment
- Complexity tiers determine automation candidacy
- Quick wins = P1/P2 + Tier1 + AutomationCandidate

---

*See portfolio-level instructions in Claude Project for full specifications.*
