# StateWeaver Architecture

StateWeaver is structured as a modular pipeline designed to ingest API interaction telemetry, normalize request paths into semantic endpoint templates, build identity and workflow graphs, execute differential authorization test probes across distinct identity profiles, and validate policy compliance.

## System Architecture

```
                  ┌──────────────────────────────┐
                  │    HTTP Traffic Sources      │
                  │ (HAR 1.2 / OpenAPI 3.0 Spec) │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ Collector & Normalizer│
                     │  - Template Extractor │
                     │  - Redaction & Scrubber│
                     └───────────┬───────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │  SQLite Storage   │
                       │ (.stateweaver.db) │
                       └─────────┬─────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       ┌───────────────────┐           ┌───────────────────┐
       │   Graph Builder   │           │ Hypothesis Engine │
       │ - Identity Graph  │           │ - Test Generator  │
       │ - Workflow State  │           │ - Scope Checker   │
       └───────────────────┘           └─────────┬─────────┘
                                                 │
                                                 ▼
                                       ┌───────────────────┐
                                       │   Safe Executor   │
                                       │ - Rate Limiter    │
                                       │ - Request Budget  │
                                       │ - Safe Read-Only  │
                                       └─────────┬─────────┘
                                                 │
                                                 ▼
                                       ┌───────────────────┐
                                       │    Comparator     │
                                       │ - Dynamic Stripper│
                                       │ - Leak Detector   │
                                       └─────────┬─────────┘
                                                 │
                                                 ▼
                                       ┌───────────────────┐
                                       │ Policy Validator  │
                                       │ - Rule Matching   │
                                       │ - Confidence Rank │
                                       └─────────┬─────────┘
                                                 │
                                                 ▼
                                       ┌───────────────────┐
                                       │ Reporter (JSON,   │
                                       │   HTML, Markdown) │
                                       └───────────────────┘
```

## Component Overview

1. **Collector (`internal/collector/`)**:
   - `har.go`: Ingests HTTP Archive (HAR 1.2) files. Preserves raw status and body evidence while normalizing paths.
   - `openapi.go`: Parses OpenAPI 3.0 / Swagger specs into standardized endpoint records.

2. **Normalizer (`internal/normalizer/`)**:
   - Dynamically translates variable paths (`/api/projects/1001`) into semantic templates (`/api/projects/{project_id}`).
   - Scrubs volatile fields (timestamps, request IDs, CSRF tokens) so the differential comparator does not trigger false positives on innocuous non-deterministic attributes.

3. **Identity Manager (`internal/identity/`)**:
   - Manages multiple testing identities (Owner, Admin, Member, Viewer, Cross-Tenant, Revoked).
   - Supports environment variable resolution (`${TOKEN}`) to keep credentials out of source control.
   - Handles bearer tokens, headers, cookies, and basic auth.

4. **Engine (`internal/engine/`)**:
   - `generator.go`: Formulates test hypotheses across identities, resource ownership, and privilege boundaries.
   - `executor.go`: Enforces strict execution safety boundaries (rate limiting, timeout, redirect restrictions, max response byte limits, and read-only mode).
   - `comparator.go`: Conducts structural and content comparisons between the baseline response and probe responses.

5. **Policy Engine (`internal/policy/`)**:
   - Evaluates whether an observed response violates explicit researcher-defined policies (e.g. cross-tenant denial, viewer privilege restrictions, revoked credential rejection).

6. **Validator (`internal/validator/`)**:
   - Ensures findings are only generated when there is a concrete policy violation and supporting evidence.
   - Assigns severity, validation status, and confidence levels.
   - Redacts credentials in reproduction curl snippets and evidence summaries.

7. **Storage (`internal/storage/`)**:
   - Zero-dependency embedded SQLite (`modernc.org/sqlite`) for local persistence across commands.

8. **Reporter (`internal/reporter/`)**:
   - Emits structured JSON, GitHub Flavored Markdown, and standalone single-file HTML reports.

