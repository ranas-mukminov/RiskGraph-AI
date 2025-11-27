# Architecture Overview

RiskGraph AI ingests infrastructure, identity, vulnerability, and control data into an attack graph, analyzes shortest and critical paths to crown jewels, and provides API/CLI access plus optional AI explanations.

## Components
- **Domain models (SQLModel)**: Workspace, Asset, Relationship, Vulnerability, AttackGraphSnapshot, AttackPath.
- **Graph engine**: `RiskGraph` wrapper over `networkx`, ready to swap for Neo4j/JanusGraph later.
- **Scoring**: Config-driven functions computing node risk, edge cost, and path risk.
- **Ingestion**: JSON bundle loader populating ORM models and building graphs.
- **Services**: Snapshot creation and path finding.
- **Interface layers**: FastAPI routers and Typer CLI; AI abstraction with dummy/stubbed clients.

## Flow
```
JSON bundle -> ingestion -> ORM (SQLite) -> build RiskGraph -> compute risks/paths -> API/CLI -> reports/AI explanations
```

## ERD (conceptual)
```
Workspace
  |--< Asset (type, criticality, entry, attributes)
  |     |--< Vulnerability (cve, cvss, exploit_available)
  |     |--< Relationship (source_asset_id -> target_asset_id, relation_type, cost, attributes)
  |
  |--< AttackGraphSnapshot (metadata, counts)
          |--< AttackPath (node_ids[], edge_ids[], cost, risk_score, explanation)
```

## Data Lifecycle
1. Create workspace.
2. Ingest bundle (assets, network, identities, vulns, controls).
3. Build snapshot: materialize graph, store counts/metadata.
4. Path analysis: shortest/K-shortest from entries to crown jewels, compute cost/risk, store AttackPath.
5. Optional AI summarization: translate paths into human-friendly findings and mitigations.

## Extensibility Notes
- Graph backend abstraction to support graph databases in enterprise editions.
- Database URL configurable; PostgreSQL-ready.
- Scoring weights configurable via environment (`RISKGRAPH_SCORING__*`).
- AI layer swappable; offline dummy provided.
