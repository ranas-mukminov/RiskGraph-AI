RiskGraph AI – attack graph and risk prioritization engine for modern infrastructures.

Features
- Attack graph modeling with assets, identities, controls, vulnerabilities, and relationships.
- Ingestion from standardized JSON bundles (assets, network, identities, vulns, controls).
- Risk scoring and path analysis (shortest/K-shortest) with configurable weights.
- FastAPI backend and Typer CLI; optional AI layer with deterministic dummy explanations.
- Open-core friendly design with swappable graph backend and database.

Quickstart
1) Clone and install:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```
2) Ingest the example lab and build a graph:
```
riskgraph init-workspace --name "Lab"
riskgraph ingest-json --workspace-id 1 --path examples/small_lab
riskgraph build-graph --workspace-id 1
```
3) List top paths:
```
riskgraph list-paths --snapshot-id 1 --top 3
```
4) Run the API:
```
uvicorn riskgraph.api.main:app --reload
```

Testing
```
pytest
```
