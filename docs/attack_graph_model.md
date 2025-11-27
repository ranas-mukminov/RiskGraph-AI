# Attack Graph Model

## Nodes (Assets)
- `host`, `db`, `identity`, `network_segment`, `control`, `cloud_resource`, `external`.
- Attributes: `type`, `subtype`, `criticality` (low/medium/high/crown_jewel), `labels`, `attributes`, `entry` flag.
- Vulnerabilities attached to assets with CVE/CVSS metadata.

## Edges (Relationships)
- Directed: `can_reach`, `has_privilege`, `has_admin`, `has_credential`, `exploits`, `depends_on`, `protects`.
- Attributes: `cost` (attacker effort, lower is easier), port/protocol, notes.
- Controls represented as assets of type `control` linked via `protects`.

## Attack Paths
- Sequence of nodes/edges from entry to target.
- Path cost: `sum(edge_costs) + node_factor * sum(node_risks)`.
- Path risk: emphasizes high criticality/vulns and ease of traversal (low-cost edges).

## Scoring Defaults
- Criticality base: low=1, medium=3, high=6, crown_jewel=10.
- Vulnerability component: `max_cvss/2 + exploit_bonus`.
- Controls reduce node risk (EDR/segmentation/firewall/logging).
- Edge cost by relation_type (e.g., can_reach=3, has_admin=1, exploits=2).
- Configurable via environment (`RISKGRAPH_SCORING__relation_costs__can_reach=2.0` etc.).

## Example Mini-Graph
```
Internet (entry) --can_reach--> Web (vuln: RCE, cvss 9) --can_reach--> App --has_admin--> ProdDB (crown_jewel)
```
- Shortest path: Internet -> Web -> App -> ProdDB.
- Highest risk contributors: Web RCE, admin edge to ProdDB.
- Mitigation example: patch Web RCE, remove admin on ProdDB; EDR on App/DB lowers node risk.
