# Ingestion Bundle Format

Provide a folder containing JSON files: `assets.json`, `network.json`, `identities.json`, `vulns.json`, `controls.json`.

## assets.json
Array of assets:
```json
[
  {
    "id": 1,
    "type": "host",
    "subtype": "web",
    "name": "WebServer",
    "criticality": "medium",
    "labels": ["prod"],
    "attributes": {"os": "linux"},
    "entry": true
  }
]
```

## network.json
Edges for reachability/dependencies:
```json
[
  {
    "source": 1,
    "target": 2,
    "relation_type": "can_reach",
    "cost": 2.0,
    "attributes": {"port": 443, "protocol": "https"}
  }
]
```

## identities.json
Privilege relationships:
```json
[
  {
    "identity_id": 10,
    "target_asset_id": 2,
    "privilege_type": "has_admin",
    "cost": 1.0,
    "attributes": {"role": "db_admin"}
  }
]
```

## vulns.json
Vulnerability findings:
```json
[
  {
    "asset_id": 2,
    "origin": "scanner",
    "cve_id": "CVE-2023-0001",
    "title": "Remote Code Execution",
    "cvss_score": 9.8,
    "exploit_available": true,
    "tags": ["rce"]
  }
]
```

## controls.json
Control coverage:
```json
[
  {
    "id": 50,
    "type": "edr",
    "name": "EDR-Agent",
    "protected_assets": [2, 3],
    "attributes": {"vendor": "Acme"}
  }
]
```

## Error Handling
- Each file must contain a JSON array; invalid records raise a 400 in the API.
- Relationships must reference asset IDs present in the bundle/workspace.
- Missing files are treated as empty lists.
