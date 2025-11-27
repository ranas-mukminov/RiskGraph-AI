"""
Ingestion utilities for standardized JSON bundles.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from sqlmodel import Session, select

from riskgraph.domain.graph_model import RiskGraph
from riskgraph.models import (
    Asset,
    AttackGraphSnapshot,
    Relationship,
    Vulnerability,
    Workspace,
)


class IngestionError(Exception):
    pass


def _load_json(path: Path) -> list:
    if not path.exists():
        return []
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise IngestionError(f"Expected list in {path}")
    return data


def _ensure_workspace(session: Session, workspace_id: int) -> Workspace:
    ws = session.get(Workspace, workspace_id)
    if not ws:
        raise IngestionError(f"Workspace {workspace_id} not found")
    return ws


def ingest_from_json_files(folder: str, workspace_id: int, session: Session) -> Dict[str, int]:
    """
    Load assets, network, identities, vulns, and controls JSON files from folder.
    Returns counts for each entity type.
    """
    base = Path(folder)
    if not base.exists():
        raise IngestionError(f"Folder {folder} does not exist")
    _ensure_workspace(session, workspace_id)

    assets_data = _load_json(base / "assets.json")
    network_data = _load_json(base / "network.json")
    identity_data = _load_json(base / "identities.json")
    vulns_data = _load_json(base / "vulns.json")
    controls_data = _load_json(base / "controls.json")

    counts = {"assets": 0, "relationships": 0, "vulns": 0, "controls": 0}

    asset_lookup: Dict[int, Asset] = {}
    for item in assets_data:
        asset = Asset(
            id=item.get("id"),
            workspace_id=workspace_id,
            type=item["type"],
            subtype=item.get("subtype"),
            name=item["name"],
            criticality=item.get("criticality", "medium"),
            labels=item.get("labels", []),
            attributes=item.get("attributes", {}),
            entry=item.get("entry", False),
        )
        session.add(asset)
        session.flush()
        asset_lookup[asset.id] = asset
        counts["assets"] += 1

    # controls are assets of type control
    for item in controls_data:
        control_asset = Asset(
            id=item.get("id"),
            workspace_id=workspace_id,
            type="control",
            subtype=item.get("type"),
            name=item.get("name", item.get("type", "control")),
            criticality="medium",
            attributes=item.get("attributes", {}),
        )
        session.add(control_asset)
        session.flush()
        asset_lookup[control_asset.id] = control_asset
        counts["assets"] += 1
        counts["controls"] += 1
        for target in item.get("protected_assets", []):
            rel = Relationship(
                workspace_id=workspace_id,
                source_asset_id=control_asset.id,
                target_asset_id=target,
                relation_type="protects",
            )
            session.add(rel)
            counts["relationships"] += 1

    def _relationship_from_dict(d: dict) -> Relationship:
        return Relationship(
            workspace_id=workspace_id,
            source_asset_id=d["source"],
            target_asset_id=d["target"],
            relation_type=d.get("relation_type", "can_reach"),
            cost=d.get("cost", None) or 0.0,
            attributes=d.get("attributes", {}),
        )

    for rel_data in network_data:
        rel = _relationship_from_dict(rel_data)
        session.add(rel)
        counts["relationships"] += 1

    # identities modeled as relationships too
    for ident in identity_data:
        # support both identity_id/target_asset_id and source/target keys
        source = ident.get("identity_id") or ident.get("source")
        target = ident.get("target_asset_id") or ident.get("target")
        if source is None or target is None:
            raise IngestionError("Identity relationship missing source/target")
        rel = Relationship(
            workspace_id=workspace_id,
            source_asset_id=source,
            target_asset_id=target,
            relation_type=ident.get("privilege_type", ident.get("relation_type", "has_privilege")),
            cost=ident.get("cost", None) or 0.0,
            attributes=ident.get("attributes", {}),
        )
        session.add(rel)
        counts["relationships"] += 1

    for v in vulns_data:
        vuln = Vulnerability(
            workspace_id=workspace_id,
            affected_asset_id=v["asset_id"],
            origin=v.get("origin"),
            cve_id=v.get("cve_id"),
            title=v.get("title", "untitled"),
            description=v.get("description"),
            cvss_score=v.get("cvss_score"),
            exploit_available=v.get("exploit_available", False),
            tags=v.get("tags", []),
        )
        session.add(vuln)
        counts["vulns"] += 1

    session.commit()
    return counts


def build_graph(session: Session, workspace_id: int) -> RiskGraph:
    _ensure_workspace(session, workspace_id)
    graph = RiskGraph()
    assets = session.exec(select(Asset).where(Asset.workspace_id == workspace_id)).all()
    for a in assets:
        graph.add_asset(a)
    relationships = session.exec(select(Relationship).where(Relationship.workspace_id == workspace_id)).all()
    for r in relationships:
        graph.add_relationship(r)
    vulns = session.exec(select(Vulnerability).where(Vulnerability.workspace_id == workspace_id)).all()
    for v in vulns:
        graph.add_vulnerability(v)
    return graph


def create_snapshot(
    session: Session,
    workspace_id: int,
    source_metadata: dict | None = None,
) -> Tuple[RiskGraph, AttackGraphSnapshot]:
    graph = build_graph(session, workspace_id)
    snapshot = AttackGraphSnapshot(
        workspace_id=workspace_id,
        source_metadata=source_metadata or {},
        node_count=len(graph.assets),
        edge_count=len(graph.relationships),
        vuln_count=sum(len(v) for v in graph.vulns_by_asset.values()),
    )
    session.add(snapshot)
    session.commit()
    session.refresh(snapshot)
    return graph, snapshot
