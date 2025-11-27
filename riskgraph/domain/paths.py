"""
Path finding and persistence utilities.
"""
from __future__ import annotations

from typing import Iterable, List

from sqlmodel import Session, select

from riskgraph.domain.graph_model import RiskGraph
from riskgraph.domain.ingest import build_graph
from riskgraph.models import (
    Asset,
    AttackGraphSnapshot,
    AttackPath,
    Relationship,
)
from riskgraph.schemas import AttackPathRead, PathEdge, PathNode


class PathFindingError(Exception):
    pass


def _select_assets(
    assets: List[Asset], ids: Iterable[int] | None, criticalities: Iterable[str]
) -> List[int]:
    if ids:
        return [a.id for a in assets if a.id in ids]
    crit_set = {c.lower() for c in criticalities}
    return [a.id for a in assets if a.criticality.lower() in crit_set]


def _assemble_read_model(
    graph: RiskGraph, path: dict, snapshot_id: int
) -> AttackPathRead:
    node_objs = []
    for n_id in path["nodes"]:
        asset = graph.assets.get(n_id)
        node_objs.append(
            PathNode(
                id=n_id,
                name=asset.name if asset else str(n_id),
                type=asset.type if asset else "unknown",
                criticality=asset.criticality if asset else "medium",
            )
        )
    edge_objs = []
    for src, tgt, data in path["edges"]:
        rel: Relationship = data.get("relationship")
        edge_objs.append(
            PathEdge(
                id=rel.id if rel else None,
                source=src,
                target=tgt,
                relation_type=rel.relation_type if rel else data.get("relation_type", "unknown"),
                cost=data.get("cost", 1.0),
            )
        )
    return AttackPathRead(
        snapshot_id=snapshot_id,
        source_asset_id=path["nodes"][0],
        target_asset_id=path["nodes"][-1],
        nodes=node_objs,
        edges=edge_objs,
        cost=path["cost"],
        risk_score=path["risk"],
        explanation=None,
    )


def find_and_store_paths(
    session: Session,
    snapshot_id: int,
    k: int = 3,
    entry_ids: Iterable[int] | None = None,
    entry_criticality: Iterable[str] = ("low", "medium", "high", "crown_jewel"),
    target_ids: Iterable[int] | None = None,
    target_criticality: Iterable[str] = ("crown_jewel",),
) -> List[AttackPathRead]:
    snapshot = session.get(AttackGraphSnapshot, snapshot_id)
    if not snapshot:
        raise PathFindingError(f"Snapshot {snapshot_id} not found")
    graph = build_graph(session, snapshot.workspace_id)
    assets = session.exec(select(Asset).where(Asset.workspace_id == snapshot.workspace_id)).all()
    if entry_ids:
        entry_nodes = set(_select_assets(assets, entry_ids, entry_criticality))
    else:
        flagged = [a.id for a in assets if getattr(a, "entry", False)]
        entry_nodes = set(flagged) if flagged else set(_select_assets(assets, None, entry_criticality))
    target_nodes = set(_select_assets(assets, target_ids, target_criticality))
    if not entry_nodes or not target_nodes:
        raise PathFindingError("No entry or target nodes resolved for path search")
    raw_paths = graph.shortest_paths(entry_nodes, target_nodes, k=k)
    results: List[AttackPathRead] = []
    for p in raw_paths:
        read_model = _assemble_read_model(graph, p, snapshot_id)
        attack_path = AttackPath(
            snapshot_id=snapshot_id,
            source_asset_id=read_model.source_asset_id,
            target_asset_id=read_model.target_asset_id,
            node_ids=[n.id for n in read_model.nodes],
            edge_ids=[e.id for e in read_model.edges if e.id is not None],
            cost=read_model.cost,
            risk_score=read_model.risk_score,
            explanation=read_model.explanation,
        )
        session.add(attack_path)
        session.flush()
        read_model.id = attack_path.id
        results.append(read_model)
    session.commit()
    return results
