"""
Attack path analysis endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from riskgraph.db import get_session
from riskgraph.domain.ingest import build_graph
from riskgraph.domain.paths import PathFindingError, find_and_store_paths
from riskgraph.models import AttackPath, AttackGraphSnapshot, Relationship
from riskgraph.schemas import AttackPathRead, PathEdge, PathFindRequest, PathFindResponse, PathNode

router = APIRouter(prefix="/snapshots", tags=["paths"])


@router.post("/{snapshot_id}/paths/find", response_model=PathFindResponse)
def find_paths(
    snapshot_id: int, req: PathFindRequest, session: Session = Depends(get_session)
) -> PathFindResponse:
    try:
        paths = find_and_store_paths(
            session,
            snapshot_id,
            k=req.k,
            entry_ids=req.entry_ids,
            entry_criticality=req.entry_criticality,
            target_ids=req.target_ids,
            target_criticality=req.target_criticality,
        )
    except PathFindingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return PathFindResponse(paths=paths)


def _reconstruct_path(session: Session, path_obj: AttackPath) -> AttackPathRead:
    snapshot = session.get(AttackGraphSnapshot, path_obj.snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found for path")
    graph = build_graph(session, snapshot.workspace_id)
    node_objs = []
    for n_id in path_obj.node_ids:
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
    for i in range(len(path_obj.node_ids) - 1):
        src = path_obj.node_ids[i]
        tgt = path_obj.node_ids[i + 1]
        data = graph.graph.get_edge_data(src, tgt) or {}
        rel: Relationship | None = data.get("relationship")
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
        id=path_obj.id,
        snapshot_id=path_obj.snapshot_id,
        source_asset_id=path_obj.source_asset_id,
        target_asset_id=path_obj.target_asset_id,
        nodes=node_objs,
        edges=edge_objs,
        cost=path_obj.cost,
        risk_score=path_obj.risk_score,
        explanation=path_obj.explanation,
    )


@router.get("/paths/{path_id}", response_model=AttackPathRead)
def get_path(path_id: int, session: Session = Depends(get_session)) -> AttackPathRead:
    path_obj = session.get(AttackPath, path_id)
    if not path_obj:
        raise HTTPException(status_code=404, detail="Path not found")
    return _reconstruct_path(session, path_obj)
