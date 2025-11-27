"""
AI explanation and mitigation endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from riskgraph.db import get_session
from riskgraph.domain.ai_client import DummyAttackGraphLLMClient
from riskgraph.domain.ingest import build_graph
from riskgraph.models import AttackGraphSnapshot, AttackPath
from riskgraph.schemas import (
    AttackGraphExplanation,
    AttackPathDTO,
    GraphContextDTO,
    PathEdge,
    PathNode,
)

router = APIRouter(prefix="/paths", tags=["ai"])


class ExplainRequest(BaseModel):
    path_ids: list[int]
    environment: str | None = None


def _dto_from_attack_path(session: Session, path_obj: AttackPath) -> AttackPathDTO:
    snapshot = session.get(AttackGraphSnapshot, path_obj.snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found for path")
    graph = build_graph(session, snapshot.workspace_id)
    nodes = []
    for n_id in path_obj.node_ids:
        asset = graph.assets.get(n_id)
        nodes.append(
            PathNode(
                id=n_id,
                name=asset.name if asset else str(n_id),
                type=asset.type if asset else "unknown",
                criticality=asset.criticality if asset else "medium",
            )
        )
    edges = []
    for i in range(len(path_obj.node_ids) - 1):
        src = path_obj.node_ids[i]
        tgt = path_obj.node_ids[i + 1]
        data = graph.graph.get_edge_data(src, tgt) or {}
        rel = data.get("relationship")
        edges.append(
            PathEdge(
                id=rel.id if rel else None,
                source=src,
                target=tgt,
                relation_type=rel.relation_type if rel else data.get("relation_type", "unknown"),
                cost=data.get("cost", 1.0),
            )
        )
    return AttackPathDTO(
        source=nodes[0],
        target=nodes[-1],
        nodes=nodes,
        edges=edges,
        risk_score=path_obj.risk_score,
        cost=path_obj.cost,
    )


@router.post("/explain", response_model=AttackGraphExplanation)
async def explain_paths(req: ExplainRequest, session: Session = Depends(get_session)) -> AttackGraphExplanation:
    if not req.path_ids:
        raise HTTPException(status_code=400, detail="No path_ids provided")
    path_objs = []
    for pid in req.path_ids:
        obj = session.get(AttackPath, pid)
        if not obj:
            raise HTTPException(status_code=404, detail=f"Path {pid} not found")
        path_objs.append(obj)
    dtos = [_dto_from_attack_path(session, p) for p in path_objs]
    client = DummyAttackGraphLLMClient()
    context = GraphContextDTO(environment=req.environment)
    return await client.explain_paths(dtos, context)
