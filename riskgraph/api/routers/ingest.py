"""
Ingestion endpoints.
"""
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from riskgraph.db import get_session
from riskgraph.domain.ingest import IngestionError, create_snapshot, ingest_from_json_files
from riskgraph.models import AttackGraphSnapshot, Workspace
from riskgraph.schemas import GraphStats, SnapshotRead

router = APIRouter(prefix="/workspaces", tags=["ingestion"])


class IngestRequest(BaseModel):
    folder: str


@router.post("/{workspace_id}/ingest/json-bundle")
def ingest_bundle(
    workspace_id: int,
    req: IngestRequest,
    session: Session = Depends(get_session),
) -> dict:
    try:
        counts = ingest_from_json_files(req.folder, workspace_id, session)
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"workspace_id": workspace_id, "counts": counts}


@router.post("/{workspace_id}/snapshots/build")
def build_snapshot(
    workspace_id: int,
    source_metadata: dict | None = Body(default=None),
    session: Session = Depends(get_session),
) -> GraphStats:
    try:
        _, snapshot = create_snapshot(session, workspace_id, source_metadata)
    except IngestionError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return GraphStats(
        snapshot_id=snapshot.id,
        node_count=snapshot.node_count,
        edge_count=snapshot.edge_count,
        vuln_count=snapshot.vuln_count,
    )


@router.get("/{workspace_id}/snapshots", response_model=list[SnapshotRead])
def list_snapshots(workspace_id: int, session: Session = Depends(get_session)) -> list[SnapshotRead]:
    ws = session.get(Workspace, workspace_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    snapshots = session.exec(select(AttackGraphSnapshot).where(AttackGraphSnapshot.workspace_id == workspace_id)).all()
    return [
        SnapshotRead(
            snapshot_id=s.id,
            workspace_id=s.workspace_id,
            created_at=s.created_at,
            node_count=s.node_count,
            edge_count=s.edge_count,
            vuln_count=s.vuln_count,
        )
        for s in snapshots
    ]
