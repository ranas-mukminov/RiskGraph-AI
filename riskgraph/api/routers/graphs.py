"""
Snapshot/graph metadata endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from riskgraph.db import get_session
from riskgraph.models import AttackGraphSnapshot
from riskgraph.schemas import GraphStats, SnapshotRead

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


@router.get("/{snapshot_id}", response_model=SnapshotRead)
def get_snapshot(snapshot_id: int, session: Session = Depends(get_session)) -> SnapshotRead:
    snapshot = session.get(AttackGraphSnapshot, snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return SnapshotRead(
        snapshot_id=snapshot.id,
        workspace_id=snapshot.workspace_id,
        created_at=snapshot.created_at,
        node_count=snapshot.node_count,
        edge_count=snapshot.edge_count,
        vuln_count=snapshot.vuln_count,
    )


@router.get("/{snapshot_id}/stats", response_model=GraphStats)
def snapshot_stats(snapshot_id: int, session: Session = Depends(get_session)) -> GraphStats:
    snapshot = session.get(AttackGraphSnapshot, snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return GraphStats(
        snapshot_id=snapshot.id,
        node_count=snapshot.node_count,
        edge_count=snapshot.edge_count,
        vuln_count=snapshot.vuln_count,
    )
