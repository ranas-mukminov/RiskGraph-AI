"""
Workspace management endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from riskgraph.db import get_session
from riskgraph.models import Workspace
from riskgraph.schemas import WorkspaceCreate, WorkspaceRead

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


@router.post("", response_model=WorkspaceRead)
def create_workspace(payload: WorkspaceCreate, session: Session = Depends(get_session)) -> Workspace:
    ws = Workspace(name=payload.name, description=payload.description)
    session.add(ws)
    session.commit()
    session.refresh(ws)
    return ws


@router.get("", response_model=list[WorkspaceRead])
def list_workspaces(session: Session = Depends(get_session)) -> list[Workspace]:
    return session.exec(select(Workspace)).all()


@router.get("/{workspace_id}", response_model=WorkspaceRead)
def get_workspace(workspace_id: int, session: Session = Depends(get_session)) -> Workspace:
    ws = session.get(Workspace, workspace_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws
