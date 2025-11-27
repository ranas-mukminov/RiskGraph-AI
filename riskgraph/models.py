"""
ORM models for RiskGraph AI.
"""
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


class Workspace(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    type: str
    subtype: Optional[str] = None
    name: str
    criticality: str = "medium"
    labels: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    attributes: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    entry: bool = False


class Relationship(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    source_asset_id: int = Field(foreign_key="asset.id", index=True)
    target_asset_id: int = Field(foreign_key="asset.id", index=True)
    relation_type: str
    cost: float = 1.0
    attributes: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    affected_asset_id: int = Field(foreign_key="asset.id", index=True)
    origin: Optional[str] = None
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    tags: List[str] = Field(default_factory=list, sa_column=Column(JSON))


class AttackGraphSnapshot(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id", index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    node_count: int = 0
    edge_count: int = 0
    vuln_count: int = 0


class AttackPath(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    snapshot_id: int = Field(foreign_key="attackgraphsnapshot.id", index=True)
    source_asset_id: int = Field(foreign_key="asset.id")
    target_asset_id: int = Field(foreign_key="asset.id")
    node_ids: List[int] = Field(default_factory=list, sa_column=Column(JSON))
    edge_ids: List[int] = Field(default_factory=list, sa_column=Column(JSON))
    cost: float = 0.0
    risk_score: float = 0.0
    explanation: Optional[str] = None
