"""
Pydantic schemas and DTOs for API and AI layers.
"""
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, Field, ConfigDict


class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None


class WorkspaceRead(WorkspaceCreate):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetIn(BaseModel):
    id: Optional[int] = None
    type: str
    subtype: Optional[str] = None
    name: str
    criticality: str = "medium"
    labels: List[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    entry: bool = False


class RelationshipIn(BaseModel):
    source: int
    target: int
    relation_type: str
    cost: Optional[float] = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityIn(BaseModel):
    asset_id: int
    origin: Optional[str] = None
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    tags: List[str] = Field(default_factory=list)


class ControlIn(BaseModel):
    id: Optional[int] = None
    type: str
    name: str
    protected_assets: List[int] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class IngestionBundle(BaseModel):
    assets: List[AssetIn] = Field(default_factory=list)
    network: List[RelationshipIn] = Field(default_factory=list)
    identities: List[RelationshipIn] = Field(default_factory=list)
    vulns: List[VulnerabilityIn] = Field(default_factory=list)
    controls: List[ControlIn] = Field(default_factory=list)


class GraphStats(BaseModel):
    snapshot_id: Optional[int] = None
    node_count: int
    edge_count: int
    vuln_count: int


class SnapshotRead(GraphStats):
    workspace_id: int
    created_at: datetime


class PathNode(BaseModel):
    id: int
    name: str
    type: str
    criticality: str


class PathEdge(BaseModel):
    id: Optional[int] = None
    source: int
    target: int
    relation_type: str
    cost: float


class AttackPathRead(BaseModel):
    id: Optional[int] = None
    snapshot_id: Optional[int] = None
    source_asset_id: int
    target_asset_id: int
    nodes: List[PathNode]
    edges: List[PathEdge]
    cost: float
    risk_score: float
    explanation: Optional[str] = None


class PathFindRequest(BaseModel):
    entry_criticality: List[str] = Field(default_factory=lambda: ["low", "medium", "high", "crown_jewel"])
    entry_ids: List[int] = Field(default_factory=list)
    target_criticality: List[str] = Field(default_factory=lambda: ["crown_jewel"])
    target_ids: List[int] = Field(default_factory=list)
    k: int = 3


class PathFindResponse(BaseModel):
    paths: List[AttackPathRead]


class AttackPathDTO(BaseModel):
    source: PathNode
    target: PathNode
    nodes: List[PathNode]
    edges: List[PathEdge]
    risk_score: float
    cost: float


class GraphContextDTO(BaseModel):
    workspace_name: Optional[str] = None
    environment: Optional[str] = None
    summary: Optional[str] = None


class MitigationAction(BaseModel):
    description: str
    impact: Optional[str] = None


class MitigationPlan(BaseModel):
    actions: List[MitigationAction]
    estimated_risk_reduction: Optional[str] = None


class AttackGraphExplanation(BaseModel):
    summary: str
    key_findings: List[str]
    mitigations: List[MitigationPlan] = Field(default_factory=list)
