"""
AI / LLM abstraction layer with dummy and stub implementations.
"""
from __future__ import annotations

from typing import List, Protocol

import httpx

from riskgraph.config import settings
from riskgraph.schemas import (
    AttackGraphExplanation,
    AttackPathDTO,
    GraphContextDTO,
    MitigationAction,
    MitigationPlan,
)


class AttackGraphLLMClient(Protocol):
    async def explain_paths(
        self, paths: List[AttackPathDTO], graph_context: GraphContextDTO, max_length: int = 1024
    ) -> AttackGraphExplanation:
        ...

    async def suggest_mitigations(
        self, paths: List[AttackPathDTO], graph_context: GraphContextDTO, constraints: dict | None = None
    ) -> List[MitigationPlan]:
        ...


class DummyAttackGraphLLMClient:
    """
    Deterministic, offline-friendly implementation.
    """

    async def explain_paths(
        self, paths: List[AttackPathDTO], graph_context: GraphContextDTO, max_length: int = 1024
    ) -> AttackGraphExplanation:
        path_count = len(paths)
        highest_risk = max((p.risk_score for p in paths), default=0.0)
        critical_nodes = {n.name for p in paths for n in p.nodes if n.criticality.lower() == "crown_jewel"}
        summary = (
            f"Analyzed {path_count} path(s). "
            f"Highest risk score {highest_risk:.2f}. "
            f"Crown jewels involved: {', '.join(sorted(critical_nodes)) or 'none'}."
        )
        findings = []
        for idx, p in enumerate(paths, start=1):
            node_names = " -> ".join([n.name for n in p.nodes])
            findings.append(f"Path {idx}: {node_names} (risk {p.risk_score:.2f}, cost {p.cost:.2f})")
        mitigations = await self.suggest_mitigations(paths, graph_context)
        return AttackGraphExplanation(summary=summary, key_findings=findings[:10], mitigations=mitigations)

    async def suggest_mitigations(
        self, paths: List[AttackPathDTO], graph_context: GraphContextDTO, constraints: dict | None = None
    ) -> List[MitigationPlan]:
        actions: List[MitigationAction] = []
        seen_assets = set()
        for p in paths:
            for node in p.nodes:
                if node.criticality.lower() in {"high", "crown_jewel"} and node.id not in seen_assets:
                    actions.append(
                        MitigationAction(
                            description=f"Reduce exposure and harden {node.name} (critical).",
                            impact="High",
                        )
                    )
                    seen_assets.add(node.id)
        if not actions:
            actions.append(MitigationAction(description="Improve network segmentation and patch exposed services."))
        return [MitigationPlan(actions=actions, estimated_risk_reduction="Qualitative high")]


class StubbedLLMClient:
    """
    Outline for calling an external LLM endpoint (no secrets included).
    """

    def __init__(self, endpoint: str | None = None, api_key: str | None = None):
        self.endpoint = endpoint or settings.llm_endpoint
        self.api_key = api_key or settings.llm_api_key

    async def explain_paths(
        self, paths: List[AttackPathDTO], graph_context: GraphContextDTO, max_length: int = 1024
    ) -> AttackGraphExplanation:
        if not self.endpoint or not self.api_key:
            raise RuntimeError("LLM endpoint/api key not configured")
        payload = {
            "paths": [p.dict() for p in paths],
            "graph_context": graph_context.dict(),
            "max_length": max_length,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        return AttackGraphExplanation(**data)

    async def suggest_mitigations(
        self, paths: List[AttackPathDTO], graph_context: GraphContextDTO, constraints: dict | None = None
    ) -> List[MitigationPlan]:
        if not self.endpoint or not self.api_key:
            raise RuntimeError("LLM endpoint/api key not configured")
        payload = {
            "paths": [p.dict() for p in paths],
            "graph_context": graph_context.dict(),
            "constraints": constraints or {},
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.endpoint}/mitigations",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        return [MitigationPlan(**item) for item in data]
