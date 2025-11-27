"""
RiskGraph abstraction built on top of networkx.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import networkx as nx

from riskgraph.domain import scoring
from riskgraph.models import Asset, Relationship, Vulnerability


@dataclass
class RiskGraph:
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    assets: Dict[int, Asset] = field(default_factory=dict)
    relationships: Dict[int | None, Relationship] = field(default_factory=dict)
    vulns_by_asset: Dict[int, List[Vulnerability]] = field(default_factory=dict)

    def add_asset(self, asset: Asset) -> None:
        if asset.id is None:
            raise ValueError("Asset must have an id to be added to graph.")
        self.assets[asset.id] = asset
        self.graph.add_node(asset.id, asset=asset)

    def add_relationship(self, rel: Relationship) -> None:
        if rel.source_asset_id not in self.assets or rel.target_asset_id not in self.assets:
            raise ValueError("Both source and target assets must be added before relationships.")
        cost = scoring.compute_edge_cost(rel)
        self.relationships[rel.id] = rel
        self.graph.add_edge(
            rel.source_asset_id,
            rel.target_asset_id,
            relationship=rel,
            cost=cost,
            relation_type=rel.relation_type,
        )

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulns_by_asset.setdefault(vuln.affected_asset_id, []).append(vuln)

    def controls_for_asset(self, asset_id: int) -> List[str]:
        controls: List[str] = []
        # Control edges modeled as control node -> asset with relation_type "protects"
        for src, tgt, data in self.graph.in_edges(asset_id, data=True):
            rel: Relationship = data.get("relationship")
            if rel and rel.relation_type in {"protects", "protected_by"}:
                control_asset = self.assets.get(src)
                if control_asset and control_asset.type == "control":
                    controls.append(control_asset.subtype or control_asset.type)
        return controls

    def compute_node_risks(self) -> Dict[int, float]:
        risks: Dict[int, float] = {}
        for asset_id, asset in self.assets.items():
            vulns = self.vulns_by_asset.get(asset_id, [])
            controls = self.controls_for_asset(asset_id)
            risks[asset_id] = scoring.compute_node_risk(asset, vulns, controls)
        return risks

    def _path_edges(self, path: Sequence[int]) -> List[Tuple[int, int, dict]]:
        edges: List[Tuple[int, int, dict]] = []
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i + 1]
            data = self.graph.get_edge_data(src, dst)
            if data is None:
                raise ValueError(f"Missing edge data for {src}->{dst}")
            edges.append((src, dst, data))
        return edges

    def _assemble_path(
        self, path_nodes: Sequence[int], node_risks: Dict[int, float]
    ) -> dict:
        edges = self._path_edges(path_nodes)
        edge_costs = [e[2].get("cost", 1.0) for e in edges]
        node_risk_values = [node_risks.get(n, 0.0) for n in path_nodes]
        path_cost, path_risk = scoring.compute_path_scores(node_risk_values, edge_costs)
        return {
            "nodes": path_nodes,
            "edges": edges,
            "edge_costs": edge_costs,
            "node_risks": node_risk_values,
            "cost": path_cost,
            "risk": path_risk,
        }

    def shortest_paths(
        self,
        entry_nodes: Iterable[int],
        target_nodes: Iterable[int],
        k: int = 3,
    ) -> List[dict]:
        node_risks = self.compute_node_risks()
        candidates: List[dict] = []
        for src in entry_nodes:
            for tgt in target_nodes:
                if src == tgt or not self.graph.has_node(src) or not self.graph.has_node(tgt):
                    continue
                try:
                    generator = nx.shortest_simple_paths(
                        self.graph, src, tgt, weight="cost"
                    )
                    for idx, path in enumerate(generator):
                        if idx >= k:
                            break
                        assembled = self._assemble_path(path, node_risks)
                        candidates.append(assembled)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        # Deduplicate identical node sequences and sort by cost then risk descending
        unique = {}
        for c in candidates:
            key = tuple(c["nodes"])
            if key not in unique or c["cost"] < unique[key]["cost"]:
                unique[key] = c
        return sorted(unique.values(), key=lambda x: (x["cost"], -x["risk"]))
