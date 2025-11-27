"""
Risk scoring utilities for nodes, edges, and paths.
"""
from typing import Iterable, Sequence

from riskgraph.config import ScoringConfig, settings
from riskgraph.models import Asset, Relationship, Vulnerability


CRITICALITY_ORDER = ["low", "medium", "high", "crown_jewel"]


def criticality_weight(criticality: str, cfg: ScoringConfig | None = None) -> float:
    cfg = cfg or settings.scoring
    return cfg.criticality_base.get(criticality, cfg.criticality_base["medium"])


def compute_node_risk(
    asset: Asset,
    vulns: Iterable[Vulnerability] = (),
    controls: Iterable[str] = (),
    cfg: ScoringConfig | None = None,
) -> float:
    """
    Compute node risk based on asset criticality, vulnerabilities, and mitigating controls.
    """
    cfg = cfg or settings.scoring
    base = criticality_weight(asset.criticality, cfg)
    max_cvss = max((v.cvss_score or 0.0) for v in vulns) if vulns else 0.0
    exploit_bonus = cfg.exploit_available_bonus if any(v.exploit_available for v in vulns) else 0.0
    vuln_component = (max_cvss / 2.0) + exploit_bonus
    reduction = sum(cfg.control_reduction.get(c.lower(), 0.0) for c in controls)
    reduction = min(reduction, cfg.max_control_reduction)
    return max(base + vuln_component - reduction, 0.0)


def compute_edge_cost(rel: Relationship, cfg: ScoringConfig | None = None) -> float:
    cfg = cfg or settings.scoring
    if rel.cost is not None:
        return rel.cost
    return cfg.relation_costs.get(rel.relation_type, 3.0)


def compute_path_scores(
    node_risks: Sequence[float],
    edge_costs: Sequence[float],
    cfg: ScoringConfig | None = None,
) -> tuple[float, float]:
    """
    Return (path_cost, path_risk_score).
    - path_cost: sum of edge costs plus factor of node risk.
    - path_risk_score: emphasizes high criticality/vuln nodes and ease of traversal (low cost edges).
    """
    cfg = cfg or settings.scoring
    path_cost = sum(edge_costs) + cfg.path_node_factor * sum(node_risks)
    ease_scores = [max(0.0, 10.0 - c) for c in edge_costs] if edge_costs else []
    risk_score = max(node_risks) if node_risks else 0.0
    risk_score += 0.5 * sum(node_risks)
    risk_score += sum(ease_scores)
    return path_cost, risk_score
