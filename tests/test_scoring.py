from riskgraph.domain import scoring
from riskgraph.models import Asset, Relationship, Vulnerability


def test_node_risk_respects_controls_and_cvss():
    asset = Asset(id=1, workspace_id=1, type="host", name="A", criticality="high")
    vuln = Vulnerability(
        id=1,
        workspace_id=1,
        affected_asset_id=1,
        title="RCE",
        cvss_score=9.0,
        exploit_available=True,
    )
    risk_without_control = scoring.compute_node_risk(asset, [vuln], controls=[])
    risk_with_control = scoring.compute_node_risk(asset, [vuln], controls=["edr"])
    assert risk_without_control > risk_with_control
    assert risk_without_control > 0


def test_path_cost_and_risk_ordering():
    node_risks = [5, 8, 10]
    edge_costs_easy = [1, 1]
    edge_costs_hard = [5, 6]
    cost_easy, risk_easy = scoring.compute_path_scores(node_risks, edge_costs_easy)
    cost_hard, risk_hard = scoring.compute_path_scores(node_risks, edge_costs_hard)
    assert cost_easy < cost_hard
    assert risk_easy > risk_hard
