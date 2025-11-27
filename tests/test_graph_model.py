from riskgraph.domain.graph_model import RiskGraph
from riskgraph.models import Asset, Relationship


def build_simple_graph() -> RiskGraph:
    g = RiskGraph()
    nodes = [
        Asset(id=1, workspace_id=1, type="external", name="Internet", criticality="low", entry=True),
        Asset(id=2, workspace_id=1, type="host", name="Web", criticality="medium"),
        Asset(id=3, workspace_id=1, type="host", name="App", criticality="high"),
        Asset(id=4, workspace_id=1, type="db", name="DB", criticality="crown_jewel"),
    ]
    for n in nodes:
        g.add_asset(n)
    edges = [
        Relationship(id=1, workspace_id=1, source_asset_id=1, target_asset_id=2, relation_type="can_reach", cost=1),
        Relationship(id=2, workspace_id=1, source_asset_id=2, target_asset_id=3, relation_type="can_reach", cost=1),
        Relationship(id=3, workspace_id=1, source_asset_id=3, target_asset_id=4, relation_type="has_admin", cost=1),
    ]
    for e in edges:
        g.add_relationship(e)
    return g


def test_shortest_path():
    g = build_simple_graph()
    paths = g.shortest_paths(entry_nodes=[1], target_nodes=[4], k=1)
    assert len(paths) == 1
    assert paths[0]["nodes"] == [1, 2, 3, 4]


def test_missing_edge_breaks_path():
    g = build_simple_graph()
    # Remove an edge to break connectivity
    g.graph.remove_edge(2, 3)
    paths = g.shortest_paths(entry_nodes=[1], target_nodes=[4], k=1)
    assert len(paths) == 0
