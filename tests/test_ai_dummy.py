import anyio

from riskgraph.domain.ai_client import DummyAttackGraphLLMClient
from riskgraph.schemas import AttackPathDTO, GraphContextDTO, PathEdge, PathNode


def test_dummy_ai_returns_summary():
    client = DummyAttackGraphLLMClient()
    nodes = [
        PathNode(id=1, name="Internet", type="external", criticality="low"),
        PathNode(id=2, name="DB", type="db", criticality="crown_jewel"),
    ]
    path = AttackPathDTO(
        source=nodes[0],
        target=nodes[-1],
        nodes=nodes,
        edges=[PathEdge(source=1, target=2, relation_type="can_reach", cost=1.0)],
        risk_score=5.0,
        cost=2.0,
    )
    explanation = anyio.run(client.explain_paths, [path], GraphContextDTO(environment="test"))
    assert "Analyzed 1 path" in explanation.summary
    assert explanation.key_findings
