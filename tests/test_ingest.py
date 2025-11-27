from pathlib import Path

from riskgraph.domain.ingest import build_graph, ingest_from_json_files
from riskgraph.models import Workspace


def test_ingest_bundle_creates_entities(session, tmp_path):
    workspace = Workspace(name="test", description="ingest")
    session.add(workspace)
    session.commit()
    session.refresh(workspace)

    example_dir = Path(__file__).parent.parent / "examples" / "small_lab"
    counts = ingest_from_json_files(str(example_dir), workspace.id, session)
    assert counts["assets"] >= 5
    assert counts["relationships"] > 0
    graph = build_graph(session, workspace.id)
    assert len(graph.assets) >= 5
    assert len(graph.relationships) > 0
