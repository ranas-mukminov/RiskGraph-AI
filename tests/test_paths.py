from pathlib import Path

from riskgraph.domain.ingest import create_snapshot, ingest_from_json_files
from riskgraph.domain.paths import find_and_store_paths
from riskgraph.models import Workspace


def test_find_paths_returns_results(session):
    ws = Workspace(name="lab", description="lab")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    example_dir = Path(__file__).parent.parent / "examples" / "small_lab"
    ingest_from_json_files(str(example_dir), ws.id, session)
    _, snapshot = create_snapshot(session, ws.id, {"source": "test"})
    paths = find_and_store_paths(session, snapshot.id, k=2, entry_ids=[], target_ids=[])
    assert paths
    assert paths[0].nodes[0].name.lower().startswith("internet")
