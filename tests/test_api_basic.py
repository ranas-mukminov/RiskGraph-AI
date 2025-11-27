from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session, create_engine

from riskgraph import db
from riskgraph.api.main import app
from riskgraph.db import get_session


def override_session():
    with Session(db.engine) as session:
        yield session


def setup_module(module):
    # Configure in-memory DB for API tests
    db.engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(db.engine)
    app.dependency_overrides[get_session] = override_session


def test_api_happy_path():
    client = TestClient(app)
    ws_resp = client.post("/workspaces", json={"name": "api-test", "description": "desc"})
    assert ws_resp.status_code == 200
    workspace_id = ws_resp.json()["id"]

    folder = str(Path(__file__).parent.parent / "examples" / "small_lab")
    ingest_resp = client.post(f"/workspaces/{workspace_id}/ingest/json-bundle", json={"folder": folder})
    assert ingest_resp.status_code == 200

    snap_resp = client.post(f"/workspaces/{workspace_id}/snapshots/build", json={"source": "test"})
    assert snap_resp.status_code == 200
    snapshot_id = snap_resp.json()["snapshot_id"]
    assert snapshot_id is not None

    path_resp = client.post(
        f"/snapshots/{snapshot_id}/paths/find",
        json={"k": 2, "entry_ids": [], "target_ids": []},
    )
    assert path_resp.status_code == 200
    data = path_resp.json()
    assert "paths" in data
    assert len(data["paths"]) > 0
