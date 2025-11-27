"""
FastAPI application entrypoint.
"""
from fastapi import FastAPI

from riskgraph.api.routers import ai, graphs, ingest, paths, workspaces
from riskgraph.db import init_db

app = FastAPI(title="RiskGraph AI", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    init_db()


app.include_router(workspaces.router)
app.include_router(ingest.router)
app.include_router(graphs.router)
app.include_router(paths.router)
app.include_router(ai.router)
