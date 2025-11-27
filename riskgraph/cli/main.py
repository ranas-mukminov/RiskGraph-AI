"""
Typer CLI for RiskGraph AI.
"""
from typing import Optional

import typer
from rich import print

from riskgraph.db import get_session, init_db
from riskgraph.domain.ingest import create_snapshot, ingest_from_json_files
from riskgraph.domain.paths import PathFindingError, find_and_store_paths
from riskgraph.models import Workspace

app = typer.Typer(help="RiskGraph AI CLI")


@app.callback()
def setup() -> None:
    init_db()


@app.command("init-workspace")
def init_workspace(name: str = typer.Option(...), description: str = typer.Option("")) -> None:
    with next(get_session()) as session:
        ws = Workspace(name=name, description=description)
        session.add(ws)
        session.commit()
        session.refresh(ws)
        print(f"[green]Created workspace {ws.id}: {ws.name}[/green]")


@app.command("ingest-json")
def ingest_json(workspace_id: int = typer.Option(...), path: str = typer.Option(...)) -> None:
    with next(get_session()) as session:
        counts = ingest_from_json_files(path, workspace_id, session)
        print(f"[green]Ingested[/green] assets={counts['assets']} relationships={counts['relationships']} vulns={counts['vulns']}")


@app.command("build-graph")
def build_graph(workspace_id: int = typer.Option(...)) -> None:
    with next(get_session()) as session:
        _, snapshot = create_snapshot(session, workspace_id, {"source": "cli"})
        print(
            f"[green]Snapshot {snapshot.id} built[/green]: nodes={snapshot.node_count} edges={snapshot.edge_count} vulns={snapshot.vuln_count}"
        )


@app.command("list-paths")
def list_paths(
    snapshot_id: int = typer.Option(...),
    top: int = typer.Option(3),
    entry_criticality: str = typer.Option("low,medium,high,crown_jewel"),
    target_criticality: str = typer.Option("crown_jewel"),
) -> None:
    entry_list = [c.strip() for c in entry_criticality.split(",") if c.strip()]
    target_list = [c.strip() for c in target_criticality.split(",") if c.strip()]
    with next(get_session()) as session:
        try:
            paths = find_and_store_paths(
                session,
                snapshot_id,
                k=top,
                entry_criticality=entry_list,
                target_criticality=target_list,
            )
        except PathFindingError as exc:
            typer.echo(f"Error: {exc}")
            raise typer.Exit(code=1)
        for p in paths:
            node_chain = " -> ".join(n.name for n in p.nodes)
            print(f"{p.id}: {node_chain} | cost={p.cost:.2f} risk={p.risk_score:.2f}")


@app.command("explain-paths")
def explain_paths_cli(
    snapshot_id: int = typer.Option(...),
    top: int = typer.Option(3),
    entry_criticality: str = typer.Option("low,medium,high,crown_jewel"),
    target_criticality: str = typer.Option("crown_jewel"),
) -> None:
    # For CLI simplicity, reuse list_paths run then print explanations from dummy AI.
    from riskgraph.api.routers.ai import _dto_from_attack_path
    from riskgraph.domain.ai_client import DummyAttackGraphLLMClient
    from riskgraph.schemas import GraphContextDTO
    from sqlmodel import select

    entry_list = [c.strip() for c in entry_criticality.split(",") if c.strip()]
    target_list = [c.strip() for c in target_criticality.split(",") if c.strip()]
    with next(get_session()) as session:
        paths = find_and_store_paths(
            session,
            snapshot_id,
            k=top,
            entry_criticality=entry_list,
            target_criticality=target_list,
        )
        client = DummyAttackGraphLLMClient()
        context = GraphContextDTO(environment="cli")
        # Fetch AttackPath objects freshly to ensure IDs
        from riskgraph.models import AttackPath

        path_objs = session.exec(
            select(AttackPath).where(AttackPath.id.in_([p.id for p in paths if p.id]))
        ).all()
        dtos = [_dto_from_attack_path(session, p) for p in path_objs]

    import anyio

    explanation = anyio.run(client.explain_paths, dtos, context)
    print(explanation.summary)
    for finding in explanation.key_findings:
        print(f"- {finding}")
    if explanation.mitigations:
        print("Mitigations:")
        for plan in explanation.mitigations:
            for action in plan.actions:
                print(f" * {action.description} (impact: {action.impact or 'n/a'})")
