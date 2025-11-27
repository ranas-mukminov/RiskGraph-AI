"""
Database engine and session utilities.
"""
from contextlib import contextmanager
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

from riskgraph.config import settings

engine = create_engine(settings.database_url, echo=False, future=True)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    with session_scope() as session:
        yield session
