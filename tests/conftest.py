import os

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, Session, create_engine

from riskgraph import db


@pytest.fixture
def session():
    db.engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(db.engine)
    with Session(db.engine) as session:
        yield session
