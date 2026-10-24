"""
database.py
-----------
SQLite connection + session handling (SQLAlchemy).
The database file (signature_system.db) is created automatically on first run.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'signature_system.db')}"

# check_same_thread=False: FastAPI may use a connection from different threads.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: one DB session per request, always closed afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create tables if they do not exist yet."""
    import models  # noqa: F401  (registers the tables with Base)
    Base.metadata.create_all(bind=engine)
