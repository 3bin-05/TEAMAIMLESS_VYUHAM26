from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings

import os

connect_args = {}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    # Ensure database folder exists for SQLite file paths
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes tables and ensures SQLite columns are synchronized safely."""
    Base.metadata.create_all(bind=engine)
    if settings.DATABASE_URL.startswith("sqlite"):
        from sqlalchemy import text
        with engine.connect() as conn:
            try:
                res = conn.execute(text("PRAGMA table_info(url_scans)")).fetchall()
                col_names = [r[1] for r in res]
                if col_names and "status" not in col_names:
                    conn.execute(text("ALTER TABLE url_scans ADD COLUMN status VARCHAR(32) DEFAULT 'pending'"))
                    conn.commit()
                if col_names and "user_id" not in col_names:
                    conn.execute(text("ALTER TABLE url_scans ADD COLUMN user_id VARCHAR(64)"))
                    conn.commit()
            except Exception:
                pass