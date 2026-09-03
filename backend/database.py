"""Database engine and session management."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from backend.config import DATABASE_URL

_is_sqlite = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    # Verify a pooled connection is alive before handing it out. Without this,
    # the first request after a database restart or an idle timeout fails with
    # a stale-connection error.
    pool_pre_ping=True,
    # Recycle connections before typical network/proxy idle timeouts close them.
    pool_recycle=1800,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Per-request database session.

    Rolls back explicitly on failure so a half-finished transaction is never
    left for the connection pool to hand to the next request.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()