"""Database initialisation.

Schema is owned by Alembic, NOT by this script.

Base.metadata.create_all() used to live here. It creates tables without
recording a migration version, so a database built that way is invisible to
Alembic: the next `alembic upgrade head` either fails on existing tables or
applies migrations out of order. Two sources of schema truth is worse than one
slow one.

Correct setup is:

    alembic upgrade head        # create/update schema
    python -m backend.seed_users
    python -m backend.seed_rules
    python -m backend.seed_frameworks

This script now only reports the current state so a misconfigured setup is
obvious rather than silent.
"""

from sqlalchemy import inspect, text

from backend.database import engine


def main():
    inspector = inspect(engine)
    tables = sorted(inspector.get_table_names())

    if not tables:
        print("No tables found. Create the schema with:\n\n    alembic upgrade head\n")
        return

    print(f"Connected. {len(tables)} table(s) present:")
    for t in tables:
        print(f"  - {t}")

    if "alembic_version" not in tables:
        print(
            "\nWARNING: no alembic_version table. This schema was not created by "
            "Alembic, so migrations cannot be applied safely. Recreate the "
            "database and run `alembic upgrade head`."
        )
        return

    with engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    print(f"\nAlembic revision: {version}")


if __name__ == "__main__":
    main()