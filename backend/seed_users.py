"""Seed the default organisation and its users.

Every tenant-owned query filters on organization_id, so users created without
one can see nothing and the application appears broken on a fresh install. The
organisation is therefore created here, not assumed to exist.

Idempotent: safe to run more than once.
"""

import os

from backend.core.auth import hash_password
from backend.database import SessionLocal
from backend.models.models import Organization, Roles, User

DEFAULT_ORG_NAME = "Default Org"

# Development credentials. Overridable by environment so a deployment is not
# forced to create well-known accounts.
DEFAULT_USERS = [
    ("admin", "ADMIN_PASSWORD", "admin123", Roles.ADMIN),
    ("auditor1", "AUDITOR_PASSWORD", "auditor123", Roles.AUDITOR),
    ("analyst1", "ANALYST_PASSWORD", "analyst123", Roles.ANALYST),
]


def seed():
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.name == DEFAULT_ORG_NAME).first()
        if org is None:
            org = Organization(name=DEFAULT_ORG_NAME)
            db.add(org)
            db.commit()
            db.refresh(org)
            print(f"Created organisation: {DEFAULT_ORG_NAME} (id={org.id})")
        else:
            print(f"Organisation already exists: {DEFAULT_ORG_NAME} (id={org.id})")

        created, using_defaults = [], False
        for username, env_key, fallback, role in DEFAULT_USERS:
            if db.query(User).filter(User.username == username).first():
                continue
            password = os.getenv(env_key)
            if not password:
                password = fallback
                using_defaults = True
            db.add(User(
                username=username,
                hashed_password=hash_password(password),
                role=role,
                organization_id=org.id,
                is_active=True,
            ))
            created.append(f"{username} ({role})")

        db.commit()

        if created:
            print("Seeded users: " + ", ".join(created))
        else:
            print("Users already exist, nothing to seed.")

        if using_defaults:
            print(
                "\nWARNING: one or more accounts use well-known development "
                "passwords. Set ADMIN_PASSWORD / AUDITOR_PASSWORD / "
                "ANALYST_PASSWORD before exposing this service to a network."
            )
    finally:
        db.close()


if __name__ == "__main__":
    seed()