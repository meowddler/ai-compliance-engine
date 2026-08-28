"""Seed a real compliance framework with canonical clause IDs.

A slice of ISO/IEC 27001:2022 Annex A. Real clause identifiers (e.g. A.8.5),
not free-text labels — this is what lets a control trace to a specific
regulatory obligation. Idempotent: running twice will not duplicate clauses.
"""
from backend.database import SessionLocal
from backend.models.models import Framework

# (clause_id, title) — a representative slice of ISO 27001:2022 Annex A
ISO_27001_2022 = [
    ("A.5.15", "Access control"),
    ("A.5.16", "Identity management"),
    ("A.5.17", "Authentication information"),
    ("A.8.2",  "Privileged access rights"),
    ("A.8.3",  "Information access restriction"),
    ("A.8.5",  "Secure authentication"),
    ("A.8.9",  "Configuration management"),
    ("A.8.15", "Logging"),
    ("A.8.16", "Monitoring activities"),
    ("A.8.20", "Networks security"),
    ("A.8.23", "Web filtering"),
    ("A.8.24", "Use of cryptography"),
]


def seed():
    db = SessionLocal()
    added = 0
    for clause_id, title in ISO_27001_2022:
        exists = db.query(Framework).filter(
            Framework.name == "ISO 27001",
            Framework.version == "2022",
            Framework.clause_id == clause_id,
        ).first()
        if exists:
            continue
        db.add(Framework(
            name="ISO 27001",
            version="2022",
            clause_id=clause_id,
            title=title,
        ))
        added += 1
    db.commit()
    total = db.query(Framework).count()
    print(f"Seeded {added} new clauses. Framework table now has {total} rows.")
    db.close()


if __name__ == "__main__":
    seed()