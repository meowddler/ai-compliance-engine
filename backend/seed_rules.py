"""Seed baseline compliance rules for the default organisation.

Rules must belong to an organisation: every rule query filters on
organization_id, so rules seeded without one are invisible and scans evaluate
nothing — the application looks functional but silently checks no controls.

Idempotent: safe to run more than once.
"""

import json

from backend.database import SessionLocal
from backend.models.models import Organization, Rule

DEFAULT_ORG_NAME = "Default Org"

BASELINE_RULES = [
    {
        "name": "exposed_port_no_mfa",
        "description": "Port is exposed to the network and MFA is not enabled",
        "framework": "ISO 27001",
        "severity": "HIGH",
        "remediation": "Enable MFA or restrict network exposure for this port.",
        "condition": [
            {"field": "port_exposed", "operator": "==", "value": True},
            {"field": "mfa_enabled", "operator": "==", "value": False},
        ],
    },
    {
        "name": "risky_port_open",
        "description": "High-risk port (SSH/RDP) is exposed",
        "framework": "PCI DSS",
        "severity": "HIGH",
        "remediation": "Restrict SSH/RDP access to trusted IPs or VPN only.",
        "condition": [
            {"field": "port", "operator": "in", "value": [22, 3389]},
            {"field": "port_exposed", "operator": "==", "value": True},
        ],
    },
    {
        "name": "excessive_failed_logins",
        "description": "Unusually high number of failed login attempts (possible brute force)",
        "framework": "SOC 2",
        "severity": "MEDIUM",
        "remediation": "Investigate for brute-force activity and enforce lockout policies.",
        "condition": [
            {"field": "failed_logins", "operator": ">", "value": 5},
        ],
    },
    {
        "name": "stale_account",
        "description": "Account has not been accessed in over 60 days",
        "framework": "GDPR",
        "severity": "LOW",
        "remediation": "Review and disable stale accounts per data minimisation policy.",
        "condition": [
            {"field": "last_login_days", "operator": ">", "value": 60},
        ],
    },
]


def seed():
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.name == DEFAULT_ORG_NAME).first()
        if org is None:
            print(
                f"Organisation {DEFAULT_ORG_NAME!r} not found. "
                f"Run `python -m backend.seed_users` first."
            )
            return

        created = []
        for spec in BASELINE_RULES:
            exists = db.query(Rule).filter(
                Rule.name == spec["name"],
                Rule.organization_id == org.id,
            ).first()
            if exists:
                continue

            db.add(Rule(
                name=spec["name"],
                organization_id=org.id,
                description=spec["description"],
                framework=spec["framework"],
                severity=spec["severity"],
                remediation=spec["remediation"],
                condition=json.dumps(spec["condition"]),
                active=True,
                version=1,
                is_current=True,
            ))
            created.append(spec["name"])

        db.commit()

        if created:
            print(f"Seeded {len(created)} rule(s) for {DEFAULT_ORG_NAME}: " + ", ".join(created))
        else:
            print("Rules already exist, nothing to seed.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()