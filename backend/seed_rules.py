import json
from backend.database import SessionLocal
from backend.models.models import Rule


def seed():
    db = SessionLocal()
    if db.query(Rule).count() > 0:
        print("Rules already exist, skipping.")
        db.close()
        return

    rules = [
        Rule(
            name="exposed_port_no_mfa",
            description="Port is exposed to the network and MFA is not enabled",
            framework="ISO 27001",
            severity="HIGH",
            remediation="Enable MFA or restrict network exposure for this port.",
            condition=json.dumps([
                {"field": "port_exposed", "operator": "==", "value": True},
                {"field": "mfa_enabled", "operator": "==", "value": False}
            ]),
            active=True
        ),
        Rule(
            name="risky_port_open",
            description="High-risk port (SSH/RDP) is exposed",
            framework="PCI DSS",
            severity="HIGH",
            remediation="Restrict SSH/RDP access to trusted IPs or VPN only.",
            condition=json.dumps([
                {"field": "port_exposed", "operator": "==", "value": True},
                {"field": "port", "operator": "in", "value": [22, 3389]}
            ]),
            active=True
        ),
        Rule(
            name="excessive_failed_logins",
            description="Unusually high number of failed login attempts (possible brute force)",
            framework="SOC 2",
            severity="MEDIUM",
            remediation="Investigate for brute-force activity and enforce lockout policies.",
            condition=json.dumps([{"field": "failed_logins", "operator": ">", "value": 5}]),
            active=True
        ),
        Rule(
            name="stale_account",
            description="Account has not been accessed in over 60 days",
            framework="GDPR",
            severity="LOW",
            remediation="Review and disable stale accounts per data minimization policy.",
            condition=json.dumps([{"field": "last_login_days", "operator": ">", "value": 60}]),
            active=True
        ),
    ]

    db.add_all(rules)
    db.commit()
    db.close()
    print(f"Seeded {len(rules)} rules.")


if __name__ == "__main__":
    seed()