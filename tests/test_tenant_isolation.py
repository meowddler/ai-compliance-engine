"""Tenant isolation tests.

Proves the core multi-tenancy guarantee: a user in one organization can never
see another organization's data. These tests hit the real API with two separate
orgs and assert the data never crosses the boundary.
"""
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.core.auth import hash_password
from backend.database import SessionLocal
from backend.models.models import (
    AIInteraction, AuditLog, Organization, RefreshToken, Rule, Scan, User, Violation,
)

client = TestClient(app)

ORG_NAMES = ["Org A Test", "Org B Test"]
USER_NAMES = ["admin_a_test", "admin_b_test"]


def _purge_test_orgs(db):
    """Remove the fixture's orgs and everything referencing them.

    Order matters: children before parents. Logging in now writes an audit
    entry AND a refresh token, so both reference the org or its users. A
    teardown that misses one fails on a foreign key, leaves the org behind, and
    breaks every subsequent test with a duplicate-name error — which is exactly
    what happened when refresh tokens were introduced.
    """
    orgs = db.query(Organization).filter(Organization.name.in_(ORG_NAMES)).all()
    for org in orgs:
        user_ids = [u.id for u in db.query(User).filter(User.organization_id == org.id).all()]
        if user_ids:
            db.query(RefreshToken).filter(
                RefreshToken.user_id.in_(user_ids)).delete(synchronize_session=False)
        for model in (AuditLog, AIInteraction, Violation, Rule, Scan, User):
            db.query(model).filter(
                model.organization_id == org.id).delete(synchronize_session=False)
        db.delete(org)
    db.commit()


@pytest.fixture
def two_orgs():
    """Two orgs; A holds data, B holds none."""
    db = SessionLocal()

    # Clear any residue from a previous failed run so the fixture is
    # self-healing rather than permanently poisoned by one bad teardown.
    _purge_test_orgs(db)

    org_a = Organization(name="Org A Test")
    org_b = Organization(name="Org B Test")
    db.add_all([org_a, org_b])
    db.commit()
    db.refresh(org_a)
    db.refresh(org_b)

    db.add_all([
        User(username="admin_a_test", hashed_password=hash_password("pw_a"),
             role="Admin", organization_id=org_a.id, is_active=True),
        User(username="admin_b_test", hashed_password=hash_password("pw_b"),
             role="Admin", organization_id=org_b.id, is_active=True),
    ])
    db.commit()

    scan_a = Scan(filename="org_a_scan.csv", rows_scanned=1, organization_id=org_a.id)
    db.add(scan_a)
    db.flush()
    db.add(Violation(scan_id=scan_a.id, organization_id=org_a.id,
                     server_id="srv-a", rule_name="test", severity="HIGH",
                     status="FAIL", message="org A only"))
    db.add(Rule(name="rule_a_test", organization_id=org_a.id, description="d",
                framework="f", severity="HIGH", remediation="r",
                condition='[{"field": "x", "operator": "==", "value": 1}]',
                version=1, is_current=True, active=True))
    db.commit()
    db.close()

    yield

    db = SessionLocal()
    _purge_test_orgs(db)
    db.close()


def _token(username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _headers(username, password):
    return {"Authorization": f"Bearer {_token(username, password)}"}


def test_org_b_cannot_see_org_a_scans(two_orgs):
    r = client.get("/scans", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    assert "org_a_scan.csv" not in [s["filename"] for s in r.json()]


def test_org_b_cannot_see_org_a_violations(two_orgs):
    r = client.get("/violations", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    assert "srv-a" not in [v["server_id"] for v in r.json()]


def test_org_b_cannot_see_org_a_rules(two_orgs):
    r = client.get("/rules", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    assert "rule_a_test" not in [rule["name"] for rule in r.json()]


def test_org_a_CAN_see_its_own_data(two_orgs):
    headers = _headers("admin_a_test", "pw_a")

    r = client.get("/scans", headers=headers)
    assert "org_a_scan.csv" in [s["filename"] for s in r.json()]

    r = client.get("/violations", headers=headers)
    assert "srv-a" in [v["server_id"] for v in r.json()]


def test_org_b_dashboard_excludes_org_a(two_orgs):
    r = client.get("/dashboard/summary", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    assert "srv-a" not in [v["server_id"] for v in r.json()["recent_violations"]]


def test_org_b_cannot_read_org_a_audit_log(two_orgs):
    """An auditor must not see another organisation's activity — the audit log
    is the most sensitive thing to leak, since it names actions and actors."""
    # Org A logs in, producing an audit entry attributed to Org A.
    _token("admin_a_test", "pw_a")

    r = client.get("/audit-log", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    assert "admin_a_test" not in [e["username"] for e in r.json()]


def test_org_b_cannot_verify_org_a_audit_chain(two_orgs):
    """Chain verification must be scoped: B's result must reflect B's chain."""
    _token("admin_a_test", "pw_a")

    r = client.get("/audit/verify", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_sessions_are_not_shared_between_users(two_orgs):
    """One user's session list must never include another's."""
    _token("admin_a_test", "pw_a")

    r = client.get("/auth/sessions", headers=_headers("admin_b_test", "pw_b"))
    assert r.status_code == 200
    # B logged in once for this request; A's sessions must not appear.
    assert len(r.json()) <= 1