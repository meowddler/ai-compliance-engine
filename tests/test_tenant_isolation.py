"""Tenant isolation tests.

Proves the core multi-tenancy guarantee: a user in one organization can never
see another organization's data. These tests hit the real API with two separate
orgs and assert the data never crosses the boundary.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import SessionLocal
from backend.models.models import Organization, User, Scan, Violation, Rule
from backend.core.auth import hash_password

client = TestClient(app)


@pytest.fixture
def two_orgs():
    """Create two orgs, each with one admin user and one scan+violation."""
    db = SessionLocal()

    org_a = Organization(name="Org A Test")
    org_b = Organization(name="Org B Test")
    db.add_all([org_a, org_b])
    db.commit()
    db.refresh(org_a)
    db.refresh(org_b)

    user_a = User(username="admin_a_test", hashed_password=hash_password("pw_a"),
                  role="Admin", organization_id=org_a.id)
    user_b = User(username="admin_b_test", hashed_password=hash_password("pw_b"),
                  role="Admin", organization_id=org_b.id)
    db.add_all([user_a, user_b])
    db.commit()

    # Org A gets a scan + violation; Org B gets nothing.
    scan_a = Scan(filename="org_a_scan.csv", rows_scanned=1, organization_id=org_a.id)
    db.add(scan_a)
    db.flush()
    db.add(Violation(scan_id=scan_a.id, organization_id=org_a.id,
                     server_id="srv-a", rule_name="test", severity="HIGH",
                     status="FAIL", message="org A only"))
    db.add(Rule(name="rule_a_test", organization_id=org_a.id, description="d",
                framework="f", severity="HIGH", remediation="r", condition="[]"))
    db.commit()
    db.close()

    yield

    # cleanup
    db = SessionLocal()
    db.query(Violation).filter(Violation.server_id == "srv-a").delete()
    db.query(Scan).filter(Scan.filename == "org_a_scan.csv").delete()
    db.query(Rule).filter(Rule.name == "rule_a_test").delete()
    db.query(User).filter(User.username.in_(["admin_a_test", "admin_b_test"])).delete()
    db.query(Organization).filter(Organization.name.in_(["Org A Test", "Org B Test"])).delete()
    db.commit()
    db.close()


def _token(username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_org_b_cannot_see_org_a_scans(two_orgs):
    token_b = _token("admin_b_test", "pw_b")
    r = client.get("/scans", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 200
    filenames = [s["filename"] for s in r.json()]
    assert "org_a_scan.csv" not in filenames   # B must not see A's scan


def test_org_b_cannot_see_org_a_violations(two_orgs):
    token_b = _token("admin_b_test", "pw_b")
    r = client.get("/violations", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 200
    servers = [v["server_id"] for v in r.json()]
    assert "srv-a" not in servers   # B must not see A's violation


def test_org_b_cannot_see_org_a_rules(two_orgs):
    token_b = _token("admin_b_test", "pw_b")
    r = client.get("/rules", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 200
    names = [rule["name"] for rule in r.json()]
    assert "rule_a_test" not in names   # B must not see A's rule


def test_org_a_CAN_see_its_own_data(two_orgs):
    token_a = _token("admin_a_test", "pw_a")
    r = client.get("/scans", headers={"Authorization": f"Bearer {token_a}"})
    filenames = [s["filename"] for s in r.json()]
    assert "org_a_scan.csv" in filenames   # A sees its own scan

    r = client.get("/violations", headers={"Authorization": f"Bearer {token_a}"})
    servers = [v["server_id"] for v in r.json()]
    assert "srv-a" in servers


def test_org_b_dashboard_excludes_org_a(two_orgs):
    token_b = _token("admin_b_test", "pw_b")
    r = client.get("/dashboard/summary", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 200
    # Org B has no scans of its own, so its dashboard total must not count A's.
    data = r.json()
    b_servers = [v["server_id"] for v in data["recent_violations"]]
    assert "srv-a" not in b_servers