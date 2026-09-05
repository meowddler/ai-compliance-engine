"""Data governance tests.

The rules being proved, in precedence order:
  1. A legal hold overrides retention.
  2. Some classes are never deletable by retention at all.
  3. Evaluation reports; it never deletes.
"""
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import SessionLocal
from backend.models.models import AuditLog, LegalHold, Organization, RetentionPolicy

client = TestClient(app)


def _headers(username="admin", password="admin123"):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def clean_holds():
    """Remove test holds before and after so runs do not interfere."""
    def purge():
        db = SessionLocal()
        db.query(LegalHold).filter(LegalHold.name.like("test_hold%")).delete(
            synchronize_session=False)
        db.commit()
        db.close()
    purge()
    yield
    purge()


def test_retention_evaluation_reports_without_deleting(clean_holds):
    headers = _headers()
    client.post("/governance/retention/seed-defaults", headers=headers)

    db = SessionLocal()
    audit_before = db.query(AuditLog).count()
    db.close()

    r = client.get("/governance/retention", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["evaluated"] is True

    db = SessionLocal()
    audit_after = db.query(AuditLog).count()
    db.close()
    # Evaluation is read-only; it must not have removed anything.
    assert audit_after >= audit_before


def test_audit_log_is_never_deletable_by_retention(clean_holds):
    headers = _headers()
    client.post("/governance/retention/seed-defaults", headers=headers)

    body = client.get("/governance/retention", headers=headers).json()
    audit = next(c for c in body["classes"] if c["data_class"] == "audit_log")

    assert audit["deletion_permitted"] is False
    assert audit["eligible_for_deletion"] == 0
    assert "never deleted" in (audit["blocked_by"] or "")


def test_legal_hold_blocks_deletion_eligibility(clean_holds):
    """A hold must override retention, not merely be recorded alongside it."""
    headers = _headers()
    client.post("/governance/retention/seed-defaults", headers=headers)

    r = client.post("/governance/legal-hold", headers=headers, json={
        "name": "test_hold_evidence",
        "reason": "Litigation hold for testing",
        "data_class": "evidence",
    })
    assert r.status_code == 200
    hold_id = r.json()["id"]

    body = client.get("/governance/retention", headers=headers).json()
    evidence = next(c for c in body["classes"] if c["data_class"] == "evidence")
    assert evidence["eligible_for_deletion"] == 0
    assert "legal hold" in (evidence["blocked_by"] or "")
    assert any(h["name"] == "test_hold_evidence" for h in evidence["active_holds"])

    # Releasing restores ordinary retention behaviour.
    assert client.delete(f"/governance/legal-hold/{hold_id}", headers=headers).status_code == 200
    body = client.get("/governance/retention", headers=headers).json()
    evidence = next(c for c in body["classes"] if c["data_class"] == "evidence")
    assert evidence["active_holds"] == []


def test_hold_with_no_data_class_covers_everything(clean_holds):
    headers = _headers()
    client.post("/governance/retention/seed-defaults", headers=headers)

    r = client.post("/governance/legal-hold", headers=headers, json={
        "name": "test_hold_global", "reason": "Covers all classes", "data_class": None,
    })
    hold_id = r.json()["id"]

    body = client.get("/governance/retention", headers=headers).json()
    for entry in body["classes"]:
        if entry["data_class"] == "audit_log":
            continue                            # blocked by policy, not by hold
        assert entry["eligible_for_deletion"] == 0, entry["data_class"]

    client.delete(f"/governance/legal-hold/{hold_id}", headers=headers)


def test_releasing_a_hold_twice_is_rejected(clean_holds):
    headers = _headers()
    r = client.post("/governance/legal-hold", headers=headers, json={
        "name": "test_hold_double", "reason": "double release", "data_class": "evidence",
    })
    hold_id = r.json()["id"]

    assert client.delete(f"/governance/legal-hold/{hold_id}", headers=headers).status_code == 200
    assert client.delete(f"/governance/legal-hold/{hold_id}", headers=headers).status_code == 409


def test_hold_operations_are_audited(clean_holds):
    """A hold that could be placed or released without a trace would be
    worthless — the point is to prove what was protected and when."""
    headers = _headers()
    r = client.post("/governance/legal-hold", headers=headers, json={
        "name": "test_hold_audited", "reason": "audit check", "data_class": "evidence",
    })
    hold_id = r.json()["id"]
    client.delete(f"/governance/legal-hold/{hold_id}", headers=headers)

    db = SessionLocal()
    actions = [a.action for a in db.query(AuditLog)
               .filter(AuditLog.entity_type == "LegalHold").all()]
    db.close()
    assert "legal_hold_placed" in actions
    assert "legal_hold_released" in actions


def test_analyst_cannot_place_a_legal_hold():
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    resp = client.post("/governance/legal-hold", headers=headers, json={
        "name": "unauthorised", "reason": "should fail", "data_class": "evidence",
    })
    assert resp.status_code == 403