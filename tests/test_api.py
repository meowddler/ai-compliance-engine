from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Compliance engine is alive"}


def test_login_fails_with_bad_credentials():
    response = client.post("/auth/login", data={"username": "nope", "password": "wrong"})
    assert response.status_code == 401  # failed login must be 401, not a 200 with an error field
    assert "access_token" not in response.json()

def test_upload_logs_requires_auth():
    response = client.post("/upload-logs")
    assert response.status_code in (401, 422)  # 422 if no file attached, 401 if auth checked first


def test_rules_creation_requires_auth():
    response = client.post("/rules", json={
        "name": "test_rule",
        "description": "test",
        "framework": "TEST",
        "severity": "LOW",
        "remediation": "test",
        "condition": []
    })
    assert response.status_code == 401



def _admin_token():
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    return r.json()["access_token"]


def _auth():
    return {"Authorization": f"Bearer {_admin_token()}"}


def test_audit_chain_verifies():
    """The chain must verify cleanly under normal operation."""
    r = client.get("/audit/verify", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True, body
    # Coverage is reported honestly, not hidden.
    assert "unchained_legacy_entries" in body


def test_audit_verify_requires_privileged_role():
    """Audit integrity is not readable by an ordinary analyst."""
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return                                  # analyst not seeded in this environment
    token = r.json()["access_token"]
    resp = client.get("/audit/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_audit_endpoints_reject_anonymous():
    for path in ("/audit/verify", "/audit-log"):
        assert client.get(path).status_code == 401


def test_traceability_returns_all_eleven_questions():
    """All eleven questions must be present, answered or explicitly not."""
    headers = _auth()
    violations = client.get("/violations", headers=headers).json()
    if not violations:
        return                                  # nothing scanned in this environment
    vid = violations[0]["id"]

    r = client.get(f"/violations/{vid}/traceability", headers=headers)
    assert r.status_code == 200
    questions = r.json()["questions"]
    assert len(questions) == 11, f"expected 11 questions, got {len(questions)}"
    for key, answer in questions.items():
        # Every question must report whether it could be answered — an absent
        # answer is a valid result, a missing question is not.
        assert "answered" in answer and "value" in answer, key


def test_traceability_is_tenant_scoped():
    """A finding from another organisation must not be traceable."""
    r = client.get("/violations/999999/traceability", headers=_auth())
    assert r.status_code == 404




# --- Capability model and separation of duties ----------------------------

def test_admin_cannot_approve_controls_or_accept_risk():
    """Separation of duties: whoever creates controls must not also approve them.

    Enforced in the capability set, not left to process documentation — an
    administrator who could do both would make independent review impossible.
    """
    from backend.core.permissions import Capability, capabilities_for

    admin = capabilities_for("Admin")
    assert Capability.CONTROLS_CREATE in admin
    assert Capability.CONTROLS_APPROVE not in admin
    assert Capability.RISK_ACCEPT not in admin


def test_auditor_can_approve_but_not_create_controls():
    """The approver must not be able to author what they approve."""
    from backend.core.permissions import Capability, capabilities_for

    auditor = capabilities_for("Auditor")
    assert Capability.CONTROLS_APPROVE in auditor
    assert Capability.RISK_ACCEPT in auditor
    assert Capability.CONTROLS_CREATE not in auditor


def test_analyst_has_no_privileged_capabilities():
    from backend.core.permissions import Capability, capabilities_for

    analyst = capabilities_for("Analyst")
    for forbidden in (Capability.CONTROLS_CREATE, Capability.CONTROLS_APPROVE,
                      Capability.CONTROLS_DELETE, Capability.RISK_ACCEPT,
                      Capability.AUDIT_READ, Capability.AUDIT_VERIFY,
                      Capability.USER_MANAGE, Capability.DATA_DELETE):
        assert forbidden not in analyst, forbidden
    assert Capability.EVIDENCE_INGEST in analyst      # can still do its job


def test_unknown_role_gets_no_capabilities():
    """A typo or injected role must grant nothing, not everything."""
    from backend.core.permissions import capabilities_for
    assert capabilities_for("SuperAdmin") == set()
    assert capabilities_for("") == set()
    assert capabilities_for(None) == set()


def test_self_approval_is_rejected():
    from backend.core.permissions import SeparationOfDutiesError, assert_not_self_approval
    import pytest as _pytest

    with _pytest.raises(SeparationOfDutiesError):
        assert_not_self_approval("amy", "amy", "control")

    # Different people is fine.
    assert_not_self_approval("amy", "ben", "control")


def test_analyst_cannot_create_a_rule_over_the_api():
    """The capability model must be enforced server-side, not just in the UI."""
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return
    token = r.json()["access_token"]
    resp = client.post("/rules", headers={"Authorization": f"Bearer {token}"}, json={
        "name": "analyst_should_not_create",
        "description": "test", "framework": "TEST", "severity": "LOW",
        "remediation": "n/a",
        "condition": [{"field": "port", "operator": "==", "value": 22}],
    })
    assert resp.status_code == 403




# --- Token lifecycle security --------------------------------------------

def test_refresh_token_rotates_on_use():
    """A used refresh token must not remain valid — otherwise a stolen copy
    works forever."""
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    first = r.json()["refresh_token"]

    r2 = client.post("/auth/refresh", json={"refresh_token": first})
    assert r2.status_code == 200
    second = r2.json()["refresh_token"]
    assert second != first

    # The old one is now dead.
    r3 = client.post("/auth/refresh", json={"refresh_token": first})
    assert r3.status_code == 401


def test_refresh_token_replay_revokes_the_whole_family():
    """Replaying a rotated token means it was stolen. Revoking only that token
    would leave the thief's newer one working, so the family goes."""
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    original = r.json()["refresh_token"]

    rotated = client.post("/auth/refresh", json={"refresh_token": original}).json()["refresh_token"]

    # Replay the original: detected as theft.
    assert client.post("/auth/refresh", json={"refresh_token": original}).status_code == 401

    # The descendant is revoked too, not just the replayed token.
    assert client.post("/auth/refresh", json={"refresh_token": rotated}).status_code == 401


def test_malformed_and_forged_tokens_are_rejected():
    for bad in ("", "garbage", "a.b.c", "Bearer nonsense"):
        r = client.get("/violations", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401, bad


def test_token_signed_with_wrong_key_is_rejected():
    """Signature verification must actually verify."""
    from jose import jwt
    from datetime import datetime, timedelta, timezone

    forged = jwt.encode(
        {"sub": "admin", "role": "Admin", "org": 1,
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        "not-the-real-signing-key-not-the-real-signing-key",
        algorithm="HS256",
    )
    assert client.get("/violations", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_alg_none_token_is_rejected():
    """The classic algorithm-confusion attack: an unsigned token claiming to be
    valid. Accepting it would make every signature meaningless."""
    import base64, json as _json

    def b64(d):
        return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()

    unsigned = f'{b64({"alg": "none", "typ": "JWT"})}.{b64({"sub": "admin", "role": "Admin"})}.'
    assert client.get("/violations", headers={"Authorization": f"Bearer {unsigned}"}).status_code == 401


def test_expired_token_is_rejected():
    from jose import jwt
    from datetime import datetime, timedelta, timezone
    from backend.config import SECRET_KEY, ALGORITHM

    expired = jwt.encode(
        {"sub": "admin", "role": "Admin", "org": 1,
         "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
        SECRET_KEY, algorithm=ALGORITHM,
    )
    assert client.get("/violations", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_token_role_claim_cannot_escalate_privileges():
    """Authorisation reads the role from the DATABASE. A token claiming a role
    the account does not have must grant nothing."""
    from jose import jwt
    from datetime import datetime, timedelta, timezone
    from backend.config import SECRET_KEY, ALGORITHM

    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return

    # Correctly signed, but claims Admin for an Analyst account.
    escalated = jwt.encode(
        {"sub": "analyst1", "role": "Admin", "org": 1,
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        SECRET_KEY, algorithm=ALGORITHM,
    )
    resp = client.post("/rules", headers={"Authorization": f"Bearer {escalated}"}, json={
        "name": "escalation_attempt", "description": "d", "framework": "TEST",
        "severity": "LOW", "remediation": "n/a",
        "condition": [{"field": "port", "operator": "==", "value": 22}],
    })
    assert resp.status_code == 403


def test_logout_revokes_all_refresh_tokens():
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    refresh = r.json()["refresh_token"]
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    assert client.post("/auth/logout", headers=headers).status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": refresh}).status_code == 401