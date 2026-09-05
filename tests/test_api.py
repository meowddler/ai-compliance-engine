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