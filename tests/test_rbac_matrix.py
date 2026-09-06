"""RBAC matrix and endpoint coverage.

Calls every endpoint as every role. Two purposes:

  * Proves the capability model is enforced server-side rather than only in the
    UI — an endpoint that checks nothing is invisible until someone finds it.
  * Exercises route code that no other test reaches.

The expectation for each endpoint is stated explicitly rather than derived, so a
permission change that widens access fails a test instead of passing silently.
"""
import io

import pytest
from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)

ROLES = {
    "admin": "admin123",
    "auditor1": "auditor123",
    "analyst1": "analyst123",
}


def token_for(username):
    r = client.post("/auth/login", data={"username": username, "password": ROLES[username]})
    if r.status_code != 200:
        return None
    return r.json()["access_token"]


def headers_for(username):
    tok = token_for(username)
    return {"Authorization": f"Bearer {tok}"} if tok else None


# (method, path, {role: allowed}) — allowed means "not 401/403", not "200".
# A 404 or 422 still proves authorisation passed and the handler ran.
MATRIX = [
    ("GET", "/", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/version", {"admin": True, "auditor1": True, "analyst1": True}),

    ("GET", "/violations", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/scans", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/rules", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/frameworks", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/dashboard/summary", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/dashboard/posture-history", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/dashboard/changes", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/auth/sessions", {"admin": True, "auditor1": True, "analyst1": True}),
    ("GET", "/auth/mfa/status", {"admin": True, "auditor1": True, "analyst1": True}),

    # Audit surface: privileged. An analyst reading the audit trail would see
    # every action taken by everyone in the organisation.
    ("GET", "/audit-log", {"admin": True, "auditor1": True, "analyst1": False}),
    ("GET", "/audit/verify", {"admin": True, "auditor1": True, "analyst1": False}),
    ("GET", "/metrics", {"admin": True, "auditor1": True, "analyst1": False}),
    ("GET", "/security/encryption-status", {"admin": True, "auditor1": True, "analyst1": False}),
    ("GET", "/governance/retention", {"admin": True, "auditor1": True, "analyst1": False}),
    ("GET", "/admin/impersonation-log", {"admin": True, "auditor1": True, "analyst1": False}),
    ("GET", "/admin/scheduler", {"admin": True, "auditor1": True, "analyst1": False}),

    # Organisation and user management: administrators only.
    ("GET", "/admin/organizations", {"admin": True, "auditor1": False, "analyst1": False}),
    ("GET", "/admin/users", {"admin": True, "auditor1": False, "analyst1": False}),
    ("GET", "/admin/usage", {"admin": True, "auditor1": False, "analyst1": False}),
]


@pytest.mark.parametrize("method,path,expectations", MATRIX)
def test_rbac_matrix(method, path, expectations):
    for role, allowed in expectations.items():
        headers = headers_for(role)
        if headers is None:
            continue                                # role not seeded
        response = client.request(method, path, headers=headers)
        denied = response.status_code in (401, 403)
        assert denied != allowed, (
            f"{role} on {method} {path}: expected "
            f"{'access' if allowed else 'denial'}, got {response.status_code}"
        )


def test_every_endpoint_rejects_anonymous_access():
    """Only the entry points may be reachable without credentials."""
    # FastAPI's own documentation routes are public by design.
    public = {"/", "/version", "/auth/login", "/auth/refresh","/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc"}

    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}
        if not methods or path in public or "{" in path or not path.startswith("/"):
            continue
        if path.startswith(("/redoc", "/static")):
            continue
        for method in methods:
            r = client.request(method, path)
            assert r.status_code in (401, 403, 405, 422), (
                f"{method} {path} returned {r.status_code} without authentication")


# --- Exercise the write paths ---------------------------------------------

def test_scan_upload_and_downstream_reads():
    """The upload pipeline is the largest untested block: parsing, evaluation,
    anomaly scoring, evidence hashing, and persistence in one request."""
    headers = headers_for("admin")
    csv = (
        "server_id,port,port_exposed,mfa_enabled,last_login_days,failed_logins\n"
        "rbac-srv-1,22,true,false,3,1\n"
        "rbac-srv-2,443,false,true,45,0\n"
        "rbac-srv-3,3389,true,false,90,12\n"
    )
    r = client.post("/upload-logs", headers=headers,
                    files={"file": ("rbac_test.csv", io.BytesIO(csv.encode()), "text/csv")})
    assert r.status_code == 200, r.text
    body = r.json()
    scan_id = body["scan_id"]
    assert body["rows_scanned"] == 3
    assert "anomaly_detection" in body

    # Evidence was recorded and can be verified.
    ev = client.get(f"/scans/{scan_id}/evidence", headers=headers).json()
    assert ev and ev["sha256"]
    verify = client.get(f"/evidence/{ev['id']}/verify", headers=headers).json()
    assert verify["status"] == "INTACT"

    # Findings from this scan carry provenance and full traceability.
    violations = client.get("/violations?page_size=200", headers=headers).json()["items"]
    mine = [v for v in violations if v["scan_id"] == scan_id]
    assert mine, "the scan produced no findings"

    vid = mine[0]["id"]
    prov = client.get(f"/violations/{vid}/provenance", headers=headers).json()
    assert prov["reproducible"] is True

    trace = client.get(f"/violations/{vid}/traceability", headers=headers).json()
    assert len(trace["questions"]) == 11

    hist = client.get(f"/violations/{vid}/history", headers=headers).json()
    assert "current_lifecycle" in hist


def test_upload_rejects_malformed_input():
    headers = headers_for("admin")

    empty = client.post("/upload-logs", headers=headers,
                        files={"file": ("e.csv", io.BytesIO(b""), "text/csv")})
    assert empty.status_code == 400

    no_id = client.post("/upload-logs", headers=headers,
                        files={"file": ("n.csv", io.BytesIO(b"port,mfa\n22,true\n"), "text/csv")})
    assert no_id.status_code == 400


def test_rule_lifecycle_end_to_end():
    """Create, edit (creating a version), then delete or retire."""
    headers = headers_for("admin")

    created = client.post("/rules", headers=headers, json={
        "name": "rbac_matrix_temp_rule", "description": "temporary",
        "framework": "TEST", "severity": "LOW", "remediation": "n/a",
        "condition": [{"field": "port", "operator": "==", "value": 9999}],
    })
    assert created.status_code == 200, created.text

    # Read the id back from the rules list rather than the create response:
    # the endpoint returns the ORM object, whose serialised shape is not part
    # of any contract this test should depend on.
    def find_rule(name, version=None):
        rules = client.get("/rules?page_size=200", headers=headers).json()
        rules = rules["items"] if isinstance(rules, dict) else rules
        for r in rules:
            if r["name"] == name and (version is None or r.get("version") == version):
                return r
        return None

    original = find_rule("rbac_matrix_temp_rule")
    assert original is not None, "created rule did not appear in the list"

    updated = client.put(f"/rules/{original['id']}", headers=headers,
                         json={"severity": "MEDIUM"})
    assert updated.status_code == 200

    # An edit creates a new version rather than mutating the original.
    v2 = find_rule("rbac_matrix_temp_rule", version=2)
    assert v2 is not None, "editing did not produce a version 2"

    removed = client.delete(f"/rules/{v2['id']}", headers=headers)
    assert removed.status_code == 200
    assert removed.json()["action"] in ("deleted", "retired")


def test_report_generation_produces_a_pdf():
    r = client.post("/reports/generate", headers=headers_for("admin"))
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"


def test_finding_lifecycle_transition_and_rejection():
    headers = headers_for("admin")
    violations = client.get("/violations?page_size=50", headers=headers).json()["items"]
    target = next((v for v in violations if v.get("lifecycle") == "OPEN"), None)
    if not target:
        pytest.skip("no OPEN finding available")

    ok = client.post(f"/violations/{target['id']}/lifecycle", headers=headers,
                     json={"to_state": "ACKNOWLEDGED", "note": "rbac matrix test"})
    assert ok.status_code == 200

    # Skipping remediation and verification must be refused.
    bad = client.post(f"/violations/{target['id']}/lifecycle", headers=headers,
                      json={"to_state": "CLOSED"})
    assert bad.status_code == 400


def test_staleness_maintenance_dry_run():
    r = client.post("/maintenance/refresh-staleness?dry_run=true",
                    headers=headers_for("admin"))
    assert r.status_code == 200
    assert r.json()["dry_run"] is True


def test_audit_checkpoint_can_be_created():
    r = client.post("/audit/checkpoint", headers=headers_for("admin"))
    assert r.status_code in (200, 409)      # 409 if the chain is already broken