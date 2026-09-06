"""Admin tooling tests.

Impersonation gets the most attention here. It is deliberate privilege
escalation, so what matters is not that it works but that it cannot be used
quietly: a reason is required, sessions are bounded, actions stay attributed to
the real operator, and auditors can review it.
"""
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import SessionLocal
from backend.models.models import ImpersonationSession, User

client = TestClient(app)


def _headers(username="admin", password="admin123"):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def clean_sessions():
    def purge():
        db = SessionLocal()
        db.query(ImpersonationSession).filter(
            ImpersonationSession.reason.like("%test impersonation%")).delete(
            synchronize_session=False)
        db.commit()
        db.close()
    purge()
    yield
    purge()


@pytest.fixture
def reactivate_users():
    """Restore any account a test disables, so the suite stays runnable."""
    yield
    db = SessionLocal()
    for u in db.query(User).filter(User.is_active.is_(False)).all():
        u.is_active = True
    db.commit()
    db.close()


# --- Tenant and user management -------------------------------------------

def test_organization_listing_is_scoped_to_the_caller():
    """A tenant administrator managing every tenant would defeat the isolation
    the rest of the system enforces."""
    body = client.get("/admin/organizations", headers=_headers()).json()
    assert len(body) == 1
    assert "users" in body[0]


def test_user_listing_never_returns_password_hashes():
    body = client.get("/admin/users", headers=_headers()).json()
    assert body
    for user in body:
        assert "hashed_password" not in user
        assert "mfa_secret_encrypted" not in user


def test_cannot_deactivate_your_own_account():
    """Self-deactivation locks the operator out, and if they are the only
    administrator it locks the organisation out permanently."""
    headers = _headers()
    me = next(u for u in client.get("/admin/users", headers=headers).json()
              if u["username"] == "admin")
    r = client.post(f"/admin/users/{me['id']}/deactivate", headers=headers)
    assert r.status_code == 409


def test_deactivation_revokes_sessions(reactivate_users):
    """Leaving a disabled user working until their token expires is not what
    'disabled' means to anyone who asked for it."""
    headers = _headers()
    users = client.get("/admin/users", headers=headers).json()
    target = next((u for u in users if u["username"] == "analyst1"), None)
    if not target:
        pytest.skip("analyst1 not seeded")

    # Give the target a live session first.
    client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})

    r = client.post(f"/admin/users/{target['id']}/deactivate", headers=headers)
    assert r.status_code == 200
    assert r.json()["is_active"] is False
    assert r.json()["sessions_revoked"] >= 1

    # A disabled account cannot log back in.
    assert client.post("/auth/login",
                       data={"username": "analyst1", "password": "analyst123"}
                       ).status_code == 403


def test_admin_endpoints_require_privilege():
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    for path in ("/admin/organizations", "/admin/users", "/admin/usage",
                 "/admin/impersonation-log"):
        assert client.get(path, headers=headers).status_code == 403, path


# --- Usage metering -------------------------------------------------------

def test_usage_reports_units_without_inventing_prices():
    """Attaching a cost model here would be fiction — no invoice reconciliation
    exists."""
    body = client.get("/admin/usage", headers=_headers()).json()
    assert "billable_units" in body
    assert "No pricing" in body["note"]
    for unit in ("scans_run", "evidence_records", "ai_calls", "ai_prompt_tokens"):
        assert unit in body["billable_units"], unit


# --- Impersonation --------------------------------------------------------

def test_impersonation_requires_a_substantive_reason(clean_sessions):
    """A one-word reason is not a reason; the audit entry has to be useful to
    whoever reads it months later."""
    headers = _headers()
    r = client.post("/admin/impersonate", headers=headers, json={
        "target_username": "analyst1", "reason": "debug"})
    assert r.status_code == 400


def test_impersonation_token_records_the_real_actor(clean_sessions):
    """Actions taken during a session must remain attributable to the operator,
    not to the user being impersonated."""
    from backend.core.auth import decode_access_token

    headers = _headers()
    r = client.post("/admin/impersonate", headers=headers, json={
        "target_username": "analyst1",
        "reason": "test impersonation for support investigation",
        "duration_minutes": 15,
    })
    if r.status_code == 404:
        pytest.skip("analyst1 not seeded")
    assert r.status_code == 200

    body = r.json()
    claims = decode_access_token(body["access_token"])
    assert claims["sub"] == "analyst1"          # acting as
    assert claims["act"] == "admin"             # but really this operator
    assert "imp" in claims                      # tied to a session record

    client.post(f"/admin/impersonate/{body['session_id']}/end", headers=headers)


def test_impersonation_duration_is_bounded(clean_sessions):
    """An unbounded session is a standing credential rather than a support tool."""
    headers = _headers()
    r = client.post("/admin/impersonate", headers=headers, json={
        "target_username": "analyst1",
        "reason": "test impersonation with an absurd duration",
        "duration_minutes": 99999,
    })
    if r.status_code == 404:
        pytest.skip("analyst1 not seeded")

    from datetime import datetime, timedelta, timezone
    expires = datetime.fromisoformat(r.json()["expires_at"])
    assert expires <= datetime.now(timezone.utc) + timedelta(minutes=121)

    client.post(f"/admin/impersonate/{r.json()['session_id']}/end", headers=headers)


def test_impersonation_is_visible_to_auditors(clean_sessions):
    """A support feature its own organisation cannot review is a backdoor."""
    headers = _headers()
    r = client.post("/admin/impersonate", headers=headers, json={
        "target_username": "analyst1",
        "reason": "test impersonation appears in the log",
    })
    if r.status_code == 404:
        pytest.skip("analyst1 not seeded")
    session_id = r.json()["session_id"]

    log = client.get("/admin/impersonation-log", headers=headers).json()
    entry = next(e for e in log if e["id"] == session_id)
    assert entry["actor"] == "admin"
    assert entry["target"] == "analyst1"
    assert entry["reason"]
    assert entry["active"] is True

    client.post(f"/admin/impersonate/{session_id}/end", headers=headers)
    log = client.get("/admin/impersonation-log", headers=headers).json()
    assert next(e for e in log if e["id"] == session_id)["active"] is False


def test_cannot_impersonate_yourself(clean_sessions):
    r = client.post("/admin/impersonate", headers=_headers(), json={
        "target_username": "admin",
        "reason": "test impersonation of my own account",
    })
    assert r.status_code == 400


def test_ending_a_session_twice_is_rejected(clean_sessions):
    headers = _headers()
    r = client.post("/admin/impersonate", headers=headers, json={
        "target_username": "analyst1",
        "reason": "test impersonation double end",
    })
    if r.status_code == 404:
        pytest.skip("analyst1 not seeded")
    sid = r.json()["session_id"]

    assert client.post(f"/admin/impersonate/{sid}/end", headers=headers).status_code == 200
    assert client.post(f"/admin/impersonate/{sid}/end", headers=headers).status_code == 409