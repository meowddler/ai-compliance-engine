"""MFA tests.

Covers what is implemented. Enforcement at login is deliberately absent, and
one test asserts that the API says so rather than implying protection that
does not exist.
"""
import json

import pyotp
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.core.mfa import (
    consume_recovery_code, generate_recovery_codes, generate_secret, verify_code,
)
from backend.database import SessionLocal
from backend.models.models import User

client = TestClient(app)


def _headers():
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def mfa_cleared():
    """Ensure admin starts and ends without MFA so runs do not interfere."""
    def clear():
        db = SessionLocal()
        u = db.query(User).filter(User.username == "admin").first()
        if u:
            u.mfa_enabled = False
            u.mfa_secret_encrypted = None
            u.mfa_recovery_codes = None
            u.mfa_enrolled_at = None
            db.commit()
        db.close()
    clear()
    yield
    clear()


# --- Unit level -----------------------------------------------------------

def test_valid_code_verifies_and_wrong_code_does_not():
    secret = generate_secret()
    assert verify_code(secret, pyotp.TOTP(secret).now()) is True
    assert verify_code(secret, "000000") is False


def test_malformed_codes_are_rejected_not_crashed():
    """A malformed submission is a failed attempt, not a server error."""
    secret = generate_secret()
    for bad in ("", "abc", "12345678901234", None):
        assert verify_code(secret, bad) is False


def test_code_from_a_different_secret_is_rejected():
    a, b = generate_secret(), generate_secret()
    assert verify_code(a, pyotp.TOTP(b).now()) is False


def test_recovery_codes_are_stored_hashed_not_plaintext():
    """A database read must not yield a usable second factor."""
    codes, stored = generate_recovery_codes()
    for code in codes:
        assert code not in stored


def test_recovery_code_is_single_use():
    """A reusable recovery code would be a permanent bypass of the factor."""
    codes, stored = generate_recovery_codes()
    first = codes[0]

    ok, remaining = consume_recovery_code(stored, first)
    assert ok is True
    assert len(json.loads(remaining)) == len(codes) - 1

    ok_again, _ = consume_recovery_code(remaining, first)
    assert ok_again is False


def test_unknown_recovery_code_is_rejected_without_consuming_others():
    codes, stored = generate_recovery_codes()
    ok, remaining = consume_recovery_code(stored, "ffff-ffff-ffff")
    assert ok is False
    assert len(json.loads(remaining)) == len(codes)


# --- API level ------------------------------------------------------------

def test_full_enrolment_flow(mfa_cleared):
    headers = _headers()

    r = client.post("/auth/mfa/enroll", headers=headers)
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert r.json()["provisioning_uri"].startswith("otpauth://")

    # Not enabled until a code is verified — otherwise a user who never scanned
    # the QR code would be locked out.
    assert client.get("/auth/mfa/status", headers=headers).json()["mfa_enabled"] is False

    r = client.post("/auth/mfa/verify", headers=headers,
                    json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    assert r.json()["mfa_enabled"] is True
    assert len(r.json()["recovery_codes"]) == 10

    assert client.get("/auth/mfa/status", headers=headers).json()["mfa_enabled"] is True


def test_enrolment_rejects_a_wrong_code(mfa_cleared):
    headers = _headers()
    client.post("/auth/mfa/enroll", headers=headers)

    r = client.post("/auth/mfa/verify", headers=headers, json={"code": "000000"})
    assert r.status_code == 400
    assert client.get("/auth/mfa/status", headers=headers).json()["mfa_enabled"] is False


def test_disable_requires_a_valid_code(mfa_cleared):
    """Stripping the second factor without proof of possession would make it
    decorative — a stolen session could simply remove it."""
    headers = _headers()
    secret = client.post("/auth/mfa/enroll", headers=headers).json()["secret"]
    client.post("/auth/mfa/verify", headers=headers, json={"code": pyotp.TOTP(secret).now()})

    assert client.post("/auth/mfa/disable", headers=headers,
                       json={"code": "000000"}).status_code == 400
    assert client.get("/auth/mfa/status", headers=headers).json()["mfa_enabled"] is True

    assert client.post("/auth/mfa/disable", headers=headers,
                       json={"code": pyotp.TOTP(secret).now()}).status_code == 200
    assert client.get("/auth/mfa/status", headers=headers).json()["mfa_enabled"] is False


def test_recovery_code_can_disable_mfa(mfa_cleared):
    headers = _headers()
    secret = client.post("/auth/mfa/enroll", headers=headers).json()["secret"]
    codes = client.post("/auth/mfa/verify", headers=headers,
                        json={"code": pyotp.TOTP(secret).now()}).json()["recovery_codes"]

    assert client.post("/auth/mfa/disable", headers=headers,
                       json={"code": codes[0]}).status_code == 200


def test_status_declares_that_enforcement_is_absent():
    """The API must not imply protection it does not provide."""
    body = client.get("/auth/mfa/status", headers=_headers()).json()
    assert body["enforced_at_login"] is False
    assert "not implemented" in body["limitation"]