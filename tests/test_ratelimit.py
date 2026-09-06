"""Rate limiting tests.

The limiter is disabled for the rest of the suite (see conftest.py), so these
tests enable it explicitly and reset its state between cases.
"""
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.core.ratelimit import (
    LIMIT_AI, LIMIT_AUTH, LIMIT_READ, LIMIT_WRITE, identify_client, limiter,
)

client = TestClient(app)


@pytest.fixture
def limiting_on():
    """Enable the limiter and clear counters so cases do not affect each other."""
    limiter.enabled = True
    limiter.reset()
    yield
    limiter.reset()
    limiter.enabled = False


def test_login_is_rate_limited(limiting_on):
    """Unlimited password attempts would make bcrypt the only thing standing
    between an attacker and a weak password."""
    statuses = [
        client.post("/auth/login", data={"username": "admin", "password": "wrong"}).status_code
        for _ in range(15)
    ]
    assert 429 in statuses, "login was never rate limited"
    # The limit must not trip immediately — a genuine typo should not lock someone out.
    assert statuses[0] == 401


def test_rate_limit_response_states_the_limit(limiting_on):
    for _ in range(15):
        r = client.post("/auth/login", data={"username": "admin", "password": "wrong"})
        if r.status_code == 429:
            assert "Rate limit exceeded" in r.text
            return
    pytest.fail("never rate limited")


def test_auth_limit_is_stricter_than_read_limit():
    """Tiering is the point: throttling reads as hard as logins would make the
    product feel broken without adding security."""
    def per_minute(spec):
        n, _, unit = spec.partition("/")
        return int(n) if unit == "minute" else int(n) / 60

    assert per_minute(LIMIT_AUTH) < per_minute(LIMIT_READ)
    assert per_minute(LIMIT_WRITE) < per_minute(LIMIT_READ)


def test_ai_limit_is_hourly_not_per_minute():
    """AI calls cost money and can hold a connection for a minute, so they are
    bounded over a longer window than ordinary writes."""
    assert LIMIT_AI.endswith("/hour")


# --- Client identification ------------------------------------------------

class _FakeRequest:
    def __init__(self, headers=None, host="1.2.3.4"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": host})()
        self.scope = {"client": (host, 0), "headers": []}


def test_authenticated_requests_are_keyed_by_organisation():
    """Per-IP limiting punishes everyone behind a shared address and fails to
    constrain a distributed attacker."""
    from backend.core.auth import create_access_token

    token = create_access_token({"sub": "admin", "role": "Admin", "org": 7})
    key = identify_client(_FakeRequest({"authorization": f"Bearer {token}"}))
    assert key == "org:7"


def test_unauthenticated_requests_fall_back_to_ip():
    assert identify_client(_FakeRequest(host="9.9.9.9")).startswith("ip:")


def test_invalid_token_does_not_escape_limiting():
    """A forged or expired token must still be limited — otherwise sending
    garbage would be a way around the limiter."""
    key = identify_client(_FakeRequest({"authorization": "Bearer not-a-real-token"}))
    assert key.startswith("ip:")


def test_forged_org_claim_cannot_borrow_another_tenants_allowance():
    """The token signature is verified before its org claim is trusted."""
    from jose import jwt

    forged = jwt.encode({"sub": "attacker", "org": 1}, "wrong-signing-key-entirely",
                        algorithm="HS256")
    key = identify_client(_FakeRequest({"authorization": f"Bearer {forged}"}))
    assert key.startswith("ip:")
    assert key != "org:1"