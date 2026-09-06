"""Shared test configuration.

Rate limiting is disabled for the suite. The tests log in dozens of times in
seconds — legitimate behaviour for a test run, and exactly what the limiter is
designed to stop in production. Leaving it enabled would mean the suite tests
the limiter rather than the application.

Rate limiting itself is covered separately in test_ratelimit.py, which enables
it deliberately for those cases.
"""
import pytest

from backend.core.ratelimit import limiter


@pytest.fixture(autouse=True, scope="session")
def disable_rate_limiting():
    """Turn the limiter off for the whole session."""
    limiter.enabled = False
    yield
    limiter.enabled = True