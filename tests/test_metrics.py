"""Metrics tests.

Metrics describe a customer's operations, so they are authenticated and
tenant-scoped. The endpoint must also be honest about which numbers are durable
and which reset on restart.
"""
from fastapi.testclient import TestClient

from backend.app import app
from backend.core.metrics import _percentile, record_request, request_metrics

client = TestClient(app)


def _headers(username="admin", password="admin123"):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- Percentiles ----------------------------------------------------------

def test_percentiles_report_the_tail_not_the_average():
    """An average hides the slow requests, which are the ones users notice."""
    samples = list(range(1, 101))            # 1..100
    assert _percentile(samples, 50) == 51
    assert _percentile(samples, 95) == 96
    assert _percentile(samples, 99) == 100


def test_percentile_of_empty_sample_is_none():
    """No data must read as 'unknown', not as zero latency."""
    assert _percentile([], 95) is None


def test_single_sample_percentile():
    assert _percentile([42.0], 99) == 42.0


# --- Counters -------------------------------------------------------------

def test_requests_are_counted_and_timed():
    record_request("GET", "/test-metric-path", 200, 12.5)
    record_request("GET", "/test-metric-path", 200, 25.0)

    metrics = request_metrics()
    entry = next(e for e in metrics["endpoints"] if e["endpoint"] == "GET /test-metric-path")
    assert entry["count"] >= 2
    assert entry["max_ms"] >= 25.0


def test_server_errors_are_tracked_separately_from_client_errors():
    """A 4xx is the client's problem; a 5xx is ours. Conflating them would make
    the error rate meaningless."""
    before = request_metrics()["server_errors"]
    record_request("GET", "/test-error-path", 404, 1.0)
    assert request_metrics()["server_errors"] == before      # 404 is not our error

    record_request("GET", "/test-error-path", 500, 1.0)
    assert request_metrics()["server_errors"] == before + 1


def test_status_classes_are_aggregated():
    record_request("GET", "/test-status-path", 201, 1.0)
    assert "2xx" in request_metrics()["status_classes"]


def test_latency_samples_are_bounded():
    """An unbounded sample buffer grows without limit in a long-running process."""
    from backend.core.metrics import _MAX_LATENCY_SAMPLES, _latencies

    for i in range(_MAX_LATENCY_SAMPLES + 200):
        record_request("GET", "/test-bounded", 200, float(i))
    assert len(_latencies["GET /test-bounded"]) == _MAX_LATENCY_SAMPLES


# --- Endpoint -------------------------------------------------------------

def test_metrics_endpoint_returns_both_sources():
    body = client.get("/metrics", headers=_headers()).json()
    assert "requests" in body and "business" in body
    for section in ("scans", "findings", "controls", "evidence", "ai", "audit"):
        assert section in body["business"], section


def test_metrics_states_which_counters_are_volatile():
    """A counter that reset an hour ago must not be read as a lifetime total."""
    body = client.get("/metrics", headers=_headers()).json()
    assert "reset on restart" in body["requests"]["note"]


def test_metrics_requires_authentication():
    assert client.get("/metrics").status_code == 401


def test_metrics_denied_to_unprivileged_role():
    """Request volumes and finding counts describe a customer's operations."""
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/metrics", headers=headers).status_code == 403


def test_business_metrics_are_tenant_scoped():
    """Counts must reflect the caller's organisation only."""
    from backend.core.metrics import business_metrics
    from backend.database import SessionLocal

    db = SessionLocal()
    try:
        real = business_metrics(db, 1)
        empty = business_metrics(db, 999999)          # organisation with no data
        assert empty["scans"]["total"] == 0
        assert empty["findings"]["total"] == 0
        assert real["scans"]["total"] >= empty["scans"]["total"]
    finally:
        db.close()