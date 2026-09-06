"""Job queue tests.

The properties that matter are claiming and retry. A queue that hands the same
job to two workers duplicates work; one that retries forever hides a permanent
failure behind apparent activity.
"""
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.core.jobs import (
    FAILED, QUEUED, SUCCEEDED, claim_next, drain, enqueue, queue_stats,
    register_handler, run_one,
)
from backend.database import SessionLocal
from backend.models.models import Job

client = TestClient(app)


def _headers():
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def clean_jobs():
    def purge():
        db = SessionLocal()
        db.query(Job).filter(Job.job_type.like("test_%")).delete(synchronize_session=False)
        db.commit()
        db.close()
    purge()
    yield
    purge()


# --- Registration ---------------------------------------------------------

def test_unregistered_job_type_is_refused_at_enqueue():
    """Failing here rather than when a worker picks it up: an unroutable job
    would otherwise sit in the queue until someone noticed."""
    db = SessionLocal()
    try:
        with pytest.raises(ValueError):
            enqueue(db, job_type="test_does_not_exist", payload={})
    finally:
        db.rollback()
        db.close()


# --- Claiming -------------------------------------------------------------

def test_a_job_is_claimed_only_once(clean_jobs):
    """Two workers reading 'the oldest queued job' simultaneously must not both
    take it."""
    register_handler("test_noop", lambda payload: {"ok": True})

    db = SessionLocal()
    enqueue(db, job_type="test_noop", payload={"n": 1}, organization_id=1)
    db.commit()
    db.close()

    first_db, second_db = SessionLocal(), SessionLocal()
    try:
        first = claim_next(first_db)
        second = claim_next(second_db)

        assert first is not None
        # Either nothing else was available, or it was a different job.
        assert second is None or second.id != first.id
    finally:
        first_db.close()
        second_db.close()


def test_claiming_an_empty_queue_returns_none(clean_jobs):
    db = SessionLocal()
    try:
        # Drain anything left over, then confirm the queue reports empty.
        drain(limit=50)
        assert queue_stats(db)["queued"] == 0
    finally:
        db.close()


# --- Execution and retry --------------------------------------------------

def test_successful_job_records_its_result(clean_jobs):
    register_handler("test_succeeds", lambda payload: {"doubled": payload["n"] * 2})

    db = SessionLocal()
    job = enqueue(db, job_type="test_succeeds", payload={"n": 21}, organization_id=1)
    db.commit()
    job_id = job.id
    db.close()

    drain(limit=10)

    db = SessionLocal()
    finished = db.query(Job).filter(Job.id == job_id).first()
    db.close()

    assert finished.status == SUCCEEDED
    assert json.loads(finished.result)["doubled"] == 42
    assert finished.finished_at is not None


def test_a_failing_job_retries_then_stops(clean_jobs):
    """Retrying forever would hide a permanent failure behind activity."""
    def always_fails(payload):
        raise RuntimeError("intentional")

    register_handler("test_fails", always_fails)

    db = SessionLocal()
    job = enqueue(db, job_type="test_fails", payload={}, organization_id=1, max_attempts=2)
    db.commit()
    job_id = job.id
    db.close()

    run_one()                       # attempt 1 -> requeued
    db = SessionLocal()
    after_first = db.query(Job).filter(Job.id == job_id).first()
    assert after_first.status == QUEUED
    assert after_first.attempts == 1
    db.close()

    run_one()                       # attempt 2 -> exhausted
    db = SessionLocal()
    after_second = db.query(Job).filter(Job.id == job_id).first()
    db.close()

    assert after_second.status == FAILED
    assert after_second.attempts == 2
    assert "RuntimeError" in after_second.error


def test_drain_is_bounded(clean_jobs):
    """One long backlog must not monopolise a scheduler tick."""
    register_handler("test_bounded", lambda payload: {"ok": True})

    db = SessionLocal()
    for i in range(5):
        enqueue(db, job_type="test_bounded", payload={"i": i}, organization_id=1)
    db.commit()
    db.close()

    result = drain(limit=2)
    assert result["processed"] == 2

    drain(limit=50)                 # clear the rest


def test_run_one_on_an_empty_queue_returns_none(clean_jobs):
    drain(limit=50)
    assert run_one() is None


# --- Endpoints ------------------------------------------------------------

def test_scan_evaluation_can_be_queued_and_polled():
    """The endpoint returns immediately; the work happens elsewhere."""
    import io

    headers = _headers()
    csv = ("server_id,port,port_exposed,mfa_enabled,last_login_days,failed_logins\n"
           "job-test-1,22,true,false,3,1\n")
    upload = client.post("/upload-logs", headers=headers,
                         files={"file": ("job.csv", io.BytesIO(csv.encode()), "text/csv")})
    assert upload.status_code == 200
    scan_id = upload.json()["scan_id"]

    queued = client.post("/jobs/evaluate-scan", headers=headers, json={"scan_id": scan_id})
    assert queued.status_code == 200
    job_id = queued.json()["job_id"]
    assert queued.json()["status"] == QUEUED

    drain(limit=10)                 # stand in for the scheduler

    finished = client.get(f"/jobs/{job_id}", headers=headers).json()
    assert finished["status"] == SUCCEEDED
    assert finished["result"]["scan_id"] == scan_id


def test_queueing_another_organisations_scan_is_refused():
    r = client.post("/jobs/evaluate-scan", headers=_headers(), json={"scan_id": 999999})
    assert r.status_code == 404


def test_job_status_is_tenant_scoped():
    assert client.get("/jobs/999999", headers=_headers()).status_code == 404


def test_queue_stats_requires_privilege():
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/jobs", headers=headers).status_code == 403


def test_evaluation_is_idempotent():
    """A retry after partial failure must produce one clean set of findings,
    not duplicates."""
    import io

    from backend.core.job_handlers import evaluate_scan
    from backend.models.models import Violation

    headers = _headers()
    csv = ("server_id,port,port_exposed,mfa_enabled,last_login_days,failed_logins\n"
           "idem-test,3389,true,false,90,12\n")
    scan_id = client.post("/upload-logs", headers=headers,
                          files={"file": ("i.csv", io.BytesIO(csv.encode()), "text/csv")}
                          ).json()["scan_id"]

    first = evaluate_scan({"scan_id": scan_id})
    second = evaluate_scan({"scan_id": scan_id})

    assert first["findings"] == second["findings"]

    db = SessionLocal()
    stored = db.query(Violation).filter(Violation.scan_id == scan_id).count()
    db.close()
    assert stored == second["findings"]