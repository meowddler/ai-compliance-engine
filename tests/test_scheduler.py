"""Scheduler tests.

What matters is not that tasks run, but that the scheduler survives them
failing. A scheduler whose loop dies on one bad run stops silently, and the
work appears to be happening when it is not.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.core.scheduler import ScheduledTask, Scheduler
from backend.core.tasks import degrade_stale_evidence, verify_audit_chains

client = TestClient(app)


def _headers():
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- Task status ----------------------------------------------------------

def test_task_reports_its_configuration():
    task = ScheduledTask("demo", lambda: None, 60)
    status = task.status()
    assert status["name"] == "demo"
    assert status["interval_seconds"] == 60
    assert status["run_count"] == 0


def test_a_task_that_never_succeeded_is_unhealthy():
    """Silent repeated failure is the outcome a scheduler most needs to avoid."""
    task = ScheduledTask("failing", lambda: None, 60)
    task.failure_count = 3
    task.last_success_at = None
    assert task.status()["healthy"] is False


def test_a_task_that_recovered_is_healthy():
    """One historic failure followed by success is not an alarm condition."""
    from datetime import datetime, timezone

    task = ScheduledTask("recovered", lambda: None, 60)
    task.failure_count = 1
    task.last_success_at = datetime.now(timezone.utc)
    assert task.status()["healthy"] is True


# --- Loop resilience ------------------------------------------------------

@pytest.mark.asyncio
async def test_a_failing_task_does_not_kill_the_loop():
    """One bad run must not stop all future runs."""
    calls = {"n": 0}

    def always_fails():
        calls["n"] += 1
        raise RuntimeError("intentional failure")

    sched = Scheduler()
    task = sched.register("boom", always_fails, interval_seconds=0.05)
    sched._running = True

    handle = asyncio.create_task(sched._run_task(task))
    await asyncio.sleep(0.25)
    sched._running = False
    handle.cancel()
    try:
        await handle
    except asyncio.CancelledError:
        pass

    assert calls["n"] >= 2, "the loop stopped after the first failure"
    assert task.failure_count >= 2
    assert "RuntimeError" in (task.last_error or "")


@pytest.mark.asyncio
async def test_a_disabled_task_does_not_run():
    calls = {"n": 0}

    def counter():
        calls["n"] += 1

    sched = Scheduler()
    task = sched.register("off", counter, interval_seconds=0.05, enabled=False)
    sched._running = True

    handle = asyncio.create_task(sched._run_task(task))
    await asyncio.sleep(0.2)
    sched._running = False
    handle.cancel()
    try:
        await handle
    except asyncio.CancelledError:
        pass

    assert calls["n"] == 0


# --- Task idempotency -----------------------------------------------------

def test_freshness_task_is_idempotent():
    """Every instance runs every task, so a second execution must be harmless."""
    first = degrade_stale_evidence()
    second = degrade_stale_evidence()
    # Anything degradable was degraded by the first run; the second finds none.
    assert second["degraded"] == 0
    assert first["organizations"] == second["organizations"]


def test_chain_verification_is_read_only():
    """Verification must not alter what it inspects."""
    from backend.database import SessionLocal
    from backend.models.models import AuditLog

    db = SessionLocal()
    before = db.query(AuditLog).count()
    db.close()

    result = verify_audit_chains()

    db = SessionLocal()
    after = db.query(AuditLog).count()
    db.close()

    assert after == before
    assert result["checked"] >= 1


# --- Endpoint -------------------------------------------------------------

def test_scheduler_status_endpoint():
    """The endpoint reports state; it does not assert the scheduler is running.

    TestClient does not trigger the application lifespan unless used as a
    context manager, so background tasks are deliberately not started during
    the suite — a test run should not be doing real maintenance work.
    """
    body = client.get("/admin/scheduler", headers=_headers()).json()
    assert "running" in body
    assert isinstance(body["tasks"], list)


def test_lifespan_registers_and_starts_the_tasks():
    """Verified with the lifespan actually triggered."""
    with TestClient(app) as lifespan_client:
        r = lifespan_client.post("/auth/login",
                                 data={"username": "admin", "password": "admin123"})
        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
        body = lifespan_client.get("/admin/scheduler", headers=headers).json()

    assert body["running"] is True
    names = {t["name"] for t in body["tasks"]}
    assert "degrade_stale_evidence" in names
    assert "verify_audit_chains" in names


def test_status_declares_the_multi_instance_caveat():
    """Every instance runs every task; that constraint must not be hidden."""
    body = client.get("/admin/scheduler", headers=_headers()).json()
    assert "idempotent" in body["note"]


def test_scheduler_status_requires_privilege():
    r = client.post("/auth/login", data={"username": "analyst1", "password": "analyst123"})
    if r.status_code != 200:
        return
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/admin/scheduler", headers=headers).status_code == 403