"""Postgres-backed job queue.

Chosen over Redis because the database is already a dependency: a queue that
lives in it cannot fail independently of the data it operates on, and there is
one less service to run, secure, and back up. The trade is throughput, which is
the right trade at this scale.

CLAIMING IS THE WHOLE PROBLEM.
Two workers reading "the oldest queued job" at the same moment will both take
it. The claim below uses SELECT ... FOR UPDATE SKIP LOCKED, which makes the read
and the claim a single atomic act: a row another worker holds is skipped rather
than waited for, so workers never block each other and never collide.
"""

import json
import socket
import traceback
from datetime import datetime, timezone

from sqlalchemy import text

from backend.core.logging_config import get_logger
from backend.database import SessionLocal
from backend.models.models import Job

logger = get_logger("jobs")

QUEUED, RUNNING, SUCCEEDED, FAILED = "QUEUED", "RUNNING", "SUCCEEDED", "FAILED"

# Handlers are registered rather than imported dynamically: a queue that can
# invoke an arbitrary named function is a remote code execution primitive.
_HANDLERS = {}


def register_handler(job_type: str, func):
    _HANDLERS[job_type] = func


def worker_id() -> str:
    """Identifies which process holds a claim, for diagnosing a stuck job."""
    import os
    return f"{socket.gethostname()}:{os.getpid()}"


def enqueue(db, *, job_type: str, payload: dict, organization_id=None,
            requested_by: str = "system", max_attempts: int = 3) -> Job:
    """Add a job. The caller commits, consistent with the rest of the codebase."""
    if job_type not in _HANDLERS:
        # Fail at enqueue time rather than when a worker picks it up — an
        # unroutable job would otherwise sit in the queue until someone noticed.
        raise ValueError(f"No handler registered for job type {job_type!r}.")

    job = Job(
        organization_id=organization_id,
        job_type=job_type,
        status=QUEUED,
        payload=json.dumps(payload),
        requested_by=requested_by,
        max_attempts=max_attempts,
    )
    db.add(job)
    return job


def claim_next(db) -> Job | None:
    """Atomically take the oldest queued job, or return None.

    SKIP LOCKED is what makes this safe with concurrent workers: a row already
    locked by another claim is passed over instead of blocking, so throughput
    does not collapse to serial execution.
    """
    row = db.execute(text("""
        SELECT id FROM jobs
        WHERE status = :queued
        ORDER BY created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    """), {"queued": QUEUED}).first()

    if row is None:
        return None

    job = db.query(Job).filter(Job.id == row[0]).first()
    if job is None or job.status != QUEUED:
        return None

    job.status = RUNNING
    job.claimed_at = datetime.now(timezone.utc)
    job.claimed_by = worker_id()
    job.started_at = job.claimed_at
    job.attempts += 1
    db.commit()
    return job


def run_one() -> dict | None:
    """Claim and execute a single job. Returns a summary, or None if idle."""
    db = SessionLocal()
    try:
        job = claim_next(db)
        if job is None:
            return None

        handler = _HANDLERS.get(job.job_type)
        if handler is None:
            job.status = FAILED
            job.error = f"No handler registered for {job.job_type!r}."
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return {"job_id": job.id, "status": FAILED, "error": job.error}

        try:
            result = handler(json.loads(job.payload))
            job.status = SUCCEEDED
            job.result = json.dumps(result, default=str)
            job.error = None
        except Exception as exc:
            # Retry until the attempt limit, then stop. A job that retries
            # forever hides a permanent failure behind apparent activity.
            job.error = f"{type(exc).__name__}: {exc}"
            job.status = QUEUED if job.attempts < job.max_attempts else FAILED
            logger.error("job failed",
                         extra={"job_id": job.id, "job_type": job.job_type,
                                "attempt": job.attempts, "error": job.error,
                                "traceback": traceback.format_exc()})
        finally:
            job.finished_at = datetime.now(timezone.utc)
            db.commit()

        return {"job_id": job.id, "status": job.status,
                "attempts": job.attempts, "error": job.error}
    finally:
        db.close()


def drain(limit: int = 25) -> dict:
    """Run queued jobs until the queue is empty or the limit is reached.

    Bounded so one long backlog cannot monopolise a scheduler tick.
    """
    processed, succeeded, failed = 0, 0, 0
    for _ in range(limit):
        outcome = run_one()
        if outcome is None:
            break
        processed += 1
        if outcome["status"] == SUCCEEDED:
            succeeded += 1
        elif outcome["status"] == FAILED:
            failed += 1
    return {"processed": processed, "succeeded": succeeded, "failed": failed}


def queue_stats(db, organization_id=None) -> dict:
    """Queue depth by status. A growing QUEUED count is the backlog signal."""
    from sqlalchemy import func

    query = db.query(Job.status, func.count(Job.id))
    if organization_id is not None:
        query = query.filter(Job.organization_id == organization_id)

    counts = dict(query.group_by(Job.status).all())
    return {
        "queued": counts.get(QUEUED, 0),
        "running": counts.get(RUNNING, 0),
        "succeeded": counts.get(SUCCEEDED, 0),
        "failed": counts.get(FAILED, 0),
    }