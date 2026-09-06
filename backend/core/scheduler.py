"""Background scheduler.

Runs periodic maintenance in-process using asyncio, not a separate worker.

That choice is deliberate and has a cost worth stating: with multiple instances,
every instance runs the same job, so a task must be idempotent or guarded by a
lock. The freshness evaluation is idempotent — degrading an already-degraded
control changes nothing — so duplicate execution is wasteful rather than
harmful. A task with side effects would need a database advisory lock before
this design is safe.

The alternative, a Celery worker with Redis, is the correct answer at scale and
is not built here. This closes the gap between "the logic exists" and "the logic
runs on its own", which is the difference between periodic and manual.
"""

import asyncio
import traceback
from datetime import datetime, timezone

from backend.core.logging_config import correlation_id, get_logger, new_correlation_id

logger = get_logger("scheduler")


class ScheduledTask:
    """One periodic job and the record of how it has been going."""

    def __init__(self, name, func, interval_seconds, enabled=True):
        self.name = name
        self.func = func
        self.interval_seconds = interval_seconds
        self.enabled = enabled

        self.last_run_at = None
        self.last_success_at = None
        self.last_error = None
        self.run_count = 0
        self.failure_count = 0
        self.last_duration_ms = None

    def status(self):
        return {
            "name": self.name,
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "run_count": self.run_count,
            "failure_count": self.failure_count,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_success_at": self.last_success_at.isoformat() if self.last_success_at else None,
            "last_duration_ms": self.last_duration_ms,
            "last_error": self.last_error,
            # A task that has never succeeded is reported as unhealthy even
            # while it keeps running — silent repeated failure is the outcome a
            # scheduler most needs to avoid.
            "healthy": self.failure_count == 0 or self.last_success_at is not None,
        }


class Scheduler:
    """Runs registered tasks on a fixed interval."""

    def __init__(self):
        self._tasks: dict[str, ScheduledTask] = {}
        self._handles: list[asyncio.Task] = []
        self._running = False

    def register(self, name, func, interval_seconds, enabled=True):
        self._tasks[name] = ScheduledTask(name, func, interval_seconds, enabled)
        return self._tasks[name]

    async def _run_task(self, task: ScheduledTask):
        """Run one task forever, surviving its own failures.

        A task that raises must not kill the loop — otherwise one bad run stops
        all future runs, and the failure is silent because nothing is left to
        report it.
        """
        # Stagger the first run so startup is not a thundering herd of jobs.
        await asyncio.sleep(min(30, task.interval_seconds))

        while self._running:
            if not task.enabled:
                await asyncio.sleep(task.interval_seconds)
                continue

            token = correlation_id.set(f"sched-{new_correlation_id()[:8]}")
            started = datetime.now(timezone.utc)
            task.last_run_at = started
            task.run_count += 1

            try:
                # Tasks are synchronous database work; running them in a thread
                # keeps the event loop free to serve requests.
                result = await asyncio.to_thread(task.func)
                task.last_success_at = datetime.now(timezone.utc)
                task.last_error = None
                task.last_duration_ms = round(
                    (task.last_success_at - started).total_seconds() * 1000, 1)
                logger.info("scheduled task completed",
                            extra={"task": task.name,
                                   "duration_ms": task.last_duration_ms,
                                   "result": result})
            except Exception as exc:
                task.failure_count += 1
                task.last_error = f"{type(exc).__name__}: {exc}"
                logger.error("scheduled task failed",
                             extra={"task": task.name,
                                    "error": task.last_error,
                                    "traceback": traceback.format_exc()})
            finally:
                correlation_id.reset(token)

            await asyncio.sleep(task.interval_seconds)

    def start(self):
        if self._running:
            return
        self._running = True
        for task in self._tasks.values():
            self._handles.append(asyncio.create_task(self._run_task(task)))
        logger.info("scheduler started", extra={"tasks": list(self._tasks)})

    async def stop(self):
        self._running = False
        for handle in self._handles:
            handle.cancel()
        # Await cancellation so shutdown does not race a task mid-write.
        await asyncio.gather(*self._handles, return_exceptions=True)
        self._handles.clear()
        logger.info("scheduler stopped")

    def status(self):
        return {
            "running": self._running,
            "tasks": [t.status() for t in self._tasks.values()],
            "note": ("In-process asyncio scheduler. Every application instance runs "
                     "every task, so tasks must be idempotent. A distributed lock "
                     "or a dedicated worker is required before running tasks with "
                     "non-idempotent side effects."),
        }


scheduler = Scheduler()