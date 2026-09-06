"""Operational metrics.

Two sources, deliberately separated:

  * In-process counters — request volume, latency, errors. Cheap, but reset on
    restart and are per-process. Adequate for a single instance; a shared store
    would be required behind a load balancer.
  * Database aggregates — scans, findings, AI cost. Durable and accurate, but
    each one is a query, so they are computed on request rather than
    continuously.

The endpoint states which is which, so nobody reads a counter that reset an
hour ago as a lifetime total.
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

# Bounded so a long-running process cannot grow memory without limit.
_MAX_LATENCY_SAMPLES = 1000

_lock = threading.Lock()
_started_at = time.time()

_request_count = defaultdict(int)          # (method, path_template) -> count
_status_count = defaultdict(int)           # status class -> count
_latencies = defaultdict(lambda: deque(maxlen=_MAX_LATENCY_SAMPLES))
_error_count = 0


def record_request(method: str, path: str, status: int, duration_ms: float):
    """Record one completed request. Called from middleware, so it must be cheap."""
    global _error_count
    key = f"{method} {path}"
    with _lock:
        _request_count[key] += 1
        _status_count[f"{status // 100}xx"] += 1
        _latencies[key].append(duration_ms)
        if status >= 500:
            _error_count += 1


def _percentile(values, pct):
    """Nearest-rank percentile. Averages hide the slow requests that matter."""
    if not values:
        return None
    ordered = sorted(values)
    idx = min(int(len(ordered) * pct / 100), len(ordered) - 1)
    return round(ordered[idx], 1)


def request_metrics() -> dict:
    with _lock:
        endpoints = []
        for key, count in sorted(_request_count.items(), key=lambda kv: -kv[1]):
            samples = list(_latencies[key])
            endpoints.append({
                "endpoint": key,
                "count": count,
                "p50_ms": _percentile(samples, 50),
                "p95_ms": _percentile(samples, 95),
                "p99_ms": _percentile(samples, 99),
                "max_ms": round(max(samples), 1) if samples else None,
            })
        total = sum(_request_count.values())
        return {
            "uptime_seconds": round(time.time() - _started_at, 1),
            "total_requests": total,
            "server_errors": _error_count,
            "error_rate": round(_error_count / total, 4) if total else 0.0,
            "status_classes": dict(_status_count),
            "endpoints": endpoints[:25],
            "note": ("In-process counters. They reset on restart and are not shared "
                     "across instances."),
        }


def business_metrics(db, organization_id) -> dict:
    """Durable counts from the database, scoped to one organisation."""
    from sqlalchemy import func

    from backend.models.models import (
        AIInteraction, AuditLog, Evidence, Rule, Scan, Violation,
    )

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)

    def count(model, *filters):
        return db.query(func.count(model.id)).filter(*filters).scalar() or 0

    org = organization_id

    ai_tokens = db.query(
        func.coalesce(func.sum(AIInteraction.prompt_tokens), 0),
        func.coalesce(func.sum(AIInteraction.completion_tokens), 0),
    ).filter(AIInteraction.organization_id == org).first()

    ai_latency = db.query(
        func.avg(AIInteraction.latency_ms)
    ).filter(AIInteraction.organization_id == org).scalar()

    return {
        "scans": {
            "total": count(Scan, Scan.organization_id == org),
            "last_24h": count(Scan, Scan.organization_id == org, Scan.created_at >= day_ago),
        },
        "findings": {
            "total": count(Violation, Violation.organization_id == org),
            "open": count(Violation, Violation.organization_id == org,
                          Violation.lifecycle == "OPEN"),
            "failing": count(Violation, Violation.organization_id == org,
                             Violation.status == "FAIL"),
            "unverifiable": count(Violation, Violation.organization_id == org,
                                  Violation.status == "INSUFFICIENT_EVIDENCE"),
        },
        "controls": {
            "active": count(Rule, Rule.organization_id == org,
                            Rule.active.is_(True), Rule.is_current.is_(True)),
            "total_versions": count(Rule, Rule.organization_id == org),
        },
        "evidence": {
            "records": count(Evidence, Evidence.organization_id == org),
            "bytes_stored": db.query(
                func.coalesce(func.sum(Evidence.size_bytes), 0)
            ).filter(Evidence.organization_id == org).scalar() or 0,
        },
        "ai": {
            "calls": count(AIInteraction, AIInteraction.organization_id == org),
            "calls_last_24h": count(AIInteraction, AIInteraction.organization_id == org,
                                    AIInteraction.created_at >= day_ago),
            "failed_calls": count(AIInteraction, AIInteraction.organization_id == org,
                                  AIInteraction.error.isnot(None)),
            "prompt_tokens": int(ai_tokens[0]) if ai_tokens else 0,
            "completion_tokens": int(ai_tokens[1]) if ai_tokens else 0,
            "avg_latency_ms": round(float(ai_latency), 1) if ai_latency else None,
        },
        "audit": {
            "entries": count(AuditLog, AuditLog.organization_id == org),
        },
    }