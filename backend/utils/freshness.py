"""Evidence freshness monitoring.

A compliance control is only as current as the evidence behind it. Evidence
that has aged past its validity window can no longer support a PASS — but it
also does not mean the control FAILED. It means we can no longer verify it.

So stale evidence degrades a control to INSUFFICIENT_EVIDENCE, never to FAIL
and never leaving it as PASS. This is the same fail-closed principle used
throughout the engine: when we cannot conclude, say so explicitly.
"""

from datetime import datetime, timedelta, timezone

# Statuses that can be degraded. A control that already FAILED stays failed —
# stale evidence does not erase a known violation.
DEGRADABLE_STATUSES = {"PASS", "FAIL"}
DEGRADED_STATUS = "INSUFFICIENT_EVIDENCE"


def is_stale(collected_at, freshness_days, now=None):
    """True if evidence has aged past its validity window."""
    if collected_at is None:
        return True                       # unknown age cannot be trusted as fresh
    # Timezone-aware: evidence timestamps carry an offset, and subtracting a
    # naive datetime from an aware one raises TypeError.
    now = now or datetime.now(timezone.utc)
    return (now - collected_at) > timedelta(days=freshness_days)


def age_days(collected_at, now=None):
    if collected_at is None:
        return None
    # Timezone-aware: evidence timestamps carry an offset, and subtracting a
    # naive datetime from an aware one raises TypeError.
    now = now or datetime.now(timezone.utc)
    return (now - collected_at).days


def evaluate_staleness(findings, freshness_days, now=None):
    """Decide which findings should degrade because their evidence is stale.

    findings: iterable of objects with .id, .status, and .evidence_collected_at

    Returns a list of degradation decisions. Nothing is mutated here — the
    caller applies them, so this stays testable and side-effect free.
    """
    # Timezone-aware: evidence timestamps carry an offset, and subtracting a
    # naive datetime from an aware one raises TypeError.
    now = now or datetime.now(timezone.utc)
    decisions = []

    for f in findings:
        current = (getattr(f, "status", None) or "").upper()
        if current not in DEGRADABLE_STATUSES:
            continue                      # already unverified; nothing to degrade

        collected = getattr(f, "evidence_collected_at", None)
        if not is_stale(collected, freshness_days, now):
            continue

        decisions.append({
            "finding_id": getattr(f, "id", None),
            "from_status": current,
            "to_status": DEGRADED_STATUS,
            "reason": (
                f"Evidence is {age_days(collected, now)} days old, exceeding the "
                f"{freshness_days}-day validity window; the control can no longer be verified."
                if collected else
                "Evidence collection date is unknown; the control cannot be verified."
            ),
        })

    return decisions