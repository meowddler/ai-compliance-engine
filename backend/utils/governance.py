"""Data retention and legal hold.

Two rules govern deletion, and their precedence matters:

1. A legal hold ALWAYS wins. A record under hold survives its retention window,
   because a legal obligation outranks a housekeeping rule.
2. Some data classes are never deletable by retention at all. Audit history is
   the obvious one: a system that can quietly age out its own audit trail
   cannot be audited.

Nothing here deletes anything. It reports what WOULD be eligible and why, so a
destructive action is always a deliberate, separately authorised step.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.models.models import (
    AuditLog, Evidence, LegalHold, RetentionPolicy, Scan, ScanRecord, Violation,
)

# Classes that retention may never delete, whatever a policy says.
UNDELETABLE_CLASSES = {"audit_log"}

# Sensible starting policy. Deliberately conservative — a too-short default
# would quietly destroy evidence.
DEFAULT_POLICIES = [
    ("evidence", 2555, True,  "Uploaded evidence files and their metadata (7 years)."),
    ("scan_records", 730, True, "Per-row feature snapshots used for anomaly baselines (2 years)."),
    ("findings", 2555, True, "Compliance findings and their lifecycle history (7 years)."),
    ("audit_log", 3650, False, "Audit trail. Retained 10 years and never deleted by retention."),
]


def seed_default_policies(db: Session, organization_id, created_by: str):
    """Create default policies for an organisation that has none."""
    created = []
    for data_class, days, deletable, description in DEFAULT_POLICIES:
        exists = db.query(RetentionPolicy).filter(
            RetentionPolicy.organization_id == organization_id,
            RetentionPolicy.data_class == data_class,
        ).first()
        if exists:
            continue
        db.add(RetentionPolicy(
            organization_id=organization_id,
            data_class=data_class,
            retention_days=days,
            deletion_permitted=deletable and data_class not in UNDELETABLE_CLASSES,
            description=description,
            created_by=created_by,
        ))
        created.append(data_class)
    return created


def active_holds(db: Session, organization_id, data_class: str | None = None):
    """Holds currently in force. A hold with no data_class covers everything."""
    query = db.query(LegalHold).filter(
        LegalHold.organization_id == organization_id,
        LegalHold.active.is_(True),
    )
    holds = query.all()
    if data_class is None:
        return holds
    return [h for h in holds if h.data_class in (None, data_class)]


def _cutoff(days: int):
    return datetime.now(timezone.utc) - timedelta(days=days)


def evaluate_retention(db: Session, organization_id):
    """Report what is eligible for deletion, and what is protected from it.

    Read-only by design. Producing a list is a different act from acting on it,
    and only the first should be automatic.
    """
    policies = db.query(RetentionPolicy).filter(
        RetentionPolicy.organization_id == organization_id).all()

    if not policies:
        return {"evaluated": False,
                "reason": "No retention policies are configured for this organisation.",
                "classes": []}

    counters = {
        "evidence": lambda c: db.query(Evidence).filter(
            Evidence.organization_id == organization_id,
            Evidence.collected_at < c).count(),
        "scan_records": lambda c: db.query(ScanRecord).filter(
            ScanRecord.organization_id == organization_id,
            ScanRecord.created_at < c).count(),
        "findings": lambda c: db.query(Violation).filter(
            Violation.organization_id == organization_id,
            Violation.created_at < c).count(),
        "audit_log": lambda c: db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id,
            AuditLog.timestamp < c).count(),
    }

    classes = []
    for policy in policies:
        holds = active_holds(db, organization_id, policy.data_class)
        cutoff = _cutoff(policy.retention_days)
        counter = counters.get(policy.data_class)
        past_retention = counter(cutoff) if counter else None

        if policy.data_class in UNDELETABLE_CLASSES or not policy.deletion_permitted:
            eligible, blocked_by = 0, "policy: this class is never deleted by retention"
        elif holds:
            eligible, blocked_by = 0, f"legal hold: {', '.join(h.name for h in holds)}"
        else:
            eligible, blocked_by = past_retention, None

        classes.append({
            "data_class": policy.data_class,
            "retention_days": policy.retention_days,
            "deletion_permitted": policy.deletion_permitted,
            "cutoff": cutoff.isoformat(),
            "records_past_retention": past_retention,
            "eligible_for_deletion": eligible,
            "blocked_by": blocked_by,
            "active_holds": [{"id": h.id, "name": h.name, "reason": h.reason} for h in holds],
        })

    return {"evaluated": True, "reason": None, "classes": classes,
            "note": ("Nothing is deleted by this evaluation. Deletion is a separate, "
                     "explicitly authorised action.")}