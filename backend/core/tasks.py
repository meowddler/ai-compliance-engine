"""Scheduled task implementations.

Each task must be idempotent: with multiple instances every instance runs it,
so a second execution has to be harmless.
"""

from backend.config import EVIDENCE_FRESHNESS_DAYS
from backend.core.logging_config import get_logger
from backend.database import SessionLocal

logger = get_logger("tasks")


def degrade_stale_evidence():
    """Move controls whose evidence has expired to INSUFFICIENT_EVIDENCE.

    Idempotent: a control already degraded is skipped, because
    evaluate_staleness only considers PASS and FAIL as degradable. Running twice
    changes nothing.

    Runs across every organisation, since a scheduled job has no calling user.
    Each degradation is recorded in FindingHistory attributed to the system, so
    the change is not silent.
    """
    from backend.models.models import Evidence, FindingHistory, Organization, Violation
    from backend.utils.audit import log_action
    from backend.utils.freshness import evaluate_staleness

    db = SessionLocal()
    summary = {"organizations": 0, "degraded": 0}

    try:
        for org in db.query(Organization).all():
            summary["organizations"] += 1

            rows = (db.query(Violation, Evidence)
                      .outerjoin(Evidence, Violation.evidence_id == Evidence.id)
                      .filter(Violation.organization_id == org.id).all())
            if not rows:
                continue

            class _F:
                pass

            candidates = []
            for v, ev in rows:
                f = _F()
                f.id, f.status = v.id, v.status
                f.evidence_collected_at = ev.collected_at if ev else None
                candidates.append(f)

            decisions = evaluate_staleness(candidates, EVIDENCE_FRESHNESS_DAYS)
            if not decisions:
                continue

            by_id = {v.id: v for v, _ in rows}
            for d in decisions:
                v = by_id.get(d["finding_id"])
                if not v:
                    continue
                v.status = d["to_status"]
                v.message = d["reason"]
                db.add(FindingHistory(
                    violation_id=v.id,
                    organization_id=org.id,
                    from_state=f"status:{d['from_status']}",
                    to_state=f"status:{d['to_status']}",
                    note=d["reason"],
                    changed_by="system:scheduler",
                ))

            db.commit()
            log_action(db, "system:scheduler", "staleness_refresh",
                       f"Degraded {len(decisions)} finding(s) with expired evidence",
                       organization_id=org.id,
                       reason="Scheduled evidence freshness check.")
            db.commit()
            summary["degraded"] += len(decisions)

        return summary
    finally:
        db.close()


def verify_audit_chains():
    """Check every organisation's audit chain and log any break.

    Read-only, so trivially idempotent. Continuous verification matters because
    on-demand checking means tampering goes unnoticed until someone happens to
    look.
    """
    from backend.models.models import Organization
    from backend.utils.audit import chained_entries
    from backend.utils.audit_chain import verify_chain

    db = SessionLocal()
    summary = {"checked": 0, "invalid": 0}

    try:
        for org in db.query(Organization).all():
            result = verify_chain(chained_entries(db, org.id))
            summary["checked"] += 1
            if not result["valid"]:
                summary["invalid"] += 1
                # Logged at ERROR: a broken audit chain is the most serious
                # thing this system can discover about itself.
                logger.error("audit chain verification failed",
                             extra={"organization_id": org.id,
                                    "reason": result["reason"],
                                    "sequence": result.get("sequence")})
        return summary
    finally:
        db.close()