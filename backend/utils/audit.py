"""Audit logging.

Two deliberate decisions here:

1. NO COMMIT. This function only stages the entry; the caller commits. The
   previous version called db.commit() itself, which would commit whatever
   else was pending in the session — turning an audit call into an accidental
   save of half-finished work.

2. TENANT-SCOPED. Every entry records the organisation it belongs to, so one
   tenant's auditor cannot read another tenant's activity.
"""

from sqlalchemy.orm import Session

from backend.models.models import AuditLog


def log_action(db: Session, username: str, action: str, details: str = "",
               organization_id: int | None = None) -> AuditLog:
    """Stage an audit entry. The CALLER is responsible for committing.

    Returns the entry so a caller can inspect it if needed.
    """
    entry = AuditLog(
        organization_id=organization_id,
        username=username,
        action=action,
        details=details,
    )
    db.add(entry)
    return entry