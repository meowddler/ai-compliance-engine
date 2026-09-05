"""Audit logging.

Entries are hash-chained: each one covers its own content plus the previous
entry's hash, so tampering breaks every hash that follows.

Design notes:

* NO COMMIT HERE. The caller commits. A helper that commits would silently
  save whatever else was pending in the session.
* Sequence and previous-hash are read at write time, so entries must be
  written in order within a transaction.
* Secrets are redacted before hashing — an immutable record must not
  permanently preserve a password or token.
"""

import json

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.models import AuditLog
from backend.utils.audit_chain import (
    CANONICAL_VERSION, GENESIS_HASH, build_payload, compute_hash, redact,
)


def _chain_head(db: Session, organization_id):
    """Return (next_sequence, previous_hash) for an organisation's chain.

    Each organisation keeps its own chain so one tenant's activity volume
    cannot affect another's verification.
    """
    last = (db.query(AuditLog)
              .filter(AuditLog.organization_id == organization_id,
                      AuditLog.entry_hash.isnot(None))
              .order_by(AuditLog.sequence.desc())
              .first())
    if last is None:
        return 1, GENESIS_HASH
    return (last.sequence or 0) + 1, last.entry_hash


def log_action(db: Session, username: str, action: str, details: str = "",
               organization_id: int | None = None, entity_type: str | None = None,
               entity_id=None, before: dict | None = None, after: dict | None = None,
               reason: str | None = None, correlation_id: str | None = None) -> AuditLog:
    """Stage a chained audit entry. The CALLER commits."""
    sequence, previous_hash = _chain_head(db, organization_id)

    safe_before = redact(before) if before is not None else None
    safe_after = redact(after) if after is not None else None

    payload = build_payload(
        sequence=sequence,
        organization_id=organization_id,
        actor=username,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        before=safe_before,
        after=safe_after,
        reason=reason,
        correlation_id=correlation_id,
    )
    entry_hash = compute_hash(previous_hash, payload)

    entry = AuditLog(
        organization_id=organization_id,
        sequence=sequence,
        username=username,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        before_state=json.dumps(safe_before) if safe_before is not None else None,
        after_state=json.dumps(safe_after) if safe_after is not None else None,
        reason=reason,
        correlation_id=correlation_id,
        details=details,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        canonical_version=CANONICAL_VERSION,
        timestamp=payload["timestamp"],
    )
    db.add(entry)
    return entry


class _VerifiableEntry:
    """Adapter presenting a stored row in the shape verify_chain expects.

    Rebuilds the payload from stored columns rather than trusting any cached
    form — that reconstruction is the point of verification.
    """

    def __init__(self, row: AuditLog):
        self._row = row
        self.sequence = row.sequence
        self.previous_hash = row.previous_hash
        self.entry_hash = row.entry_hash

    def payload(self):
        return build_payload(
            sequence=self._row.sequence,
            organization_id=self._row.organization_id,
            actor=self._row.username,
            action=self._row.action,
            entity_type=self._row.entity_type,
            entity_id=self._row.entity_id,
            before=json.loads(self._row.before_state) if self._row.before_state else None,
            after=json.loads(self._row.after_state) if self._row.after_state else None,
            reason=self._row.reason,
            correlation_id=self._row.correlation_id,
            timestamp=self._row.timestamp,
        )


def chained_entries(db: Session, organization_id):
    """All chained entries for an organisation, in sequence order.

    Pre-chain rows (no hash) are excluded: they are real history but predate
    the chain and cannot be vouched for. Silently including them would make
    verification fail for a reason that is not tampering.
    """
    rows = (db.query(AuditLog)
              .filter(AuditLog.organization_id == organization_id,
                      AuditLog.entry_hash.isnot(None))
              .order_by(AuditLog.sequence.asc())
              .all())
    return [_VerifiableEntry(r) for r in rows]


def chain_stats(db: Session, organization_id):
    """Counts used by the verification API to describe coverage honestly."""
    total = db.query(func.count(AuditLog.id)).filter(
        AuditLog.organization_id == organization_id).scalar() or 0
    chained = db.query(func.count(AuditLog.id)).filter(
        AuditLog.organization_id == organization_id,
        AuditLog.entry_hash.isnot(None)).scalar() or 0
    return {"total_entries": total, "chained_entries": chained,
            "unchained_legacy_entries": total - chained}

# --- Controlled audit representations --------------------------------------
# Deliberately explicit rather than serialising whole ORM objects: an audit
# record is permanent, so what goes into it is a decision, not an accident.
# Adding a column to a model must not silently start recording it forever.

def snapshot_rule(rule) -> dict:
    """The audit-visible shape of a control."""
    if rule is None:
        return None
    return {
        "id": rule.id,
        "name": rule.name,
        "version": rule.version,
        "is_current": rule.is_current,
        "description": rule.description,
        "framework": rule.framework,
        "severity": rule.severity,
        "remediation": rule.remediation,
        "condition": rule.condition,
        "active": rule.active,
    }


def snapshot_finding(v) -> dict:
    """The audit-visible shape of a finding."""
    if v is None:
        return None
    return {
        "id": v.id,
        "server_id": v.server_id,
        "rule_name": v.rule_name,
        "rule_id": v.rule_id,
        "evidence_id": v.evidence_id,
        "severity": v.severity,
        "status": v.status,
        "lifecycle": v.lifecycle,
    }