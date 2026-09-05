"""Database models.

Two conventions worth knowing before reading:

1. TENANCY. Every tenant-owned table carries `organization_id`. Queries must
   filter on it; nothing in this layer enforces that, so the service layer is
   responsible. Tables without it (Framework) are deliberately global.

2. DELETION. Foreign keys that point at scans or violations declare
   ON DELETE CASCADE. Clearing a scan previously required remembering to delete
   every dependent table by hand, and adding a new table silently broke it —
   three times. The database now enforces the ordering instead of the caller.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Index
)
from sqlalchemy.orm import relationship

from backend.database import Base


def utcnow():
    """Timezone-aware UTC timestamp.

    datetime.utcnow() is deprecated and returns a NAIVE datetime, which silently
    compares wrong against aware values. Timestamps are stored in UTC; clients
    convert for display.
    """
    return datetime.now(timezone.utc)


# Role names used by require_role(). Defined once so a typo is an ImportError
# rather than a silent authorisation failure.
class Roles:
    ADMIN = "Admin"
    AUDITOR = "Auditor"
    ANALYST = "Analyst"
    ALL = ("Admin", "Auditor", "Analyst")


class Organization(Base):
    """A tenant. Every piece of customer data belongs to exactly one."""
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Framework(Base):
    """A regulatory clause, e.g. ISO 27001:2022 A.8.5.

    Deliberately NOT tenant-scoped: published standards are the same for
    everyone, so they are shared reference data rather than customer data.
    """
    __tablename__ = "frameworks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)           # e.g. "ISO 27001"
    version = Column(String)                    # e.g. "2022"
    clause_id = Column(String, index=True)      # e.g. "A.8.5"
    title = Column(String)                      # e.g. "Secure authentication"
    description = Column(String, nullable=True)

    __table_args__ = (
        Index("ix_frameworks_name_version_clause", "name", "version", "clause_id"),
    )


class Rule(Base):
    """A compliance control. Immutably versioned.

    Editing never mutates a row: a new version is inserted and the previous one
    is marked is_current=False. Historical findings therefore remain tied to the
    exact control text that produced them.
    """
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    name = Column(String, index=True, nullable=False)
    description = Column(String)
    framework = Column(String)
    framework_clause_id = Column(Integer, ForeignKey("frameworks.id"), nullable=True, index=True)
    severity = Column(String, nullable=False)
    remediation = Column(String)
    condition = Column(Text)                    # JSON-encoded condition list
    active = Column(Boolean, default=True, nullable=False)

    version = Column(Integer, default=1, nullable=False)
    parent_id = Column(Integer, ForeignKey("rules.id"), nullable=True)   # root of the version chain
    is_current = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        # The hot path: "active current rules for this org".
        Index("ix_rules_org_active_current", "organization_id", "active", "is_current"),
    )


class Scan(Base):
    """One evaluation run over one uploaded file."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    filename = Column(String)
    rows_scanned = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    # passive_deletes lets the database's ON DELETE CASCADE do the work rather
    # than SQLAlchemy loading every child row to delete it in Python.
    violations = relationship("Violation", back_populates="scan", passive_deletes=True)
    evidence = relationship("Evidence", back_populates="scan", uselist=False,
                            foreign_keys="Evidence.scan_id", passive_deletes=True)


class Evidence(Base):
    """The uploaded artifact behind a scan, hashed at ingest.

    Never discarded: a finding is only defensible if the evidence that produced
    it can be produced again and shown to be unaltered.
    """
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)

    filename = Column(String)
    content_type = Column(String, nullable=True)
    sha256 = Column(String, index=True)         # of the raw bytes as uploaded
    size_bytes = Column(Integer)
    storage_path = Column(String)
    # Encrypted at rest: the filesystem path reveals the org id and a content
    # hash, and the uploader identifies a person. Both are stored as ciphertext
    # tagged with the key that produced them.
    storage_path_encrypted = Column(Text, nullable=True)
    uploaded_by = Column(String)
    collected_at = Column(DateTime(timezone=True), default=utcnow)

    scan = relationship("Scan", back_populates="evidence", foreign_keys=[scan_id])


class Violation(Base):
    """A single evaluation result that was not a PASS.

    Two independent state fields, often confused:
      status    — the ENGINE's verdict (FAIL / ERROR / INSUFFICIENT_EVIDENCE)
      lifecycle — how the ORGANISATION is handling it (OPEN → ... → CLOSED)
    The engine owns the first; people own the second.
    """
    __tablename__ = "violations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"),
                         nullable=True, index=True)
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=True, index=True)

    server_id = Column(String, index=True)
    rule_name = Column(String)
    severity = Column(String)
    status = Column(String, default="FAIL", index=True)

    lifecycle = Column(String, default="OPEN", index=True)
    lifecycle_updated_at = Column(DateTime(timezone=True), nullable=True)
    lifecycle_updated_by = Column(String, nullable=True)

    message = Column(Text)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    scan = relationship("Scan", back_populates="violations")

    __table_args__ = (
        Index("ix_violations_org_scan", "organization_id", "scan_id"),
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)       # see Roles above
    is_active = Column(Boolean, default=True, nullable=False)


class AuditLog(Base):
    """Append-only, hash-chained record of state-changing actions.

    Each entry hashes its own content together with the previous entry's hash,
    so modifying, deleting, or reordering any entry breaks every hash after it.

    LIMITATION, stated plainly: an attacker with unrestricted write access to
    this table can recompute the whole chain and leave it internally
    consistent. Hash chaining detects ad-hoc tampering, not a full rewrite by a
    database administrator. Periodic checkpoints (see AuditCheckpoint) narrow
    that window by anchoring the head hash outside the chain itself.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    # Position in this organisation's chain. Gaps are themselves evidence.
    sequence = Column(Integer, index=True, nullable=True)

    username = Column(String)                   # actor
    action = Column(String, index=True)
    entity_type = Column(String, nullable=True, index=True)
    entity_id = Column(String, nullable=True, index=True)

    before_state = Column(Text, nullable=True)  # JSON, secrets redacted
    after_state = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    correlation_id = Column(String, nullable=True, index=True)

    details = Column(Text)                      # human-readable summary

    previous_hash = Column(String, nullable=True)
    entry_hash = Column(String, nullable=True, index=True)
    canonical_version = Column(String, nullable=True)

    timestamp = Column(DateTime(timezone=True), default=utcnow, index=True)

    __table_args__ = (
        Index("ix_audit_org_sequence", "organization_id", "sequence"),
    )


class AuditCheckpoint(Base):
    """A periodically recorded head hash.

    Anchors the chain at a point in time. If a checkpoint is also recorded
    somewhere outside this database — printed, emailed, written to an external
    log — then a full in-database rewrite becomes detectable, because the
    recomputed chain will not reproduce the checkpointed hash.
    """
    __tablename__ = "audit_checkpoints"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    sequence = Column(Integer)                  # head sequence at checkpoint time
    head_hash = Column(String)
    entries_covered = Column(Integer)
    created_by = Column(String)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class AIInteraction(Base):
    """Immutable record of every AI call.

    Every AI-derived artifact must be reconstructible: which model, which prompt
    version, what input, what came back, what it cost.
    """
    __tablename__ = "ai_interactions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    task = Column(String, index=True)
    provider = Column(String)
    model = Column(String)
    prompt_version = Column(String)

    input_ref = Column(String, nullable=True)
    input_hash = Column(String, nullable=True)
    raw_output = Column(Text, nullable=True)

    latency_ms = Column(Integer, nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)

    error = Column(Text, nullable=True)
    requested_by = Column(String)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class ScanRecord(Base):
    """One observed row from a scan — the feature snapshot for a server.

    Retained so anomaly detection fits against an organisation's HISTORY rather
    than a single uploaded batch. Batch-relative fitting made the same server
    'normal' in one file and 'anomalous' in another (audit S2-01).
    """
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    server_id = Column(String, index=True)
    features = Column(Text)                     # JSON snapshot of feature columns
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(String, nullable=True)
    detector_version = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class FindingHistory(Base):
    """Append-only record of every lifecycle change on a finding.

    Current state alone is not auditable — you must be able to show who moved a
    finding, when, and from what.
    """
    __tablename__ = "finding_history"

    id = Column(Integer, primary_key=True, index=True)
    violation_id = Column(Integer, ForeignKey("violations.id", ondelete="CASCADE"), index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    from_state = Column(String, nullable=True)
    to_state = Column(String)
    note = Column(Text, nullable=True)
    changed_by = Column(String)
    changed_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class PostureSnapshot(Base):
    """Posture at a point in time.

    The current score says where you stand; snapshots say whether you are
    improving. Tied to real evaluation runs rather than sampled arbitrarily.
    """
    __tablename__ = "posture_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True)

    score = Column(String, nullable=True)       # null when not scoreable
    controls_evaluated = Column(Integer, default=0)
    controls_passed = Column(Integer, default=0)
    controls_failed = Column(Integer, default=0)
    controls_unverified = Column(Integer, default=0)
    rubric_version = Column(String)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class RefreshToken(Base):
    """A refresh token, stored as a hash.

    The raw token is returned to the client once and never persisted: a
    database read must not yield a usable credential. Verification hashes the
    presented value and compares.

    Rotation on use is deliberate. If a token is replayed after rotation, that
    is evidence of theft — the whole family is revoked rather than the single
    token, because an attacker and the legitimate user now both hold tokens
    descended from the same original.
    """
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    token_hash = Column(String, unique=True, index=True, nullable=False)
    family_id = Column(String, index=True)      # shared across rotations

    issued_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String, nullable=True)
    replaced_by_hash = Column(String, nullable=True)

    user_agent = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_refresh_user_active", "user_id", "revoked_at"),
    )

class RetentionPolicy(Base):
    """How long a class of data is kept before becoming eligible for deletion.

    Retention is a domain concept, not a cron job: an auditor asks what the
    policy IS, who set it, and when it changed — so it is stored, versioned by
    audit trail, and enforced rather than implied by a script.
    """
    __tablename__ = "retention_policies"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    data_class = Column(String, index=True)     # e.g. "evidence", "audit_log"
    retention_days = Column(Integer)
    # Some classes must never be deleted by ordinary retention — audit history
    # in particular. Marked explicitly rather than relying on policy discipline.
    deletion_permitted = Column(Boolean, default=True, nullable=False)
    description = Column(Text, nullable=True)

    created_by = Column(String)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=True)


class LegalHold(Base):
    """A hold preventing deletion of records regardless of retention policy.

    Legal hold overrides retention, never the reverse. A record under hold
    survives its retention window because a legal obligation outranks a
    housekeeping rule.
    """
    __tablename__ = "legal_holds"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    name = Column(String)
    reason = Column(Text)
    data_class = Column(String, index=True, nullable=True)   # null = all classes
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)

    active = Column(Boolean, default=True, nullable=False, index=True)
    placed_by = Column(String)
    placed_at = Column(DateTime(timezone=True), default=utcnow)
    released_by = Column(String, nullable=True)
    released_at = Column(DateTime(timezone=True), nullable=True)