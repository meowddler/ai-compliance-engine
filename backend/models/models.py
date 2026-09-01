from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base



class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Framework(Base):
    __tablename__ = "frameworks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)          # e.g. "ISO 27001"
    version = Column(String)                    # e.g. "2022"
    clause_id = Column(String, index=True)      # e.g. "A.8.5"
    title = Column(String)                      # e.g. "Secure authentication"
    description = Column(String, nullable=True)



class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    name = Column(String, index=True)
    description = Column(String)
    framework = Column(String)
    framework_clause_id = Column(Integer, ForeignKey("frameworks.id"), nullable=True, index=True)
    severity = Column(String)
    remediation = Column(String)
    condition = Column(String)          # NEW — stores rule logic as JSON text
    active = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    parent_id = Column(Integer, ForeignKey("rules.id"), nullable=True)  # points to the original rule
    is_current = Column(Boolean, default=True)  # False once superseded by a newer version



class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)    
    filename = Column(String)
    rows_scanned = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

    # One scan can have many violations
    violations = relationship("Violation", back_populates="scan")
    evidence = relationship("Evidence", backref="scan", uselist=False, foreign_keys="Evidence.scan_id")

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)

    filename = Column(String)                       # original uploaded name
    content_type = Column(String, nullable=True)    # e.g. text/csv
    sha256 = Column(String, index=True)             # hash of the raw bytes at ingest
    size_bytes = Column(Integer)
    storage_path = Column(String)                   # where the raw file lives on disk
    uploaded_by = Column(String)                    # username
    collected_at = Column(DateTime, default=datetime.utcnow)  # when we ingested it

class Violation(Base):
    __tablename__ = "violations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)    
    scan_id = Column(Integer, ForeignKey("scans.id"))   # links back to the Scan it came from
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True, index=True)  # the exact file evaluated
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=True, index=True)         # the exact rule VERSION that fired

    server_id = Column(String, index=True)
    rule_name = Column(String)
    severity = Column(String)
    status = Column(String, default="FAIL", index=True)   # PASS/FAIL/ERROR/INSUFFICIENT_EVIDENCE
    message = Column(String)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="violations")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)   # "Admin", "Auditor", "Analyst"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    action = Column(String)          # e.g. "rule_created", "scan_run", "report_generated"
    details = Column(String)         # short human-readable description
    timestamp = Column(DateTime, default=datetime.utcnow)


class AIInteraction(Base):
    """Immutable record of every AI call.

    The roadmap's requirement: every AI call must be reconstructible later.
    Stores what was asked, what came back, which model and prompt version
    produced it, and what it cost — so any AI-derived artifact can be audited.
    """
    __tablename__ = "ai_interactions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)

    task = Column(String, index=True)          # e.g. "explain_finding"
    provider = Column(String)                  # e.g. "nvidia"
    model = Column(String)                     # exact model id
    prompt_version = Column(String)            # which prompt template version

    input_ref = Column(String, nullable=True)  # what it was about, e.g. "violation:72"
    input_hash = Column(String, nullable=True) # hash of the input, for reproducibility
    raw_output = Column(Text, nullable=True)   # exactly what the model returned

    latency_ms = Column(Integer, nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)

    error = Column(String, nullable=True)
    requested_by = Column(String)              # username
    created_at = Column(DateTime, default=datetime.utcnow)

class ScanRecord(Base):
    """One observed row from a scan — the raw feature snapshot for a server.

    Kept so anomaly detection can be fitted against an organization's HISTORY
    rather than the single uploaded batch. Batch-relative fitting made the same
    server 'normal' in one file and 'anomalous' in another (audit S2-01).
    """
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True, nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    server_id = Column(String, index=True)
    features = Column(Text)          # JSON snapshot of the feature columns
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(String, nullable=True)
    detector_version = Column(String, nullable=True)   # which model scored it
    created_at = Column(DateTime, default=datetime.utcnow)