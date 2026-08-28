from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    framework = Column(String)
    severity = Column(String)
    remediation = Column(String)
    condition = Column(String)          # NEW — stores rule logic as JSON text
    active = Column(Boolean, default=True)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    rows_scanned = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

    # One scan can have many violations
    violations = relationship("Violation", back_populates="scan")


class Violation(Base):
    __tablename__ = "violations"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))   # links back to the Scan it came from

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