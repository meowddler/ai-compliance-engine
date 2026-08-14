from sqlalchemy.orm import Session
from backend.models.models import AuditLog


def log_action(db: Session, username: str, action: str, details: str = ""):
    entry = AuditLog(username=username, action=action, details=details)
    db.add(entry)
    db.commit()