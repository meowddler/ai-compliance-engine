from fastapi import FastAPI, UploadFile, File, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import pandas as pd
import io
import json
from backend.core.dependencies import require_role, get_current_user
from backend.rules.rule_engine import evaluate_dataframe
from backend.ml_engine.anomaly_detector import detect_anomalies
from backend.database import get_db
from backend.models.models import Violation, Scan, Rule, User
from backend.schemas.schemas import RuleCreate, RuleUpdate
from backend.core.auth import verify_password, create_access_token
from backend.core.dependencies import require_role
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from backend.utils.report_generator import generate_compliance_report
from backend.utils.audit import log_action
from backend.config import CORS_ORIGINS
from fastapi.staticfiles import StaticFiles
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.get("/")
def read_root():
    return {"message": "Compliance engine is alive"}


@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        return {"error": "Invalid username or password"}

    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role}


@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contents = await file.read()
    df = pd.read_csv(io.BytesIO(contents))

    scan = Scan(filename=file.filename, rows_scanned=len(df))
    db.add(scan)
    db.commit()
    db.refresh(scan)

    active_rules = db.query(Rule).filter(Rule.active == True).all()
    rule_results = evaluate_dataframe(df, active_rules)

    df_with_anomalies = detect_anomalies(df)
    anomaly_map = df_with_anomalies.set_index("server_id")[["is_anomaly", "anomaly_score"]].to_dict("index")

    for result in rule_results:
        server = result["server_id"]
        is_anomaly = False
        anomaly_score = None

        if server in anomaly_map:
            is_anomaly = bool(anomaly_map[server]["is_anomaly"])
            anomaly_score = str(anomaly_map[server]["anomaly_score"])
            result["is_anomaly"] = is_anomaly
            result["anomaly_score"] = anomaly_map[server]["anomaly_score"]

        for v in result["violations"]:
            db.add(Violation(
                scan_id=scan.id,
                server_id=server,
                rule_name=v["rule"],
                severity=v["severity"],
                message=v["message"],
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score
            ))

        # Evaluation errors must be recorded, never dropped. A control that
        # could not run is surfaced as an EVALUATION_ERROR row so it is visible
        # in findings rather than silently treated as a clean pass.
        for e in result.get("errors", []):
            db.add(Violation(
                scan_id=scan.id,
                server_id=server,
                rule_name=e["rule"],
                severity="EVALUATION_ERROR",
                message=f"Could not evaluate: {e['reason']}",
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score
            ))

    db.commit()
    log_action(db, current_user.username, "scan_run", f"Scanned {file.filename} ({len(df)} rows)")
    return {"scan_id": scan.id, "filename": file.filename, "rows_scanned": len(df), "findings": rule_results}


@app.get("/violations")
def get_violations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Violation).all()


@app.get("/scans")
def get_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Scan).all()


@app.get("/rules")
def get_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Rule).all()

@app.post("/rules")
def create_rule(rule: RuleCreate, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    db_rule = Rule(
        name=rule.name,
        description=rule.description,
        framework=rule.framework,
        severity=rule.severity,
        remediation=rule.remediation,
        condition=json.dumps([c.dict() for c in rule.condition]),
        active=rule.active
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    log_action(db, current_user.username, "rule_created", f"Created rule: {db_rule.name}")
    return db_rule

@app.put("/rules/{rule_id}")
def update_rule(rule_id: int, rule: RuleUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin", "Auditor"]))):
    db_rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not db_rule:
        return {"error": "Rule not found"}

    update_data = rule.dict(exclude_unset=True)
    if "condition" in update_data:
        update_data["condition"] = json.dumps([c.dict() if hasattr(c, "dict") else c for c in rule.condition])

    for key, value in update_data.items():
        setattr(db_rule, key, value)

    db.commit()
    db.refresh(db_rule)
    return db_rule

@app.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total_scans = db.query(Scan).count()
    total_violations = db.query(Violation).count()

    high = db.query(Violation).filter(Violation.severity == "HIGH").count()
    medium = db.query(Violation).filter(Violation.severity == "MEDIUM").count()
    low = db.query(Violation).filter(Violation.severity == "LOW").count()

    anomalies = db.query(Violation).filter(Violation.is_anomaly == True).count()

    # Recent violations for a "latest findings" table
    recent = (
        db.query(Violation)
        .order_by(Violation.created_at.desc())
        .limit(10)
        .all()
    )

    return {
        "total_scans": total_scans,
        "total_violations": total_violations,
        "severity_breakdown": {"HIGH": high, "MEDIUM": medium, "LOW": low},
        "anomaly_count": anomalies,
        "recent_violations": [
            {
                "server_id": v.server_id,
                "rule_name": v.rule_name,
                "severity": v.severity,
                "is_anomaly": v.is_anomaly,
                "created_at": v.created_at.isoformat()
            }
            for v in recent
        ]
    }

@app.post("/reports/generate")
def generate_report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    summary = dashboard_summary(db, current_user)  # reuse the same logic you already built
    pdf_buffer = generate_compliance_report(summary)

    log_action(db, current_user.username, "report_generated", "Generated compliance PDF report")

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=compliance_report.pdf"}
    )


@app.get("/audit-log")
def get_audit_log(db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin", "Auditor"]))):
    from backend.models.models import AuditLog
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()


@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    db_rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not db_rule:
        return {"error": "Rule not found"}
    rule_name = db_rule.name
    db.delete(db_rule)
    db.commit()
    log_action(db, current_user.username, "rule_deleted", f"Deleted rule: {rule_name}")
    return {"message": "Rule deleted"}

@app.delete("/scans/reset")
def reset_scans(db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    db.query(Violation).delete()
    db.query(Scan).delete()
    db.commit()
    log_action(db, current_user.username, "scans_reset", "Cleared all scan history and violations")
    return {"message": "All scans and violations cleared"}


# Serve the frontend. Must be last — it catches all routes not claimed above.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")