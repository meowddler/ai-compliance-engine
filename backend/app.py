from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
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
        # 401, not a 200 with an error field. A failed login is not a success,
        # and the same generic message for both cases avoids revealing whether
        # a username exists (prevents user enumeration).
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username, "role": user.role, "org": user.organization_id})
    return {"access_token": token, "token_type": "bearer", "role": user.role}

def build_anomaly_map(df):
    """Map server_id -> anomaly info, tolerant of duplicate server_ids.

    A CSV can legitimately contain several rows for the same server. Using
    set_index().to_dict("index") crashes when server_id repeats
    (ValueError: index must be unique), and keeping only one row would silently
    discard data. Instead we keep the most anomalous row per server — lowest
    anomaly_score is most anomalous for IsolationForest — so a server flagged
    anomalous in ANY row is treated as anomalous rather than being let off by a
    later clean-looking duplicate.
    """
    if "server_id" not in df.columns:
        return {}

    anomaly_map = {}
    for _, r in df.iterrows():
        sid = r["server_id"]
        score = r.get("anomaly_score")
        prev = anomaly_map.get(sid)
        if prev is None or (score is not None and score < prev["anomaly_score"]):
            anomaly_map[sid] = {
                "is_anomaly": bool(r.get("is_anomaly", False)),
                "anomaly_score": score if score is not None else 0.0,
            }
    return anomaly_map


@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # --- Validate input up front, before creating anything in the DB. ---
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse file as CSV.")

    if df.empty:
        raise HTTPException(status_code=400, detail="CSV contains no rows.")
    if "server_id" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV must include a 'server_id' column.")

    # --- Do ALL processing before touching the database. ---
    # If any of this fails, we haven't created a scan record, so no ghost scan
    # can be left behind.
    try:
        active_rules = db.query(Rule).filter(Rule.active == True).all()
        rule_results = evaluate_dataframe(df, active_rules)

        df_with_anomalies = detect_anomalies(df)
        anomaly_map = build_anomaly_map(df_with_anomalies)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan processing failed: {exc}")

    # --- Persist scan + all violations as one atomic unit. ---
    # The scan row and its violations are added to the same transaction and
    # committed together at the very end. If the commit fails, rollback leaves
    # the database exactly as it was — all-or-nothing.
    try:
        scan = Scan(filename=file.filename, rows_scanned=len(df), organization_id=current_user.organization_id)
        db.add(scan)
        db.flush()  # assigns scan.id without committing yet

        for result in rule_results:
            server = result["server_id"]
            is_anomaly = False
            anomaly_score = None

            if server in anomaly_map:
                is_anomaly = bool(anomaly_map[server]["is_anomaly"])
                anomaly_score = str(anomaly_map[server]["anomaly_score"])
                result["is_anomaly"] = is_anomaly
                result["anomaly_score"] = anomaly_map[server]["anomaly_score"]

            # Record every non-PASS result with its explicit status. A PASS is
            # compliant and needs no finding row; FAIL / ERROR / INSUFFICIENT_
            # EVIDENCE each persist with the status that says what happened.
            for r in result["results"]:
                if r["status"] == "PASS":
                    continue
                db.add(Violation(
                    scan_id=scan.id,
                    organization_id=current_user.organization_id,
                    server_id=server,
                    rule_name=r["rule"],
                    severity=r["severity"],
                    status=r["status"],
                    message=r.get("message") if r["status"] == "FAIL" else r.get("reason"),
                    is_anomaly=is_anomaly,
                    anomaly_score=anomaly_score
                ))

        db.commit()
    except Exception as exc:
        db.rollback()  # no partial scan is left behind
        raise HTTPException(status_code=500, detail=f"Failed to save scan: {exc}")

    log_action(db, current_user.username, "scan_run", f"Scanned {file.filename} ({len(df)} rows)")
    return {"scan_id": scan.id, "filename": file.filename, "rows_scanned": len(df), "findings": rule_results}

@app.get("/violations")
def get_violations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Violation).filter(Violation.organization_id == current_user.organization_id).all()


@app.get("/scans")
def get_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Scan).filter(Scan.organization_id == current_user.organization_id).all()


@app.get("/rules")
def get_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Rule).filter(Rule.organization_id == current_user.organization_id).all()

@app.post("/rules")
def create_rule(rule: RuleCreate, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    db_rule = Rule(
        name=rule.name,
        organization_id=current_user.organization_id,
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

    # Record what actually changes, so the audit entry names the substance of
    # the edit rather than a bare "rule updated". Silently altering detection
    # logic is exactly the gap a compliance audit trail must close.
    changes = []
    for key, value in update_data.items():
        old_value = getattr(db_rule, key)
        if old_value != value:
            changes.append(f"{key}: {old_value!r} -> {value!r}")
            setattr(db_rule, key, value)

    db.commit()
    db.refresh(db_rule)

    if changes:
        log_action(
            db,
            current_user.username,
            "rule_updated",
            f"Updated rule '{db_rule.name}' (id={rule_id}): " + "; ".join(changes),
        )

    return db_rule

@app.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    org_id = current_user.organization_id
    total_scans = db.query(Scan).filter(Scan.organization_id == org_id).count()
    total_violations = db.query(Violation).filter(Violation.organization_id == org_id).count()

    high = db.query(Violation).filter(Violation.organization_id == org_id, Violation.severity == "HIGH").count()
    medium = db.query(Violation).filter(Violation.organization_id == org_id, Violation.severity == "MEDIUM").count()
    low = db.query(Violation).filter(Violation.organization_id == org_id, Violation.severity == "LOW").count()

    anomalies = db.query(Violation).filter(Violation.organization_id == org_id, Violation.is_anomaly == True).count()

    # Recent violations for a "latest findings" table
    recent = (
        db.query(Violation)
        .filter(Violation.organization_id == org_id)
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