from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import pandas as pd
import io
import json
import hashlib
import os
from backend.core.dependencies import require_role, get_current_user
from backend.rules.rule_engine import evaluate_dataframe
from backend.ml_engine.anomaly_detector import detect_anomalies
from backend.database import get_db
from backend.models.models import Violation, Scan, Rule, User, Framework, Evidence, ScanRecord, AuditLog,Organization
from backend.schemas.schemas import RuleCreate, RuleUpdate
from backend.core.auth import verify_password, create_access_token
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from backend.utils.report_generator import generate_compliance_report
from backend.utils.audit import log_action
from backend.config import CORS_ORIGINS, EVIDENCE_FRESHNESS_DAYS, ACCESS_TOKEN_EXPIRE_MINUTES
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timezone
from backend.ai.service import explain_finding
from pydantic import BaseModel
from backend.models.models import PostureSnapshot
from backend.core.permissions import Capability, require_capability
import anyio

TAGS_METADATA = [
    {"name": "Auth", "description": "Login and token issue."},
    {"name": "Dashboard", "description": "Compliance posture and summary metrics."},
    {"name": "Scans", "description": "Upload evidence and review scan history."},
    {"name": "Findings", "description": "Evaluation results, lifecycle workflow, and provenance."},
    {"name": "Evidence", "description": "Stored evidence and integrity verification."},
    {"name": "Rules", "description": "Compliance controls and framework clauses."},
    {"name": "AI", "description": "Explanations and drafted controls. AI proposes; the deterministic engine decides."},
    {"name": "Reports", "description": "Generated compliance reports."},
    {"name": "Audit", "description": "Append-only audit trail."},
    {"name": "System", "description": "Health and service information."},
]

app = FastAPI(
    title="AI Compliance Engine",
    description="Evidence-driven compliance evaluation with deterministic controls and an AI assistance layer.",
    version="0.4.0",
    openapi_tags=TAGS_METADATA,
)

def evidence_freshness(collected_at):
    """Classify evidence age. Stale evidence should not count as current proof
    of compliance — a control relying on it degrades to INSUFFICIENT_EVIDENCE."""
    if collected_at is None:
        return {"state": "UNKNOWN", "age_days": None}
    age_days = (datetime.now(timezone.utc) - collected_at).days
    state = "FRESH" if age_days <= EVIDENCE_FRESHNESS_DAYS else "STALE"
    return {"state": state, "age_days": age_days, "threshold_days": EVIDENCE_FRESHNESS_DAYS}

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.get("/", tags=["System"])
def read_root():
    return {"message": "Compliance engine is alive"}


@app.post("/auth/login", tags=["Auth"])
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        # 401, not a 200 with an error field, and the same message for both
        # cases so an attacker cannot learn which usernames exist.
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.is_active is False:
        raise HTTPException(status_code=403, detail="Account is disabled")

    from backend.core.tokens import issue_refresh_token

    token = create_access_token({"sub": user.username, "role": user.role,
                                 "org": user.organization_id})
    raw_refresh, _ = issue_refresh_token(
        db, user,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    log_action(db, user.username, "login_success", "Successful login",
               organization_id=user.organization_id,
               entity_type="User", entity_id=user.id)
    db.commit()

    return {"access_token": token, "token_type": "bearer", "role": user.role,
            "refresh_token": raw_refresh,
            "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES}

def build_anomaly_map(df):
    """Map server_id -> anomaly info, tolerant of duplicate server_ids.

    A CSV can legitimately contain several rows for the same server. Using
    set_index().to_dict("index") crashes when server_id repeats, and keeping
    only one row would silently discard data. We keep the most anomalous row
    per server — lowest score is most anomalous for IsolationForest — so a
    server flagged in ANY row is treated as anomalous rather than excused by a
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

def _write_evidence(path: str, data: bytes) -> None:
    """Persist raw evidence bytes. Separated so it can be run off the event loop."""
    with open(path, "wb") as fh:
        fh.write(data)

@app.post("/upload-logs", tags=["Scans"])
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

    # --- Evidence: hash the raw bytes and persist the file before evaluation. ---
    # The hash is computed on exactly what was uploaded, so any later tampering
    # with the stored file is detectable. Evidence is never discarded.
    sha256 = hashlib.sha256(contents).hexdigest()
    evidence_dir = os.path.join("evidence_store", str(current_user.organization_id))
    os.makedirs(evidence_dir, exist_ok=True)
    storage_path = os.path.join(evidence_dir, f"{sha256}_{file.filename}")
    # Written off the event loop. A blocking write inside an async handler
    # stalls every other request for its duration — unnoticeable on a 200-byte
    # CSV, material on a large upload.
    await anyio.to_thread.run_sync(lambda: _write_evidence(storage_path, contents))
    # --- Do ALL processing before touching the database. ---
    # If any of this fails, we haven't created a scan record, so no ghost scan
    # can be left behind.
    try:
        # Org filter is essential: without it a scan would be evaluated against
        # every tenant's rules, leaking one organisation's detection logic into
        # another's results.
        active_rules = db.query(Rule).filter(
            Rule.organization_id == current_user.organization_id,
            Rule.active == True,
            Rule.is_current == True,
        ).all()
        rule_results = evaluate_dataframe(df, active_rules)
        # name -> exact rule id (this version), so each finding pins the rule
        # version that actually produced it, for later reproducibility.
        rule_id_by_name = {r.name: r.id for r in active_rules}

        # Baseline = this organization's historical observations, not this batch.
        history_rows = db.query(ScanRecord).filter(
            ScanRecord.organization_id == current_user.organization_id
        ).all()
        history_df = pd.DataFrame([json.loads(r.features) for r in history_rows]) if history_rows else None

        df_with_anomalies, anomaly_meta = detect_anomalies(df, history_df)
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

        from backend.utils.encryption import encrypt
        evidence = Evidence(
            organization_id=current_user.organization_id,
            scan_id=scan.id,
            filename=file.filename,
            content_type=file.content_type,
            sha256=sha256,
            size_bytes=len(contents),
            storage_path=storage_path,
            # Also stored encrypted: a database dump then reveals ciphertext
            # rather than a path disclosing org id and content hash.
            storage_path_encrypted=encrypt(storage_path),
            uploaded_by=current_user.username,
        )
        db.add(evidence)
        db.flush()   # assign evidence.id so violations can reference it
        # Persist each observed row so future scans have a baseline to fit on.
        from backend.ml_engine.anomaly_detector import extract_features, DETECTOR_VERSION
        for _, raw_row in df_with_anomalies.iterrows():
            db.add(ScanRecord(
                organization_id=current_user.organization_id,
                scan_id=scan.id,
                server_id=str(raw_row.get("server_id", "unknown")),
                features=json.dumps(extract_features(raw_row), default=str),
                is_anomaly=bool(raw_row.get("is_anomaly", False)),
                anomaly_score=str(raw_row.get("anomaly_score")) if raw_row.get("anomaly_score") is not None else None,
                detector_version=DETECTOR_VERSION,
            ))

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
                    evidence_id=evidence.id,
                    rule_id=rule_id_by_name.get(r["rule"]),
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

    # Record posture at this point in time so trends are tied to real
    # evaluation runs rather than sampled arbitrarily.
    try:
        from backend.utils.posture import compute_posture
        from backend.models.models import PostureSnapshot

        flat_results = [r for res in rule_results for r in res["results"]]
        snap = compute_posture(flat_results)
        db.add(PostureSnapshot(
            organization_id=current_user.organization_id,
            scan_id=scan.id,
            score=str(snap["score"]) if snap["score"] is not None else None,
            controls_evaluated=snap["controls_evaluated"],
            controls_passed=snap["controls_passed"],
            controls_failed=snap["controls_failed"],
            controls_unverified=snap["controls_unverified"],
            rubric_version=snap["rubric_version"],
        ))
        db.commit()
    except Exception:
        db.rollback()   # a snapshot failure must never fail the scan itself

    log_action(db, current_user.username, "scan_run",
               f"Scanned {file.filename} ({len(df)} rows)",
               organization_id=current_user.organization_id,
               entity_type="Scan", entity_id=scan.id,
               after={"scan_id": scan.id, "filename": file.filename,
                      "rows_scanned": len(df), "evidence_sha256": sha256})
    db.commit()
    return {"scan_id": scan.id, "filename": file.filename, "rows_scanned": len(df),
            "anomaly_detection": anomaly_meta, "findings": rule_results}

class DraftControlRequest(BaseModel):
    requirement: str


@app.post("/ai/draft-control", tags=["AI"])
def ai_draft_control(req: DraftControlRequest, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    from backend.ai.service import draft_control
    available = ["server_id", "port", "port_exposed", "mfa_enabled", "last_login_days", "failed_logins"]
    return draft_control(db, requirement_text=req.requirement, available_fields=available, current_user=current_user)

class ApproveDraftRequest(BaseModel):
    name: str
    description: str
    framework: str
    severity: str
    remediation: str
    condition: list
    interaction_id: int | None = None


@app.post("/ai/approve-draft", tags=["AI"])
def approve_draft(req: ApproveDraftRequest, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    """Turn a reviewed AI draft into a real control.

    The AI never reaches this point on its own — a human explicitly approves,
    and the approval is audit-logged with the AI interaction it came from.
    """
    db_rule = Rule(
        name=req.name,
        organization_id=current_user.organization_id,
        description=req.description,
        framework=req.framework,
        severity=req.severity,
        remediation=req.remediation,
        condition=json.dumps(req.condition),
        active=True,
        version=1,
        is_current=True,
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)

    log_action(
        db, current_user.username, "rule_created_from_ai_draft",
        f"Approved AI-drafted control '{db_rule.name}' (ai_interaction={req.interaction_id})",
        organization_id=current_user.organization_id,
    )
    db.commit()
    return db_rule

@app.post("/violations/{violation_id}/explain", tags=["AI"])
def explain_violation(violation_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    v = db.query(Violation).filter(
        Violation.id == violation_id,
        Violation.organization_id == current_user.organization_id
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Finding not found")

    rule = db.query(Rule).filter(Rule.id == v.rule_id).first() if v.rule_id else None
    evidence = db.query(Evidence).filter(Evidence.id == v.evidence_id).first() if v.evidence_id else None

    return explain_finding(db, violation=v, rule=rule, evidence=evidence, current_user=current_user)

@app.get("/violations", tags=["Findings"])
def get_violations(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Violation).filter(Violation.organization_id == current_user.organization_id).all()


class LifecycleUpdateRequest(BaseModel):
    to_state: str
    note: str | None = None


@app.post("/violations/{violation_id}/lifecycle", tags=["Findings"])
def update_finding_lifecycle(violation_id: int, req: LifecycleUpdateRequest,
                             db: Session = Depends(get_db),
                             current_user: User = Depends(get_current_user)):
    """Move a finding through its lifecycle. Every change is recorded."""
    from backend.utils.lifecycle import validate_transition, InvalidTransition, allowed_next
    from backend.models.models import FindingHistory

    v = db.query(Violation).filter(
        Violation.id == violation_id,
        Violation.organization_id == current_user.organization_id
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Finding not found")

    current_state = v.lifecycle or "OPEN"
    try:
        validate_transition(current_state, req.to_state)
    except InvalidTransition as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    from backend.utils.audit import snapshot_finding
    before_snapshot = snapshot_finding(v)    

    db.add(FindingHistory(
        violation_id=v.id,
        organization_id=current_user.organization_id,
        from_state=current_state,
        to_state=req.to_state,
        note=req.note,
        changed_by=current_user.username,
    ))
    v.lifecycle = req.to_state
    v.lifecycle_updated_at = datetime.now(timezone.utc)
    v.lifecycle_updated_by = current_user.username
    db.commit()

    log_action(db, current_user.username, "finding_lifecycle_changed",
               f"Finding #{v.id}: {current_state} -> {req.to_state}"
               + (f" ({req.note})" if req.note else ""),
               organization_id=current_user.organization_id,
               entity_type="Finding", entity_id=v.id,
               before=before_snapshot, after=snapshot_finding(v),
               reason=req.note)
    db.commit()

    return {"violation_id": v.id, "lifecycle": v.lifecycle,
            "allowed_next": allowed_next(v.lifecycle),
            "updated_by": v.lifecycle_updated_by}


@app.get("/violations/{violation_id}/history", tags=["Findings"])
def get_finding_history(violation_id: int, db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    """Full lifecycle history for a finding — append-only, never rewritten."""
    from backend.models.models import FindingHistory
    from backend.utils.lifecycle import allowed_next

    v = db.query(Violation).filter(
        Violation.id == violation_id,
        Violation.organization_id == current_user.organization_id
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Finding not found")

    rows = db.query(FindingHistory).filter(
        FindingHistory.violation_id == violation_id
    ).order_by(FindingHistory.changed_at.asc()).all()

    return {
        "violation_id": v.id,
        "current_lifecycle": v.lifecycle or "OPEN",
        "allowed_next": allowed_next(v.lifecycle),
        "history": [
            {"from": h.from_state, "to": h.to_state, "note": h.note,
             "by": h.changed_by, "at": h.changed_at.isoformat() if h.changed_at else None}
            for h in rows
        ],
    }


@app.get("/violations/{violation_id}/provenance", tags=["Findings"])
def get_violation_provenance(violation_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    v = db.query(Violation).filter(
        Violation.id == violation_id,
        Violation.organization_id == current_user.organization_id
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Finding not found")

    ev = db.query(Evidence).filter(Evidence.id == v.evidence_id).first() if v.evidence_id else None
    rule = db.query(Rule).filter(Rule.id == v.rule_id).first() if v.rule_id else None

    return {
        "finding": {
            "id": v.id,
            "server_id": v.server_id,
            "status": v.status,
            "severity": v.severity,
            "message": v.message,
            "detected_at": v.created_at.isoformat() if v.created_at else None,
        },
        "evidence": {
            "id": ev.id,
            "filename": ev.filename,
            "sha256": ev.sha256,
            "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
            "uploaded_by": ev.uploaded_by,
        } if ev else None,
        "control": {
            "rule_id": rule.id,
            "name": rule.name,
            "version": rule.version,
            "condition": rule.condition,
            "is_current": rule.is_current,
        } if rule else None,
        "reproducible": bool(ev and rule),
    }


@app.get("/scans", tags=["Scans"])
def get_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Scan).filter(Scan.organization_id == current_user.organization_id).all()

@app.get("/scans/{scan_id}/evidence", tags=["Evidence"])
def get_scan_evidence(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ev = db.query(Evidence).filter(
        Evidence.scan_id == scan_id,
        Evidence.organization_id == current_user.organization_id
    ).first()
    if not ev:
        return None
    return {
        "id": ev.id,
        "filename": ev.filename,
        "sha256": ev.sha256,
        "size_bytes": ev.size_bytes,
        "uploaded_by": ev.uploaded_by,
        "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
        "freshness": evidence_freshness(ev.collected_at),
    }


@app.get("/rules", tags=["Rules"])
def get_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Rule).filter(
        Rule.organization_id == current_user.organization_id,
        Rule.is_current == True
    ).all()

@app.get("/frameworks", tags=["Rules"])
def get_frameworks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    frameworks = db.query(Framework).order_by(Framework.name, Framework.clause_id).all()
    return [
        {
            "id": f.id,
            "name": f.name,
            "version": f.version,
            "clause_id": f.clause_id,
            "title": f.title,
            "label": f"{f.name}:{f.version} {f.clause_id} — {f.title}",
        }
        for f in frameworks
    ]

@app.get("/evidence/{evidence_id}/verify", tags=["Evidence"])
def verify_evidence(evidence_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ev = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.organization_id == current_user.organization_id
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    if not os.path.exists(ev.storage_path):
        return {"evidence_id": ev.id, "status": "MISSING", "detail": "Stored file not found on disk."}

    with open(ev.storage_path, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()

    intact = (current_hash == ev.sha256)
    return {
        "evidence_id": ev.id,
        "filename": ev.filename,
        "status": "INTACT" if intact else "TAMPERED",
        "recorded_sha256": ev.sha256,
        "current_sha256": current_hash,
    }


@app.post("/rules", tags=["Rules"])
def create_rule(rule: RuleCreate, db: Session = Depends(get_db), current_user: User = Depends(require_capability(Capability.CONTROLS_CREATE))):
    db_rule = Rule(
        name=rule.name,
        organization_id=current_user.organization_id,
        description=rule.description,
        framework=rule.framework,
        severity=rule.severity,
        remediation=rule.remediation,
        # condition is validated plain data (leaf, tree, or legacy list), not
        # a list of models — dump it directly.
        condition=json.dumps(rule.condition),
        active=rule.active
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    from backend.utils.audit import snapshot_rule
    log_action(db, current_user.username, "rule_created",
               f"Created rule: {db_rule.name}",
               organization_id=current_user.organization_id,
               entity_type="Rule", entity_id=db_rule.id,
               after=snapshot_rule(db_rule))
    db.commit()
    return db_rule


@app.put("/rules/{rule_id}", tags=["Rules"])
def update_rule(rule_id: int, rule: RuleUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin", "Auditor"]))):
    db_rule = db.query(Rule).filter(
        Rule.id == rule_id,
        Rule.organization_id == current_user.organization_id
    ).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_data = rule.dict(exclude_unset=True)
    if "condition" in update_data:
        update_data["condition"] = json.dumps(rule.condition)

    # Detect what actually changes.
    changes = []
    for key, value in update_data.items():
        if getattr(db_rule, key) != value:
            changes.append(f"{key}: {getattr(db_rule, key)!r} -> {value!r}")

    if not changes:
        return db_rule  # nothing changed, no new version

    # Immutable versioning: the old version is never mutated. We retire it and
    # create a new version carrying the edits. Historical findings that point to
    # the old version remain reproducible against exactly what was evaluated.
    from backend.utils.audit import snapshot_rule
    # Captured before mutation — an after-the-fact snapshot would record the
    # new state twice and prove nothing.
    before_snapshot = snapshot_rule(db_rule)

    root_id = db_rule.parent_id or db_rule.id  # all versions share the original's id as root
    db_rule.is_current = False

    new_rule = Rule(
        name=db_rule.name,
        organization_id=db_rule.organization_id,
        description=update_data.get("description", db_rule.description),
        framework=update_data.get("framework", db_rule.framework),
        severity=update_data.get("severity", db_rule.severity),
        remediation=update_data.get("remediation", db_rule.remediation),
        condition=update_data.get("condition", db_rule.condition),
        active=update_data.get("active", db_rule.active),
        version=db_rule.version + 1,
        parent_id=root_id,
        is_current=True,
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)

    log_action(
        db,
        current_user.username,
        "rule_updated",
        f"Rule '{new_rule.name}' -> v{new_rule.version} (id={new_rule.id}): " + "; ".join(changes),
        organization_id=current_user.organization_id,
        entity_type="Rule", entity_id=new_rule.id,
        before=before_snapshot, after=snapshot_rule(new_rule),
        reason="; ".join(changes),
    )
    db.commit()

    return new_rule


@app.get("/dashboard/summary", tags=["Dashboard"])
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

    # Posture is scoped to the LATEST scan: it reflects current standing, not a
    # sum over history. Re-scanning unchanged evidence yields the same score,
    # and remediation improves it.
    from backend.utils.posture import compute_posture
    latest_scan = db.query(Scan).filter(Scan.organization_id == org_id).order_by(Scan.id.desc()).first()
    if latest_scan:
        latest_findings = db.query(Violation).filter(
            Violation.organization_id == org_id,
            Violation.scan_id == latest_scan.id
        ).all()
        # Findings only record non-PASS results, so passes are inferred from
        # the number of evaluations that produced no finding.
        records = db.query(ScanRecord).filter(ScanRecord.scan_id == latest_scan.id).count()
        active_rule_count = db.query(Rule).filter(
            Rule.organization_id == org_id, Rule.active == True, Rule.is_current == True
        ).count()
        total_evaluations = records * active_rule_count
        non_pass = [{"status": v.status or "FAIL", "severity": v.severity} for v in latest_findings]
        passes = max(0, total_evaluations - len(non_pass))
        results_for_posture = non_pass + [{"status": "PASS", "severity": "MEDIUM"}] * passes
        posture = compute_posture(results_for_posture)
    else:
        posture = compute_posture([])

    return {
        "posture": posture,
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

@app.get("/dashboard/posture-history", tags=["Dashboard"])
def posture_history(limit: int = 30, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    """Posture over time — the trend behind the current score."""
    from backend.models.models import PostureSnapshot

    rows = (db.query(PostureSnapshot)
              .filter(PostureSnapshot.organization_id == current_user.organization_id)
              .order_by(PostureSnapshot.created_at.desc())
              .limit(limit).all())
    rows = list(reversed(rows))   # oldest first, for charting

    return {
        "points": [
            {
                "scan_id": r.scan_id,
                "score": float(r.score) if r.score is not None else None,
                "controls_evaluated": r.controls_evaluated,
                "controls_passed": r.controls_passed,
                "controls_failed": r.controls_failed,
                "controls_unverified": r.controls_unverified,
                "at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "rubric_version": rows[-1].rubric_version if rows else None,
    }


@app.post("/reports/generate", tags=["Reports"])
def generate_report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    summary = dashboard_summary(db, current_user)  # reuse the same logic you already built
    org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
    pdf_buffer = generate_compliance_report(summary, organization_name=org.name if org else None)

    log_action(db, current_user.username, "report_generated",
               "Generated compliance PDF report",
               organization_id=current_user.organization_id)
    db.commit()

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=compliance_report.pdf"}
    )


@app.get("/audit-log", tags=["Audit"])
def get_audit_log(db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin", "Auditor"]))):
    # Tenant-scoped: an auditor must never see another organisation's activity.
    return (db.query(AuditLog)
              .filter(AuditLog.organization_id == current_user.organization_id)
              .order_by(AuditLog.timestamp.desc())
              .limit(500)
              .all())


@app.delete("/rules/{rule_id}", tags=["Rules"])
def delete_rule(rule_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(require_capability(Capability.CONTROLS_DELETE))):
    """Retire a control, or delete it if it has never produced a finding.

    A control that has produced findings is NOT removed. Deleting it would
    orphan every finding that cites it and destroy the traceability the audit
    trail depends on — you could no longer show which control version produced
    a historical result. Such controls are retired instead: deactivated and
    marked non-current, so they stop evaluating but remain citable.
    """
    from backend.utils.audit import snapshot_rule

    db_rule = db.query(Rule).filter(
        Rule.id == rule_id,
        Rule.organization_id == current_user.organization_id,
    ).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule_name = db_rule.name
    before_snapshot = snapshot_rule(db_rule)

    referencing = db.query(Violation).filter(Violation.rule_id == rule_id).count()

    if referencing:
        db_rule.active = False
        db_rule.is_current = False
        db.commit()
        log_action(db, current_user.username, "rule_retired",
                   f"Retired rule '{rule_name}' ({referencing} finding(s) reference it)",
                   organization_id=current_user.organization_id,
                   entity_type="Rule", entity_id=rule_id,
                   before=before_snapshot, after=snapshot_rule(db_rule),
                   reason="Referenced by existing findings; retained for traceability.")
        db.commit()
        return {
            "message": f"Rule retired rather than deleted: {referencing} finding(s) reference it.",
            "action": "retired",
            "referencing_findings": referencing,
        }

    db.delete(db_rule)
    db.commit()
    log_action(db, current_user.username, "rule_deleted",
               f"Deleted rule: {rule_name}",
               organization_id=current_user.organization_id,
               entity_type="Rule", entity_id=rule_id,
               before=before_snapshot)
    db.commit()
    return {"message": "Rule deleted", "action": "deleted"}

@app.delete("/scans/reset", tags=["Scans"])
def reset_scans(db: Session = Depends(get_db), current_user: User = Depends(require_role(["Admin"]))):
    # Scoped to the caller's organisation — an admin must never be able to
    # destroy another tenant's data. Deleted in FK dependency order: children
    # (history, findings, records, evidence) before parents (scans).
    from backend.models.models import FindingHistory
    org_id = current_user.organization_id

    finding_ids = [v.id for v in db.query(Violation).filter(Violation.organization_id == org_id).all()]
    if finding_ids:
        db.query(FindingHistory).filter(FindingHistory.violation_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(Violation).filter(Violation.organization_id == org_id).delete(synchronize_session=False)
    db.query(PostureSnapshot).filter(PostureSnapshot.organization_id == org_id).delete(synchronize_session=False)
    db.query(ScanRecord).filter(ScanRecord.organization_id == org_id).delete(synchronize_session=False)
    db.query(Evidence).filter(Evidence.organization_id == org_id).delete(synchronize_session=False)
    db.query(Scan).filter(Scan.organization_id == org_id).delete(synchronize_session=False)
    db.commit()
    log_action(db, current_user.username, "scans_reset",
               "Cleared all scan history, evidence, and violations",
               organization_id=current_user.organization_id)
    db.commit()
    return {"message": "All scans, evidence, and violations cleared"}



@app.post("/maintenance/refresh-staleness", tags=["Scans"])
def refresh_staleness(dry_run: bool = True, db: Session = Depends(get_db),
                      current_user: User = Depends(require_role(["Admin", "Auditor"]))):
    """Degrade findings whose evidence has aged past its validity window.

    Stale evidence cannot support a verdict, so affected findings move to
    INSUFFICIENT_EVIDENCE — never silently remaining PASS. Runs as an explicit
    maintenance action now; Phase 5's scheduler will invoke the same logic.

    dry_run=True reports what WOULD change without writing anything.
    """
    from backend.utils.freshness import evaluate_staleness
    from backend.models.models import FindingHistory

    org_id = current_user.organization_id

    rows = (db.query(Violation, Evidence)
              .outerjoin(Evidence, Violation.evidence_id == Evidence.id)
              .filter(Violation.organization_id == org_id).all())

    class _F:
        pass
    candidates = []
    for v, ev in rows:
        f = _F()
        f.id = v.id
        f.status = v.status
        f.evidence_collected_at = ev.collected_at if ev else None
        candidates.append(f)

    decisions = evaluate_staleness(candidates, EVIDENCE_FRESHNESS_DAYS)

    if not dry_run and decisions:
        by_id = {v.id: v for v, _ in rows}
        for d in decisions:
            v = by_id.get(d["finding_id"])
            if not v:
                continue
            v.status = d["to_status"]
            v.message = d["reason"]
            db.add(FindingHistory(
                violation_id=v.id,
                organization_id=org_id,
                from_state=f"status:{d['from_status']}",
                to_state=f"status:{d['to_status']}",
                note=d["reason"],
                changed_by="system:freshness-monitor",
            ))
        db.commit()
        log_action(db, current_user.username, "staleness_refresh",
                   f"Degraded {len(decisions)} finding(s) due to stale evidence",
                   organization_id=current_user.organization_id)
        db.commit()

    return {
        "dry_run": dry_run,
        "freshness_window_days": EVIDENCE_FRESHNESS_DAYS,
        "findings_checked": len(candidates),
        "degraded_count": len(decisions),
        "degraded": decisions[:50],
    }
@app.get("/dashboard/changes", tags=["Dashboard"])
def posture_changes(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Diff the two most recent scans: what newly failed, newly passed, or became unverifiable.

    A posture score tells you where you stand; this tells you what MOVED. It is
    the difference between monitoring and merely measuring.
    """
    org_id = current_user.organization_id

    scans = (db.query(Scan).filter(Scan.organization_id == org_id)
               .order_by(Scan.id.desc()).limit(2).all())
    if len(scans) < 2:
        return {"comparable": False,
                "reason": "At least two scans are required to detect change.",
                "scans_available": len(scans)}

    current_scan, previous_scan = scans[0], scans[1]

    def status_map(scan_id):
        """server_id + rule_name -> status, for one scan."""
        rows = db.query(Violation).filter(
            Violation.organization_id == org_id,
            Violation.scan_id == scan_id
        ).all()
        return {(r.server_id, r.rule_name): (r.status or "FAIL") for r in rows}

    cur, prev = status_map(current_scan.id), status_map(previous_scan.id)

    newly_failing, newly_resolved, newly_unverified, newly_observed = [], [], [], []

    prev_servers = {k[0] for k in prev.keys()}

    for key, status in cur.items():
        was = prev.get(key)
        # A server absent from the previous scan was not "passing" — it was
        # simply not observed. Reporting it as a regression would be false.
        if key[0] not in prev_servers:
            newly_observed.append({"server_id": key[0], "rule": key[1], "status": status})
            continue
        if status == "FAIL" and was != "FAIL":
            newly_failing.append({"server_id": key[0], "rule": key[1], "was": was or "PASS"})
        elif status in ("INSUFFICIENT_EVIDENCE", "ERROR") and was not in ("INSUFFICIENT_EVIDENCE", "ERROR"):
            newly_unverified.append({"server_id": key[0], "rule": key[1], "was": was or "PASS", "now": status})

    # Present in the previous scan but no longer a finding => it now passes.
    cur_servers = {k[0] for k in cur.keys()}
    for key, was in prev.items():
        # Only a server still being observed can be said to have improved.
        if key[0] in cur_servers and key not in cur and was in ("FAIL", "INSUFFICIENT_EVIDENCE", "ERROR"):
            newly_resolved.append({"server_id": key[0], "rule": key[1], "was": was})

    return {
        "comparable": True,
        "current_scan": {"id": current_scan.id, "filename": current_scan.filename,
                         "at": current_scan.created_at.isoformat() if current_scan.created_at else None},
        "previous_scan": {"id": previous_scan.id, "filename": previous_scan.filename,
                          "at": previous_scan.created_at.isoformat() if previous_scan.created_at else None},
        "newly_failing": newly_failing,
        "newly_resolved": newly_resolved,
        "newly_unverified": newly_unverified,
        "newly_observed": newly_observed,
        "summary": {
            "newly_failing": len(newly_failing),
            "newly_resolved": len(newly_resolved),
            "newly_unverified": len(newly_unverified),
            "newly_observed": len(newly_observed),
        },
    }

@app.get("/audit/verify", tags=["Audit"])
def verify_audit_chain(db: Session = Depends(get_db), current_user: User = Depends(require_capability(Capability.AUDIT_VERIFY))):
    """Verify the integrity of this organisation's audit chain.

    Reports the first break and where it occurred. A broken chain is a finding
    to surface, not an error — so this returns 200 with valid=false rather than
    raising.
    """
    from backend.utils.audit import chained_entries, chain_stats
    from backend.utils.audit_chain import verify_chain

    org_id = current_user.organization_id
    result = verify_chain(chained_entries(db, org_id))
    stats = chain_stats(db, org_id)

    return {
        **result,
        **stats,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "verified_by": current_user.username,
        "note": (
            "Hash chaining detects modified, deleted, reordered, or inserted "
            "entries. It cannot detect a full rewrite by an actor with "
            "unrestricted database write access; checkpoints anchored outside "
            "this database are required for that."
        ),
    }


@app.post("/audit/checkpoint", tags=["Audit"])
def create_audit_checkpoint(db: Session = Depends(get_db),
                            current_user: User = Depends(require_role(["Admin", "Auditor"]))):
    """Record the current head hash as a checkpoint.

    Recording this value somewhere outside the database — an external log, a
    printed report — is what makes a wholesale rewrite detectable.
    """
    from backend.models.models import AuditCheckpoint
    from backend.utils.audit import chained_entries
    from backend.utils.audit_chain import verify_chain

    org_id = current_user.organization_id
    entries = chained_entries(db, org_id)
    result = verify_chain(entries)

    if not result["valid"]:
        # Checkpointing a broken chain would certify tampering as legitimate.
        raise HTTPException(
            status_code=409,
            detail=f"Refusing to checkpoint: chain is invalid ({result['reason']} "
                   f"at sequence {result.get('sequence')}). Investigate before checkpointing."
        )

    checkpoint = AuditCheckpoint(
        organization_id=org_id,
        sequence=entries[-1].sequence if entries else 0,
        head_hash=result["head_hash"],
        entries_covered=result["entries_verified"],
        created_by=current_user.username,
    )
    db.add(checkpoint)
    db.commit()
    db.refresh(checkpoint)

    return {
        "checkpoint_id": checkpoint.id,
        "sequence": checkpoint.sequence,
        "head_hash": checkpoint.head_hash,
        "entries_covered": checkpoint.entries_covered,
        "created_at": checkpoint.created_at.isoformat(),
        "instruction": ("Record this head_hash outside the system. A rewrite of the "
                        "chain will not reproduce it."),
    }


@app.get("/violations/{violation_id}/traceability", tags=["Audit"])
def finding_traceability(violation_id: int, db: Session = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    """Answer the eleven auditability questions for one finding.

    Each answer carries the data it was derived from, so a reviewer can check
    the reasoning rather than trust the summary.
    """
    from backend.models.models import AuditLog, FindingHistory

    v = db.query(Violation).filter(
        Violation.id == violation_id,
        Violation.organization_id == current_user.organization_id
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Finding not found")

    rule = db.query(Rule).filter(Rule.id == v.rule_id).first() if v.rule_id else None
    evidence = db.query(Evidence).filter(Evidence.id == v.evidence_id).first() if v.evidence_id else None
    scan = db.query(Scan).filter(Scan.id == v.scan_id).first() if v.scan_id else None

    clause = None
    if rule and rule.framework_clause_id:
        clause = db.query(Framework).filter(Framework.id == rule.framework_clause_id).first()

    history = (db.query(FindingHistory)
                 .filter(FindingHistory.violation_id == v.id)
                 .order_by(FindingHistory.changed_at.asc()).all())

    audit_events = (db.query(AuditLog)
                      .filter(AuditLog.organization_id == current_user.organization_id,
                              AuditLog.entity_type == "Finding",
                              AuditLog.entity_id == str(v.id))
                      .order_by(AuditLog.timestamp.asc()).all())

    def answered(value):
        return {"answered": value is not None and value != "", "value": value}

    return {
        "finding_id": v.id,
        "questions": {
            "1_what_requirement_caused_this": answered(
                f"{clause.name}:{clause.version} {clause.clause_id} — {clause.title}"
                if clause else (rule.framework if rule else None)
            ),
            "2_which_control_version_was_evaluated": answered(
                {"rule_id": rule.id, "name": rule.name, "version": rule.version,
                 "condition": rule.condition, "is_current": rule.is_current}
                if rule else None
            ),
            "3_what_evidence_was_used": answered(
                {"evidence_id": evidence.id, "filename": evidence.filename,
                 "sha256": evidence.sha256, "size_bytes": evidence.size_bytes}
                if evidence else None
            ),
            "4_when_was_evidence_collected": answered(
                evidence.collected_at.isoformat() if evidence and evidence.collected_at else None
            ),
            "5_which_evaluator_and_version": answered(
                {"evaluator": "deterministic_rule_engine",
                 "control_version": rule.version if rule else None,
                 "anomaly_detector": v.anomaly_score is not None}
            ),
            "6_what_reasoning_produced_the_result": answered(v.message),
            "7_what_confidence_exists": answered(
                {"basis": "deterministic",
                 "note": ("Status assigned by rule evaluation, not estimation. "
                          "Anomaly score is advisory and does not affect status."),
                 "anomaly_score": v.anomaly_score,
                 "is_anomaly": v.is_anomaly}
            ),
            "8_why_was_this_status_assigned": answered(
                {"status": v.status, "reason": v.message}
            ),
            "9_who_changed_the_result_and_when": answered([
                {"from": h.from_state, "to": h.to_state, "by": h.changed_by,
                 "at": h.changed_at.isoformat() if h.changed_at else None,
                 "note": h.note}
                for h in history
            ] or None),
            "10_which_framework_version_applied": answered(
                {"framework": clause.name, "version": clause.version,
                 "clause": clause.clause_id} if clause
                else ({"framework": rule.framework, "version": None,
                       "clause": None} if rule else None)
            ),
            "11_is_the_audit_trail_tamper_evident": answered(
                {"hash_chained": True,
                 "verify_endpoint": "/audit/verify",
                 "related_audit_events": len(audit_events)}
            ),
        },
        "chain": {
            "finding": {"id": v.id, "server_id": v.server_id, "status": v.status,
                        "severity": v.severity, "lifecycle": v.lifecycle,
                        "detected_at": v.created_at.isoformat() if v.created_at else None},
            "scan": {"id": scan.id, "filename": scan.filename,
                     "at": scan.created_at.isoformat() if scan and scan.created_at else None} if scan else None,
            "evidence": {"id": evidence.id, "sha256": evidence.sha256,
                         "uploaded_by": evidence.uploaded_by} if evidence else None,
            "control": {"id": rule.id, "name": rule.name, "version": rule.version} if rule else None,
            "clause": {"framework": clause.name, "version": clause.version,
                       "clause_id": clause.clause_id, "title": clause.title} if clause else None,
        },
        "audit_events": [
            {"action": a.action, "by": a.username,
             "at": a.timestamp.isoformat() if a.timestamp else None,
             "sequence": a.sequence}
            for a in audit_events
        ],
        "reproducible": bool(evidence and rule),
    }

class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/refresh", tags=["Auth"])
def refresh_access_token(req: RefreshRequest, request: Request,
                         db: Session = Depends(get_db)):
    """Exchange a refresh token for a new access token, rotating the refresh token."""
    from backend.core.tokens import consume_refresh_token, issue_refresh_token

    result = consume_refresh_token(db, req.refresh_token)

    if not result.ok:
        if result.replay:
            # Reuse of a rotated token means it was stolen or replayed. The
            # family is already revoked; record it as a security event.
            log_action(db, "system", "refresh_token_replay_detected",
                       "A revoked refresh token was presented; token family revoked.",
                       organization_id=result.record.organization_id if result.record else None,
                       entity_type="RefreshToken",
                       entity_id=result.record.id if result.record else None,
                       reason="Possible token theft.")
        db.commit()
        raise HTTPException(status_code=401, detail=result.error)

    user = result.user
    new_access = create_access_token({"sub": user.username, "role": user.role,
                                      "org": user.organization_id})
    raw_refresh, _ = issue_refresh_token(
        db, user, family_id=result.record.family_id,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    return {"access_token": new_access, "token_type": "bearer",
            "refresh_token": raw_refresh,
            "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES}


@app.get("/auth/sessions", tags=["Auth"])
def list_sessions(db: Session = Depends(get_db),
                  current_user: User = Depends(get_current_user)):
    """Active sessions for the current user."""
    from backend.core.tokens import active_sessions

    return [
        {"id": s.id,
         "issued_at": s.issued_at.isoformat() if s.issued_at else None,
         "expires_at": s.expires_at.isoformat() if s.expires_at else None,
         "last_used_at": s.last_used_at.isoformat() if s.last_used_at else None,
         "user_agent": s.user_agent,
         "ip_address": s.ip_address}
        for s in active_sessions(db, current_user)
    ]


@app.post("/auth/logout", tags=["Auth"])
def logout_all_sessions(db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    """Revoke every refresh token for the current user.

    Access tokens already issued remain valid until they expire — they are
    stateless by design. Keeping their lifetime short is what bounds that
    window.
    """
    from backend.core.tokens import revoke_all_for_user

    revoked = revoke_all_for_user(db, current_user, "User logged out of all sessions.")
    log_action(db, current_user.username, "sessions_revoked",
               f"Revoked {revoked} active session(s)",
               organization_id=current_user.organization_id,
               entity_type="User", entity_id=current_user.id)
    db.commit()
    return {"revoked_sessions": revoked}

@app.get("/security/encryption-status", tags=["Audit"])
def get_encryption_status(current_user: User = Depends(require_capability(Capability.AUDIT_READ))):
    """Report the real encryption configuration.

    Deliberately states when encryption is disabled rather than staying silent —
    an operator must not assume data is protected when it is not.
    """
    from backend.utils.encryption import encryption_status
    return encryption_status()


class LegalHoldRequest(BaseModel):
    name: str
    reason: str
    data_class: str | None = None


@app.get("/governance/retention", tags=["Audit"])
def get_retention_status(db: Session = Depends(get_db),
                         current_user: User = Depends(require_capability(Capability.AUDIT_READ))):
    """What retention would delete, and what is protected from it."""
    from backend.utils.governance import evaluate_retention
    return evaluate_retention(db, current_user.organization_id)


@app.post("/governance/retention/seed-defaults", tags=["Audit"])
def seed_retention_defaults(db: Session = Depends(get_db),
                            current_user: User = Depends(require_capability(Capability.ORGANIZATION_MANAGE))):
    from backend.utils.governance import seed_default_policies
    created = seed_default_policies(db, current_user.organization_id, current_user.username)
    db.commit()
    log_action(db, current_user.username, "retention_policies_seeded",
               f"Created default retention policies: {', '.join(created) or 'none (already present)'}",
               organization_id=current_user.organization_id,
               entity_type="RetentionPolicy")
    db.commit()
    return {"created": created}


@app.post("/governance/legal-hold", tags=["Audit"])
def place_legal_hold(req: LegalHoldRequest, db: Session = Depends(get_db),
                     current_user: User = Depends(require_capability(Capability.AUDIT_READ))):
    """Place a hold. While active it overrides retention for the covered class."""
    from backend.models.models import LegalHold

    hold = LegalHold(
        organization_id=current_user.organization_id,
        name=req.name, reason=req.reason, data_class=req.data_class,
        active=True, placed_by=current_user.username,
    )
    db.add(hold)
    db.commit()
    db.refresh(hold)

    log_action(db, current_user.username, "legal_hold_placed",
               f"Placed legal hold '{hold.name}' on {hold.data_class or 'all data classes'}",
               organization_id=current_user.organization_id,
               entity_type="LegalHold", entity_id=hold.id, reason=req.reason)
    db.commit()

    return {"id": hold.id, "name": hold.name, "data_class": hold.data_class,
            "active": True, "placed_by": hold.placed_by}


@app.delete("/governance/legal-hold/{hold_id}", tags=["Audit"])
def release_legal_hold(hold_id: int, db: Session = Depends(get_db),
                       current_user: User = Depends(require_capability(Capability.AUDIT_READ))):
    """Release a hold. The record is retained, marked released — never deleted,
    since the existence of a past hold is itself auditable."""
    from backend.models.models import LegalHold

    hold = db.query(LegalHold).filter(
        LegalHold.id == hold_id,
        LegalHold.organization_id == current_user.organization_id).first()
    if not hold:
        raise HTTPException(status_code=404, detail="Legal hold not found")
    if not hold.active:
        raise HTTPException(status_code=409, detail="Legal hold is already released")

    hold.active = False
    hold.released_by = current_user.username
    hold.released_at = datetime.now(timezone.utc)
    db.commit()

    log_action(db, current_user.username, "legal_hold_released",
               f"Released legal hold '{hold.name}'",
               organization_id=current_user.organization_id,
               entity_type="LegalHold", entity_id=hold.id)
    db.commit()

    return {"id": hold.id, "active": False, "released_by": hold.released_by}

# Serve the frontend. Must be last — it catches all routes not claimed above.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

