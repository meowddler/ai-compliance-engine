"""Job handlers.

Each handler receives a payload dict and returns a JSON-serialisable summary.
Handlers must be idempotent where possible: a job can be retried after a partial
failure, and re-running must not duplicate work.
"""

import json

from backend.core.jobs import register_handler
from backend.core.logging_config import get_logger
from backend.database import SessionLocal

logger = get_logger("job_handlers")


def evaluate_scan(payload: dict) -> dict:
    """Evaluate an already-persisted scan against the organisation's controls.

    The upload endpoint stores evidence and creates the scan synchronously —
    that part is fast and the user needs the scan id immediately. Evaluation,
    which scales with rows multiplied by rules, runs here instead.

    Idempotent: existing findings for the scan are cleared before re-evaluating,
    so a retry after partial failure produces one clean set rather than
    duplicates.
    """
    import pandas as pd

    from backend.ml_engine.anomaly_detector import DETECTOR_VERSION, detect_anomalies, extract_features
    from backend.models.models import (
        Evidence, PostureSnapshot, Rule, Scan, ScanRecord, Violation,
    )
    from backend.rules.rule_engine import evaluate_dataframe
    from backend.utils.posture import compute_posture

    scan_id = payload["scan_id"]
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            return {"error": f"Scan {scan_id} no longer exists.", "scan_id": scan_id}

        org_id = scan.organization_id

        evidence = db.query(Evidence).filter(Evidence.scan_id == scan_id).first()
        if evidence is None:
            return {"error": "No evidence is attached to this scan.", "scan_id": scan_id}

        with open(evidence.storage_path, "rb") as fh:
            df = pd.read_csv(fh)

        # Clear prior results so a retry does not accumulate duplicates.
        db.query(Violation).filter(Violation.scan_id == scan_id).delete(synchronize_session=False)
        db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).delete(synchronize_session=False)
        db.query(PostureSnapshot).filter(PostureSnapshot.scan_id == scan_id).delete(synchronize_session=False)
        db.commit()

        active_rules = db.query(Rule).filter(
            Rule.organization_id == org_id,
            Rule.active.is_(True),
            Rule.is_current.is_(True),
        ).all()
        rule_id_by_name = {r.name: r.id for r in active_rules}

        rule_results = evaluate_dataframe(df, active_rules)

        history_rows = db.query(ScanRecord).filter(ScanRecord.organization_id == org_id).all()
        history_df = pd.DataFrame(
            [json.loads(r.features) for r in history_rows]) if history_rows else None
        df_scored, anomaly_meta = detect_anomalies(df, history_df)

        anomaly_map = {}
        if "server_id" in df_scored.columns:
            for _, row in df_scored.iterrows():
                sid = row["server_id"]
                score = row.get("anomaly_score")
                prev = anomaly_map.get(sid)
                if prev is None or (score is not None and score < prev["anomaly_score"]):
                    anomaly_map[sid] = {
                        "is_anomaly": bool(row.get("is_anomaly", False)),
                        "anomaly_score": score if score is not None else 0.0,
                    }

        for _, raw in df_scored.iterrows():
            db.add(ScanRecord(
                organization_id=org_id, scan_id=scan_id,
                server_id=str(raw.get("server_id", "unknown")),
                features=json.dumps(extract_features(raw), default=str),
                is_anomaly=bool(raw.get("is_anomaly", False)),
                anomaly_score=str(raw.get("anomaly_score"))
                if raw.get("anomaly_score") is not None else None,
                detector_version=DETECTOR_VERSION,
            ))

        findings = 0
        for result in rule_results:
            server = result["server_id"]
            info = anomaly_map.get(server, {})
            is_anomaly = bool(info.get("is_anomaly", False))
            anomaly_score = str(info["anomaly_score"]) if info.get("anomaly_score") is not None else None

            for r in result["results"]:
                if r["status"] == "PASS":
                    continue
                db.add(Violation(
                    scan_id=scan_id, organization_id=org_id,
                    evidence_id=evidence.id,
                    rule_id=rule_id_by_name.get(r["rule"]),
                    server_id=server, rule_name=r["rule"],
                    severity=r["severity"], status=r["status"],
                    message=r.get("message") if r["status"] == "FAIL" else r.get("reason"),
                    is_anomaly=is_anomaly, anomaly_score=anomaly_score,
                ))
                findings += 1

        flat = [r for res in rule_results for r in res["results"]]
        snap = compute_posture(flat)
        db.add(PostureSnapshot(
            organization_id=org_id, scan_id=scan_id,
            score=str(snap["score"]) if snap["score"] is not None else None,
            controls_evaluated=snap["controls_evaluated"],
            controls_passed=snap["controls_passed"],
            controls_failed=snap["controls_failed"],
            controls_unverified=snap["controls_unverified"],
            rubric_version=snap["rubric_version"],
        ))

        db.commit()

        return {
            "scan_id": scan_id,
            "rows": len(df),
            "rules": len(active_rules),
            "findings": findings,
            "posture": snap["score"],
            "anomaly_detection": anomaly_meta,
        }
    finally:
        db.close()


register_handler("evaluate_scan", evaluate_scan)