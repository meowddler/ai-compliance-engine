"""Regression tests for the S0/S1 defects found in the original audit.

Each test pins a specific historical failure. The value is not that these pass
today — it is that a future change reintroducing one fails a test instead of
reaching a user.
"""
import io

from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)


def _headers():
    r = client.post("/auth/login", data={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_s0_01_no_hardcoded_signing_key():
    """The JWT secret was committed in source, letting anyone who read the repo
    forge an admin token. It now comes from the environment and the application
    refuses to start without it."""
    import inspect

    from backend.core import auth

    source = inspect.getsource(auth)
    assert "dev-secret" not in source
    assert "SECRET_KEY =" not in source          # imported, never literal

    from backend.config import SECRET_KEY
    assert len(SECRET_KEY) >= 32


def test_s0_02_score_is_not_fabricated_from_nothing():
    """The old score returned 100 for an empty database — an unevaluated system
    reported as perfectly compliant."""
    from backend.utils.posture import compute_posture

    empty = compute_posture([])
    assert empty["score"] is None
    assert empty["scored"] is False


def test_s0_03_unevaluable_control_never_reads_as_compliant():
    """Rules that could not run were silently skipped and the host reported
    clean, so a check that never happened looked identical to one that passed."""
    import json

    from backend.rules.rule_engine import Status, evaluate_rule_status

    class R:
        name, severity, description = "enc", "HIGH", "encryption required"
        framework, remediation = "TEST", "n/a"
        condition = json.dumps([{"field": "encryption_enabled",
                                 "operator": "==", "value": True}])

    # Field absent entirely.
    assert evaluate_rule_status({"server_id": "s"}, R())["status"] == \
        Status.INSUFFICIENT_EVIDENCE

    # Field present but empty — the same defect class, found later.
    assert evaluate_rule_status(
        {"server_id": "s", "encryption_enabled": float("nan")}, R()
    )["status"] == Status.INSUFFICIENT_EVIDENCE


def test_s0_04_control_edits_are_audited():
    """An auditor could downgrade a control's severity and rewrite its logic
    with no trace in the audit log."""
    from backend.database import SessionLocal
    from backend.models.models import AuditLog

    headers = _headers()
    client.post("/rules", headers=headers, json={
        "name": "regression_audit_rule", "description": "d", "framework": "TEST",
        "severity": "LOW", "remediation": "n/a",
        "condition": [{"field": "port", "operator": "==", "value": 4444}],
    })

    body = client.get("/rules", headers=headers).json()
    rules = body["items"] if isinstance(body, dict) and "items" in body else body
    rule = next((r for r in rules if r["name"] == "regression_audit_rule"), None)
    assert rule is not None

    client.put(f"/rules/{rule['id']}", headers=headers, json={"severity": "HIGH"})

    db = SessionLocal()
    entry = (db.query(AuditLog)
               .filter(AuditLog.action == "rule_updated")
               .order_by(AuditLog.id.desc()).first())
    db.close()

    assert entry is not None
    assert entry.before_state and entry.after_state       # not just "something changed"


def test_s1_01_data_endpoints_reject_anonymous_access():
    """Four endpoints served findings, scans, rules, and the dashboard to
    anyone who asked."""
    for path in ("/violations", "/scans", "/rules", "/dashboard/summary"):
        assert client.get(path).status_code == 401, path


def test_s1_02_cors_is_an_allowlist_not_a_wildcard():
    """Any website could make credentialed requests to the API on behalf of a
    logged-in user."""
    from backend.config import CORS_ORIGINS

    assert "*" not in CORS_ORIGINS
    assert all(o.startswith("http") for o in CORS_ORIGINS)


def test_s1_03_uploaded_values_are_not_rendered_as_html():
    """A server_id containing markup executed in the browser of anyone viewing
    the findings. Every render site now writes text, not HTML."""
    import re
    from pathlib import Path

    frontend = Path(__file__).resolve().parent.parent / "frontend"
    for page in frontend.glob("*.html"):
        source = page.read_text(encoding="utf-8")
        # Assigning a template literal containing ${...} to innerHTML is the
        # exact pattern that made uploaded data executable.
        assert not re.search(r"\.innerHTML\s*=\s*`[^`]*\$\{", source), page.name


def test_s1_04_invalid_severity_is_refused_at_the_boundary():
    """A control created with an unrecognised severity crashed entire scans
    later, when a lookup failed deep in the pipeline."""
    r = client.post("/rules", headers=_headers(), json={
        "name": "regression_bad_severity", "description": "d", "framework": "TEST",
        "severity": "Critical", "remediation": "n/a",
        "condition": [{"field": "port", "operator": "==", "value": 22}],
    })
    assert r.status_code == 422


def test_s1_05_duplicate_server_ids_do_not_crash_a_scan():
    """Two rows for the same server — ordinary in real log data — raised a
    ValueError and killed the whole scan."""
    csv = (
        "server_id,port,port_exposed,mfa_enabled,last_login_days,failed_logins\n"
        "regression-dup,22,true,false,3,1\n"
        "regression-dup,3389,true,false,10,5\n"
        "regression-other,443,false,true,20,0\n"
    )
    r = client.post("/upload-logs", headers=_headers(),
                    files={"file": ("dup.csv", io.BytesIO(csv.encode()), "text/csv")})
    assert r.status_code == 200, r.text
    assert r.json()["rows_scanned"] == 3


def test_s1_06_failed_login_returns_401_and_no_token():
    """A wrong password returned HTTP 200 with an error field, so clients
    checking the status code believed the login had succeeded."""
    r = client.post("/auth/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
    assert "access_token" not in r.json()

    # The same message for both cases, so usernames cannot be enumerated.
    unknown = client.post("/auth/login",
                          data={"username": "no_such_user", "password": "wrong"})
    assert unknown.json()["detail"] == r.json()["detail"]


def test_s1_07_a_failed_scan_leaves_no_ghost_record():
    """A scan row was written before processing, so a failure left a record that
    looked like a completed clean scan."""
    headers = _headers()
    before = client.get("/scans?page_size=1", headers=headers).json()["pagination"]["total_items"]

    bad = client.post("/upload-logs", headers=headers,
                      files={"file": ("junk.csv", io.BytesIO(b"not,a,valid\nfile"), "text/csv")})
    assert bad.status_code == 400

    after = client.get("/scans?page_size=1", headers=headers).json()["pagination"]["total_items"]
    assert after == before, "a failed upload created a scan record"


def test_s2_01_anomaly_detection_is_not_batch_relative():
    """Fitting on the uploaded batch made the same server 'normal' in a 5-row
    file and 'anomalous' in a 30-row one."""
    import inspect

    from backend.ml_engine import anomaly_detector

    signature = inspect.signature(anomaly_detector.detect_anomalies)
    assert "history_df" in signature.parameters

    import pandas as pd

    df = pd.DataFrame([{"server_id": "s", "port": 22, "port_exposed": True,
                        "mfa_enabled": False, "last_login_days": 1,
                        "failed_logins": 0}])
    _, meta = anomaly_detector.detect_anomalies(df, history_df=None)
    assert meta["scored"] is False          # refuses rather than inventing