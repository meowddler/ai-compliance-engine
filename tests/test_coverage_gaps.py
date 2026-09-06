"""Tests for modules the coverage report showed as thin.

Written against behaviour that matters rather than to raise a number: schema
validation is the boundary that keeps bad rules out of the engine, posture is
the headline metric, and the PDF is the auditor-facing artifact.
"""
import pytest

from backend.schemas.schemas import RuleCreate, RuleUpdate, Severity
from backend.utils.posture import compute_posture
from backend.utils.report_generator import generate_compliance_report


# --- Schema validation ----------------------------------------------------

def _rule(**overrides):
    base = {
        "name": "test_rule", "description": "d", "framework": "ISO 27001",
        "severity": "HIGH", "remediation": "fix it",
        "condition": [{"field": "port", "operator": "==", "value": 22}],
    }
    base.update(overrides)
    return base


def test_valid_rule_is_accepted():
    rule = RuleCreate(**_rule())
    assert rule.severity == Severity.HIGH


def test_invalid_severity_is_rejected():
    """A bad severity used to crash entire scans downstream; it is now refused
    at the boundary."""
    for bad in ("Critical", "high", "urgent", ""):
        with pytest.raises(Exception):
            RuleCreate(**_rule(severity=bad))


def test_unsupported_operator_is_rejected():
    """The validator imports its operator set from the engine, so a rule that
    passes validation cannot fail during a scan."""
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition=[{"field": "x", "operator": "REGEX_LIKE", "value": 1}]))


def test_blank_name_and_field_are_rejected():
    with pytest.raises(Exception):
        RuleCreate(**_rule(name="   "))
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition=[{"field": "  ", "operator": "==", "value": 1}]))


def test_empty_condition_is_rejected():
    """A rule with no conditions matches every record."""
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition=[]))


def test_list_operators_require_a_list():
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition=[{"field": "port", "operator": "in", "value": 22}]))


def test_invalid_regex_is_rejected_at_creation():
    """Catching this here makes it a 422 once, rather than an ERROR on every
    future scan."""
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition=[{"field": "x", "operator": "regex", "value": "([unclosed"}]))


def test_expression_trees_are_accepted():
    RuleCreate(**_rule(condition={"any": [
        {"field": "a", "operator": "==", "value": 1},
        {"not": {"field": "b", "operator": "==", "value": 2}},
    ]}))


def test_excessive_nesting_is_rejected():
    node = {"field": "a", "operator": "==", "value": 1}
    for _ in range(15):
        node = {"all": [node]}
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition=node))


def test_multiple_combinators_in_one_node_are_rejected():
    with pytest.raises(Exception):
        RuleCreate(**_rule(condition={
            "all": [{"field": "a", "operator": "==", "value": 1}],
            "any": [{"field": "b", "operator": "==", "value": 2}],
        }))


def test_presence_operators_need_no_value():
    RuleCreate(**_rule(condition=[{"field": "owner", "operator": "exists"}]))


def test_update_allows_partial_but_still_validates():
    RuleUpdate(severity="LOW")                      # partial is fine
    with pytest.raises(Exception):
        RuleUpdate(condition=[])                    # but not invalid


# --- Posture --------------------------------------------------------------

def test_unverified_controls_are_excluded_from_the_denominator():
    """A control we could not verify must never inflate the score."""
    results = (
        [{"status": "PASS", "severity": "HIGH"}] * 3 +
        [{"status": "INSUFFICIENT_EVIDENCE", "severity": "HIGH"}] * 5 +
        [{"status": "ERROR", "severity": "HIGH"}] * 2
    )
    posture = compute_posture(results)
    assert posture["controls_evaluated"] == 3
    assert posture["controls_unverified"] == 7
    assert posture["score"] == 100.0          # of what was actually checked


def test_severity_weighting_changes_the_score():
    high_fails = compute_posture([{"status": "FAIL", "severity": "HIGH"},
                                  {"status": "PASS", "severity": "LOW"}])
    low_fails = compute_posture([{"status": "PASS", "severity": "HIGH"},
                                 {"status": "FAIL", "severity": "LOW"}])
    assert low_fails["score"] > high_fails["score"]


def test_unknown_severity_gets_a_default_weight():
    """An unrecognised severity must not crash scoring."""
    posture = compute_posture([{"status": "PASS", "severity": "WEIRD"}])
    assert posture["scored"] is True


def test_missing_severity_is_tolerated():
    assert compute_posture([{"status": "PASS"}])["scored"] is True


def test_score_carries_its_rubric_version():
    """A score without the rubric that produced it cannot be compared over time."""
    assert compute_posture([{"status": "PASS", "severity": "HIGH"}])["rubric_version"]


# --- Report generation ----------------------------------------------------

def _pdf(buffer):
    data = buffer.getvalue()
    assert data[:5] == b"%PDF-"
    return data


def test_report_renders_with_full_data():
    _pdf(generate_compliance_report({
        "posture": {"scored": True, "score": 63.6, "controls_evaluated": 25,
                    "controls_passed": 17, "controls_failed": 8,
                    "controls_unverified": 0, "rubric_version": "posture-v1"},
        "total_scans": 3, "total_violations": 8, "anomaly_count": 2,
        "severity_breakdown": {"HIGH": 5, "MEDIUM": 2, "LOW": 1},
        "recent_violations": [{"server_id": "srv-1", "rule_name": "r",
                               "severity": "HIGH", "is_anomaly": True}],
    }, organization_name="Test Org"))


def test_report_survives_missing_data():
    """A KeyError here used to crash report generation entirely."""
    _pdf(generate_compliance_report({}))


def test_report_states_when_posture_cannot_be_computed():
    """Printing a zero would imply total failure rather than no measurement."""
    _pdf(generate_compliance_report({
        "posture": {"scored": False, "reason": "No controls were evaluated."}}))


def test_report_handles_oversized_values():
    """Uploaded identifiers are arbitrarily long; they must be clipped rather
    than overflow the table."""
    _pdf(generate_compliance_report({
        "recent_violations": [{"server_id": "x" * 300, "rule_name": "y" * 300,
                               "severity": "HIGH", "is_anomaly": False}],
    }))


def test_report_handles_no_findings():
    _pdf(generate_compliance_report({"recent_violations": []}))




# --- Anomaly detection (30% covered) --------------------------------------

def test_anomaly_detection_refuses_without_a_baseline():
    """Scoring a batch against itself made the same server 'normal' in one file
    and 'anomalous' in another. Refusing is the correct answer."""
    import pandas as pd

    from backend.ml_engine.anomaly_detector import MIN_BASELINE_ROWS, detect_anomalies

    df = pd.DataFrame([{"server_id": f"s{i}", "port": 443, "port_exposed": False,
                        "mfa_enabled": True, "last_login_days": 5,
                        "failed_logins": 0} for i in range(5)])

    result, meta = detect_anomalies(df, history_df=None)
    assert meta["scored"] is False
    assert "Insufficient baseline" in meta["reason"]
    assert not result["is_anomaly"].any()       # nothing fabricated

    thin = df.head(MIN_BASELINE_ROWS - 1)
    assert detect_anomalies(df, thin)[1]["scored"] is False


def test_anomaly_detection_scores_against_history():
    import random

    import pandas as pd

    from backend.ml_engine.anomaly_detector import detect_anomalies

    random.seed(3)
    history = pd.DataFrame([{
        "server_id": f"h{i}", "port": random.choice([443, 80]),
        "port_exposed": False, "mfa_enabled": True,
        "last_login_days": random.randint(1, 20), "failed_logins": 0,
    } for i in range(60)])

    batch = pd.DataFrame([{
        "server_id": "outlier", "port": 3389, "port_exposed": True,
        "mfa_enabled": False, "last_login_days": 400, "failed_logins": 99,
    }])

    result, meta = detect_anomalies(batch, history)
    assert meta["scored"] is True
    assert meta["baseline_rows"] == 60
    assert meta["detector_version"]


def test_feature_extraction_handles_missing_columns():
    from backend.ml_engine.anomaly_detector import FEATURE_COLUMNS, extract_features

    features = extract_features({"server_id": "s1", "port": 22})
    assert set(features) == set(FEATURE_COLUMNS)


# --- Freshness (72% covered) ----------------------------------------------

def test_unknown_collection_date_is_treated_as_stale():
    """Evidence of unknown age cannot be trusted as fresh."""
    from backend.utils.freshness import age_days, is_stale

    assert is_stale(None, 90) is True
    assert age_days(None) is None


def test_freshness_boundary_is_exact():
    from datetime import datetime, timedelta, timezone

    from backend.utils.freshness import is_stale

    now = datetime.now(timezone.utc)
    assert is_stale(now - timedelta(days=90), 90, now) is False
    assert is_stale(now - timedelta(days=91), 90, now) is True


def test_already_unverified_findings_are_not_degraded_again():
    """Idempotence: the scheduler runs this repeatedly."""
    from backend.utils.freshness import evaluate_staleness

    class F:
        def __init__(self, id, status):
            self.id, self.status = id, status
            self.evidence_collected_at = None

    decisions = evaluate_staleness(
        [F(1, "INSUFFICIENT_EVIDENCE"), F(2, "ERROR"), F(3, "PASS")], 90)
    assert [d["finding_id"] for d in decisions] == [3]


# --- Encryption edge cases (84%) ------------------------------------------

def test_plaintext_marker_round_trips():
    """With no keys configured, values are marked explicitly so plaintext can
    never be mistaken for ciphertext under an unknown key."""
    from backend.utils.encryption import PLAINTEXT_PREFIX, decrypt

    assert decrypt(f"{PLAINTEXT_PREFIX}:hello") == "hello"


def test_rotation_is_a_no_op_when_not_needed():
    from backend.utils.encryption import encrypt, needs_rotation, rotate

    stored = encrypt("value")
    if not needs_rotation(stored):
        assert rotate(stored) == stored


def test_rotate_passes_none_through():
    from backend.utils.encryption import rotate
    assert rotate(None) is None


# --- Audit chain edge cases (83%) -----------------------------------------

def test_empty_chain_verifies():
    """No entries is a valid state, not a failure."""
    from backend.utils.audit_chain import verify_chain

    result = verify_chain([])
    assert result["valid"] is True
    assert result["entries_verified"] == 0


def test_redaction_handles_deep_nesting():
    from backend.utils.audit_chain import redact

    deep = {"a": {"b": {"c": {"password": "secret", "keep": "yes"}}}}
    out = redact(deep)
    assert out["a"]["b"]["c"]["password"] == "[REDACTED]"
    assert out["a"]["b"]["c"]["keep"] == "yes"


def test_canonicalization_is_stable_across_equivalent_inputs():
    """If one event could serialize two ways, verification would fail on
    differences that do not matter."""
    from backend.utils.audit_chain import canonicalize

    assert canonicalize({"b": 1, "a": [1, 2]}) == canonicalize({"a": [1, 2], "b": 1})


def test_hash_changes_when_any_field_changes():
    from backend.utils.audit_chain import GENESIS_HASH, compute_hash

    base = {"action": "created", "actor": "amy"}
    changed = {"action": "deleted", "actor": "amy"}
    assert compute_hash(GENESIS_HASH, base) != compute_hash(GENESIS_HASH, changed)