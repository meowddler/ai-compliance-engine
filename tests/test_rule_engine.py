import json
from backend.rules.rule_engine import (
    evaluate_condition, rule_matches, evaluate_row, evaluate_rule_status, Status
)


class FakeRule:
    """Mimics a DB Rule object without needing a real database."""
    def __init__(self, name, severity, description, condition):
        self.name = name
        self.severity = severity
        self.description = description
        self.framework = "TEST"
        self.remediation = "Fix it"
        self.condition = json.dumps(condition)


def test_evaluate_condition_equals():
    row = {"port_exposed": True}
    condition = {"field": "port_exposed", "operator": "==", "value": True}
    assert evaluate_condition(row, condition) is True


def test_evaluate_condition_greater_than():
    row = {"failed_logins": 10}
    condition = {"field": "failed_logins", "operator": ">", "value": 5}
    assert evaluate_condition(row, condition) is True


def test_evaluate_condition_in_list():
    row = {"port": 22}
    condition = {"field": "port", "operator": "in", "value": [22, 3389]}
    assert evaluate_condition(row, condition) is True


def test_rule_matches_requires_all_conditions():
    row = {"port_exposed": True, "mfa_enabled": True}  # MFA is ON
    conditions = [
        {"field": "port_exposed", "operator": "==", "value": True},
        {"field": "mfa_enabled", "operator": "==", "value": False}  # this fails
    ]
    assert rule_matches(row, conditions) is False


def test_evaluate_row_flags_violation():
    row = {"server_id": "srv-test", "port_exposed": True, "mfa_enabled": False}
    rule = FakeRule(
        name="exposed_no_mfa",
        severity="HIGH",
        description="Exposed with no MFA",
        condition=[
            {"field": "port_exposed", "operator": "==", "value": True},
            {"field": "mfa_enabled", "operator": "==", "value": False}
        ]
    )
    result = evaluate_row(row, [rule])
    assert len(result["violations"]) == 1
    assert result["errors"] == []
    assert result["violations"][0]["severity"] == "HIGH"


def test_evaluate_row_no_violation_when_clean():
    row = {"server_id": "srv-clean", "port_exposed": False, "mfa_enabled": True}
    rule = FakeRule(
        name="exposed_no_mfa",
        severity="HIGH",
        description="Exposed with no MFA",
        condition=[
            {"field": "port_exposed", "operator": "==", "value": True},
            {"field": "mfa_enabled", "operator": "==", "value": False}
        ]
    )
    result = evaluate_row(row, [rule])
    assert len(result["violations"]) == 0
    assert result["errors"] == []


# --- Status model tests (Phase 1) -----------------------------------------

def test_status_fail_when_rule_fires():
    row = {"server_id": "s", "port": 3389}
    rule = FakeRule("risky", "HIGH", "risky port",
                    [{"field": "port", "operator": "==", "value": 3389}])
    assert evaluate_rule_status(row, rule)["status"] == Status.FAIL


def test_status_pass_when_rule_does_not_fire():
    row = {"server_id": "s", "port": 443}
    rule = FakeRule("risky", "HIGH", "risky port",
                    [{"field": "port", "operator": "==", "value": 3389}])
    assert evaluate_rule_status(row, rule)["status"] == Status.PASS


def test_status_insufficient_evidence_when_field_absent():
    """A field the rule needs is missing -> INSUFFICIENT_EVIDENCE, never PASS.
    This is the core guarantee: missing evidence is not compliance."""
    row = {"server_id": "s", "port": 443}
    rule = FakeRule("enc", "HIGH", "encryption required",
                    [{"field": "encryption_enabled", "operator": "==", "value": True}])
    result = evaluate_rule_status(row, rule)
    assert result["status"] == Status.INSUFFICIENT_EVIDENCE
    assert "encryption_enabled" in result["reason"]


def test_status_error_on_type_mismatch():
    """A present field with an incompatible type -> ERROR (the rule/data is broken),
    distinct from missing evidence."""
    row = {"server_id": "s", "patch_level": "unknown"}
    rule = FakeRule("patch", "HIGH", "patch level",
                    [{"field": "patch_level", "operator": ">", "value": 5}])
    assert evaluate_rule_status(row, rule)["status"] == Status.ERROR


def test_status_error_on_bad_json():
    row = {"server_id": "s"}
    rule = FakeRule("broken", "HIGH", "broken rule", [])
    rule.condition = "this is not json"
    assert evaluate_rule_status(row, rule)["status"] == Status.ERROR


def test_evaluate_row_separates_insufficient_from_errors():
    """Missing field and type mismatch must land in DIFFERENT buckets."""
    row = {"server_id": "s", "patch_level": "unknown"}
    missing = FakeRule("enc", "HIGH", "enc",
                       [{"field": "encryption_enabled", "operator": "==", "value": True}])
    mismatch = FakeRule("patch", "HIGH", "patch",
                        [{"field": "patch_level", "operator": ">", "value": 5}])
    result = evaluate_row(row, [missing, mismatch])
    assert len(result["insufficient_evidence"]) == 1   # the missing field
    assert len(result["errors"]) == 1                  # the type mismatch
    assert len(result["violations"]) == 0

def test_empty_cell_is_insufficient_evidence_not_pass():
    """A blank value must never read as compliant.

    pandas parses an empty CSV cell as NaN, and every comparison against NaN is
    False — so without an explicit check the rule silently fails to fire and the
    record is reported as passing. Blanking a column would mark an entire fleet
    compliant. Same defect class as a missing column.
    """
    row = {"server_id": "srv-1", "port": 22, "mfa_enabled": float("nan")}
    rule = FakeRule("mfa_required", "HIGH", "MFA must be enabled",
                    [{"field": "mfa_enabled", "operator": "==", "value": False}])
    result = evaluate_rule_status(row, rule)
    assert result["status"] == Status.INSUFFICIENT_EVIDENCE
    assert result["status"] != Status.PASS


def test_blank_string_is_insufficient_evidence():
    """Whitespace-only values carry no information either."""
    row = {"server_id": "srv-2", "owner": "   "}
    rule = FakeRule("owner_set", "LOW", "Owner must be recorded",
                    [{"field": "owner", "operator": "==", "value": ""}])
    assert evaluate_rule_status(row, rule)["status"] == Status.INSUFFICIENT_EVIDENCE


def test_none_value_is_insufficient_evidence():
    """A JSON null is missing evidence, not a passing check."""
    row = {"server_id": "srv-3", "encryption": None}
    rule = FakeRule("enc", "HIGH", "Encryption required",
                    [{"field": "encryption", "operator": "==", "value": True}])
    assert evaluate_rule_status(row, rule)["status"] == Status.INSUFFICIENT_EVIDENCE


def test_zero_and_false_are_real_values_not_missing():
    """0 and False are legitimate data. Treating them as 'missing' would be a
    serious false negative — a port of 0 or mfa_enabled=False must still evaluate."""
    row = {"server_id": "srv-4", "failed_logins": 0, "mfa_enabled": False}

    rule_zero = FakeRule("no_failures", "LOW", "failed logins",
                         [{"field": "failed_logins", "operator": "==", "value": 0}])
    assert evaluate_rule_status(row, rule_zero)["status"] == Status.FAIL   # condition matched

    rule_false = FakeRule("mfa_off", "HIGH", "mfa disabled",
                          [{"field": "mfa_enabled", "operator": "==", "value": False}])
    assert evaluate_rule_status(row, rule_false)["status"] == Status.FAIL