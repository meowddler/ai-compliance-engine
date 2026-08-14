import json
from backend.rules.rule_engine import evaluate_condition, rule_matches, evaluate_row


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
    violations = evaluate_row(row, [rule])
    assert len(violations) == 1
    assert violations[0]["severity"] == "HIGH"


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
    violations = evaluate_row(row, [rule])
    assert len(violations) == 0