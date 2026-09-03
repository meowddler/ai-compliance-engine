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



# --- Expression tree: OR, NOT, nesting ------------------------------------

def test_or_fires_when_either_branch_matches():
    rule = FakeRule("mfa_or_vpn", "HIGH", "needs MFA or VPN",
                    {"any": [{"field": "mfa_enabled", "operator": "==", "value": False},
                             {"field": "vpn_only", "operator": "==", "value": False}]})
    assert evaluate_rule_status({"mfa_enabled": False, "vpn_only": True}, rule)["status"] == Status.FAIL
    assert evaluate_rule_status({"mfa_enabled": True, "vpn_only": True}, rule)["status"] == Status.PASS


def test_not_inverts_result():
    rule = FakeRule("must_encrypt", "HIGH", "encryption required",
                    {"not": {"field": "encrypted", "operator": "==", "value": True}})
    assert evaluate_rule_status({"encrypted": True}, rule)["status"] == Status.PASS
    assert evaluate_rule_status({"encrypted": False}, rule)["status"] == Status.FAIL


def test_nested_all_containing_any():
    """Production servers must have both encryption and backups."""
    rule = FakeRule("prod_hardening", "HIGH", "prod requires encryption and backup",
                    {"all": [
                        {"field": "env", "operator": "==", "value": "production"},
                        {"any": [{"field": "encrypted", "operator": "==", "value": False},
                                 {"field": "backup_enabled", "operator": "==", "value": False}]}]})
    assert evaluate_rule_status(
        {"env": "production", "encrypted": False, "backup_enabled": True}, rule)["status"] == Status.FAIL
    assert evaluate_rule_status(
        {"env": "production", "encrypted": True, "backup_enabled": True}, rule)["status"] == Status.PASS
    # Not production, so the rule does not apply even though both are off.
    assert evaluate_rule_status(
        {"env": "dev", "encrypted": False, "backup_enabled": False}, rule)["status"] == Status.PASS


def test_legacy_flat_list_still_means_and():
    """Every rule written before the tree existed must keep working."""
    rule = FakeRule("legacy", "HIGH", "flat AND",
                    [{"field": "port_exposed", "operator": "==", "value": True},
                     {"field": "mfa_enabled", "operator": "==", "value": False}])
    assert evaluate_rule_status({"port_exposed": True, "mfa_enabled": False}, rule)["status"] == Status.FAIL
    assert evaluate_rule_status({"port_exposed": True, "mfa_enabled": True}, rule)["status"] == Status.PASS


# --- Three-valued logic ---------------------------------------------------
# The subtle part. Collapsing "unverifiable" into true or false would either
# invent findings or hide real ones.

def test_or_with_one_true_branch_settles_despite_missing_evidence():
    """A satisfied branch settles an OR — the unverifiable branch cannot change it."""
    rule = FakeRule("or_rule", "HIGH", "either",
                    {"any": [{"field": "a", "operator": "==", "value": 1},
                             {"field": "b", "operator": "==", "value": 1}]})
    assert evaluate_rule_status({"a": 1}, rule)["status"] == Status.FAIL


def test_or_with_no_true_branch_and_missing_evidence_is_unverifiable():
    """Nothing matched, but the missing branch might have — so we cannot conclude."""
    rule = FakeRule("or_rule", "HIGH", "either",
                    {"any": [{"field": "a", "operator": "==", "value": 1},
                             {"field": "b", "operator": "==", "value": 1}]})
    assert evaluate_rule_status({"a": 9}, rule)["status"] == Status.INSUFFICIENT_EVIDENCE


def test_and_with_one_false_branch_settles_despite_missing_evidence():
    """A failed branch settles an AND — the rule cannot fire regardless."""
    rule = FakeRule("and_rule", "HIGH", "both",
                    {"all": [{"field": "a", "operator": "==", "value": 1},
                             {"field": "b", "operator": "==", "value": 1}]})
    assert evaluate_rule_status({"a": 9}, rule)["status"] == Status.PASS


def test_and_with_all_true_but_missing_evidence_is_unverifiable():
    """Everything checked passed, but the missing branch might have been false."""
    rule = FakeRule("and_rule", "HIGH", "both",
                    {"all": [{"field": "a", "operator": "==", "value": 1},
                             {"field": "b", "operator": "==", "value": 1}]})
    assert evaluate_rule_status({"a": 1}, rule)["status"] == Status.INSUFFICIENT_EVIDENCE


def test_not_of_unknown_stays_unknown():
    """Negating something unverifiable does not make it verifiable."""
    rule = FakeRule("neg", "HIGH", "not missing",
                    {"not": {"field": "absent", "operator": "==", "value": 1}})
    assert evaluate_rule_status({"other": 1}, rule)["status"] == Status.INSUFFICIENT_EVIDENCE


# --- New operators --------------------------------------------------------

def test_regex_operator():
    rule = FakeRule("pw_policy", "HIGH", "lowercase only",
                    {"field": "pw", "operator": "regex", "value": "^[a-z]+$"})
    assert evaluate_rule_status({"pw": "abc"}, rule)["status"] == Status.FAIL
    assert evaluate_rule_status({"pw": "Abc1"}, rule)["status"] == Status.PASS


def test_exists_operators_answer_when_field_absent():
    """Presence checks must answer even when the field is missing — that absence
    is the thing being tested, not an obstacle to testing it."""
    exists = FakeRule("has_owner", "LOW", "owner recorded",
                      {"field": "owner", "operator": "exists"})
    assert evaluate_rule_status({}, exists)["status"] == Status.PASS
    assert evaluate_rule_status({"owner": "amy"}, exists)["status"] == Status.FAIL

    missing = FakeRule("no_owner", "LOW", "owner absent",
                       {"field": "owner", "operator": "not_exists"})
    assert evaluate_rule_status({}, missing)["status"] == Status.FAIL


def test_between_and_not_in_operators():
    btw = FakeRule("stale_window", "LOW", "30-60 days",
                   {"field": "days", "operator": "between", "value": [30, 60]})
    assert evaluate_rule_status({"days": 45}, btw)["status"] == Status.FAIL
    assert evaluate_rule_status({"days": 90}, btw)["status"] == Status.PASS

    nin = FakeRule("odd_port", "MEDIUM", "non-standard port",
                   {"field": "port", "operator": "not_in", "value": [80, 443]})
    assert evaluate_rule_status({"port": 8080}, nin)["status"] == Status.FAIL
    assert evaluate_rule_status({"port": 443}, nin)["status"] == Status.PASS


# --- Malformed trees fail loudly ------------------------------------------

def test_malformed_trees_are_errors_not_silent_passes():
    cases = [
        ("empty all", {"all": []}),
        ("empty any", {"any": []}),
        ("unknown operator", {"field": "x", "operator": "BOOM", "value": 1}),
        ("two combinators", {"all": [{"field": "a", "operator": "==", "value": 1}], "any": []}),
        ("invalid regex", {"field": "x", "operator": "regex", "value": "([unclosed"}),
        ("missing value", {"field": "x", "operator": "=="}),
    ]
    for label, cond in cases:
        rule = FakeRule("bad", "HIGH", label, cond)
        assert evaluate_rule_status({"x": "a", "a": 1}, rule)["status"] == Status.ERROR, label


def test_excessive_nesting_is_rejected():
    """A depth limit bounds both accidental and malicious rule structures."""
    node = {"field": "a", "operator": "==", "value": 1}
    for _ in range(15):
        node = {"all": [node]}
    rule = FakeRule("deep", "HIGH", "too deep", node)
    assert evaluate_rule_status({"a": 1}, rule)["status"] == Status.ERROR