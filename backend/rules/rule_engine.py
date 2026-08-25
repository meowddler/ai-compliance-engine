import json

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# Operators that require the rule's value to be a list. Used to catch
# misconfigured rules before they raise deep inside a comparison.
_LIST_OPERATORS = {"in"}


class ConditionError(Exception):
    """Raised when a condition cannot be evaluated (bad data, bad rule, type mismatch).

    This exists so that a check which *could not run* is never silently treated
    as if it passed. A compliance control that cannot be evaluated must surface
    as an explicit error, never as a clean result.
    """


def evaluate_condition(row, condition):
    """Check ONE condition against a row. No eval(), no code execution.

    Returns True/False when the check genuinely ran. Raises ConditionError when
    the check could not be performed — a missing field, an unknown operator, or
    a type mismatch. The caller must treat that error as 'could not evaluate',
    not as a pass.
    """
    # A malformed rule (missing keys) is a rule problem, not a clean host.
    try:
        field = condition["field"]
        op = condition["operator"]
        value = condition["value"]
    except (KeyError, TypeError) as exc:
        raise ConditionError(f"Malformed condition: {condition!r}") from exc

    # Missing evidence must never read as compliant. If the field the control
    # needs isn't in the data, we cannot conclude anything — that's an error.
    if field not in row:
        raise ConditionError(
            f"Field {field!r} is not present in the record; cannot evaluate."
        )

    row_value = row[field]

    if op in _LIST_OPERATORS and not isinstance(value, (list, tuple, set)):
        raise ConditionError(
            f"Operator {op!r} requires a list value, got {type(value).__name__}."
        )

    try:
        if op == "==":
            return row_value == value
        elif op == "!=":
            return row_value != value
        elif op == ">":
            return row_value > value
        elif op == "<":
            return row_value < value
        elif op == ">=":
            return row_value >= value
        elif op == "<=":
            return row_value <= value
        elif op == "in":
            return row_value in value
    except TypeError as exc:
        # e.g. comparing a string against an int threshold. The check could not
        # be performed — surface it, don't swallow it.
        raise ConditionError(
            f"Cannot apply {op!r} between {row_value!r} and {value!r}."
        ) from exc

    # An operator we don't recognise is a rule definition error, not a pass.
    raise ConditionError(f"Unknown operator {op!r}.")


def rule_matches(row, conditions):
    """A rule fires only if ALL its conditions are true (AND logic).

    An empty condition list is rejected: a rule that matches everything is
    almost never intended and would flag every record. Any condition that
    cannot be evaluated propagates as a ConditionError.
    """
    if not conditions:
        raise ConditionError("Rule has no conditions; refusing to match everything.")
    return all(evaluate_condition(row, c) for c in conditions)


def evaluate_row(row, rules):
    """Evaluate every rule against one row.

    Returns a dict with two lists:
      violations — rules that fired (a real finding)
      errors     — rules that could not be evaluated (surfaced, never hidden)

    The key property: a rule that errors appears in `errors`. It is NEVER
    dropped, and its host is NEVER implicitly reported clean because of it.
    """
    violations = []
    errors = []

    for rule in rules:
        try:
            conditions = json.loads(rule.condition)
        except (json.JSONDecodeError, TypeError) as exc:
            errors.append({
                "rule": rule.name,
                "severity": rule.severity,
                "reason": f"Rule condition is not valid JSON: {exc}",
            })
            continue

        try:
            fired = rule_matches(row, conditions)
        except ConditionError as exc:
            errors.append({
                "rule": rule.name,
                "severity": rule.severity,
                "reason": str(exc),
            })
            continue

        if fired:
            violations.append({
                "rule": rule.name,
                "severity": rule.severity,
                "message": rule.description,
                "framework": rule.framework,
                "remediation": rule.remediation,
            })

    return {"violations": violations, "errors": errors}


def evaluate_dataframe(df, rules):
    results = []
    for _, row in df.iterrows():
        outcome = evaluate_row(row, rules)
        violations = outcome["violations"]
        errors = outcome["errors"]

        highest_severity = (
            max(violations, key=lambda v: SEVERITY_RANK.get(v["severity"], 0))["severity"]
            if violations else "NONE"
        )

        results.append({
            "server_id": row.get("server_id", "unknown"),
            "highest_severity": highest_severity,
            "violations": violations,
            "errors": errors,
            "has_errors": bool(errors),
        })

    # Sort by severity, but push any row with evaluation errors to the top —
    # an un-evaluable control needs a human's attention before a clean pass.
    results.sort(
        key=lambda r: (r["has_errors"], SEVERITY_RANK.get(r["highest_severity"], 0)),
        reverse=True,
    )
    return results