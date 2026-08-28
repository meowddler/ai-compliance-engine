import json

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# Operators that require the rule's value to be a list. Used to catch
# misconfigured rules before they raise deep inside a comparison.
_LIST_OPERATORS = {"in"}


# --- Evaluation status vocabulary (Phase 1) --------------------------------
# Every rule evaluated against every record now yields ONE explicit status.
# "No violation" can no longer be confused with "not evaluated": each outcome
# says exactly what happened.
class Status:
    PASS = "PASS"                                  # rule ran, record is compliant
    FAIL = "FAIL"                                  # rule ran, record violates it
    ERROR = "ERROR"                                # rule could not be evaluated
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # data needed to judge is absent
    NOT_APPLICABLE = "NOT_APPLICABLE"              # rule does not apply to this record


class ConditionError(Exception):
    """Raised when a condition cannot be evaluated (bad data, bad rule, type mismatch)."""


class InsufficientEvidence(Exception):
    """Raised when the data required to evaluate a condition is absent.

    Distinct from ConditionError: a missing field is not a broken rule, it is a
    gap in evidence. A compliance tool must report 'we could not verify this'
    rather than either passing it or calling the rule itself broken.
    """


def evaluate_condition(row, condition):
    """Check ONE condition against a record. No eval(), no code execution.

    Returns True/False when the check genuinely ran.
    Raises InsufficientEvidence when the field needed is absent.
    Raises ConditionError when the rule/data is malformed (bad operator, type mismatch).
    """
    try:
        field = condition["field"]
        op = condition["operator"]
        value = condition["value"]
    except (KeyError, TypeError) as exc:
        raise ConditionError(f"Malformed condition: {condition!r}") from exc

    # Missing evidence is its own explicit outcome — not a pass, not a broken rule.
    if field not in row:
        raise InsufficientEvidence(
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
        raise ConditionError(
            f"Cannot apply {op!r} between {row_value!r} and {value!r}."
        ) from exc

    raise ConditionError(f"Unknown operator {op!r}.")


def rule_matches(row, conditions):
    """A rule fires only if ALL its conditions are true (AND logic).

    Propagates InsufficientEvidence and ConditionError from the conditions.
    An empty condition list is a malformed rule.
    """
    if not conditions:
        raise ConditionError("Rule has no conditions; refusing to match everything.")
    return all(evaluate_condition(row, c) for c in conditions)


def evaluate_rule_status(row, rule):
    """Evaluate ONE rule against ONE record and return an explicit status result.

    This is the heart of the status model. Instead of only reporting rules that
    fired, we return the outcome of the evaluation itself:

      FAIL                  - the rule's conditions matched (a violation)
      PASS                  - the rule ran and the record is compliant
      INSUFFICIENT_EVIDENCE - a field the rule needs is absent
      ERROR                 - the rule or data is malformed and cannot be run

    (NOT_APPLICABLE is reserved for the applicability engine in a later phase;
    it is defined in Status now so the vocabulary is complete.)
    """
    result = {
        "rule": rule.name,
        "severity": rule.severity,
        "framework": rule.framework,
        "message": rule.description,
        "remediation": rule.remediation,
        "status": None,
        "reason": None,
    }

    try:
        conditions = json.loads(rule.condition)
    except (json.JSONDecodeError, TypeError) as exc:
        result["status"] = Status.ERROR
        result["reason"] = f"Rule condition is not valid JSON: {exc}"
        return result

    try:
        fired = rule_matches(row, conditions)
    except InsufficientEvidence as exc:
        result["status"] = Status.INSUFFICIENT_EVIDENCE
        result["reason"] = str(exc)
        return result
    except ConditionError as exc:
        result["status"] = Status.ERROR
        result["reason"] = str(exc)
        return result

    if fired:
        result["status"] = Status.FAIL
        result["reason"] = "All conditions matched."
    else:
        result["status"] = Status.PASS
        result["reason"] = "Conditions did not match; record is compliant with this rule."
    return result


def evaluate_row(row, rules):
    """Evaluate every rule against one record.

    Returns a dict with:
      results  - the full status result for EVERY rule (PASS/FAIL/ERROR/…)
      violations - the FAILs only (backward-compatible with existing callers)
      errors     - the ERRORs only (backward-compatible with existing callers)

    Keeping `violations` and `errors` means the current app.py and tests keep
    working unchanged, while new code can read the richer `results` list.
    """
    results = [evaluate_rule_status(row, rule) for rule in rules]

    violations = [
        {
            "rule": r["rule"],
            "severity": r["severity"],
            "message": r["message"],
            "framework": r["framework"],
            "remediation": r["remediation"],
        }
        for r in results if r["status"] == Status.FAIL
    ]
    errors = [
        {"rule": r["rule"], "severity": r["severity"], "reason": r["reason"]}
        for r in results if r["status"] == Status.ERROR
    ]
    insufficient = [
        {"rule": r["rule"], "severity": r["severity"], "reason": r["reason"]}
        for r in results if r["status"] == Status.INSUFFICIENT_EVIDENCE
    ]

    return {
        "results": results,
        "violations": violations,
        "errors": errors,
        "insufficient_evidence": insufficient,
    }


def _status_counts(results):
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts


def evaluate_dataframe(df, rules):
    results = []
    for _, row in df.iterrows():
        outcome = evaluate_row(row, rules)
        violations = outcome["violations"]
        errors = outcome["errors"]
        insufficient = outcome["insufficient_evidence"]

        highest_severity = (
            max(violations, key=lambda v: SEVERITY_RANK.get(v["severity"], 0))["severity"]
            if violations else "NONE"
        )

        results.append({
            "server_id": row.get("server_id", "unknown"),
            "highest_severity": highest_severity,
            "violations": violations,
            "errors": errors,
            "insufficient_evidence": insufficient,
            "results": outcome["results"],
            "status_counts": _status_counts(outcome["results"]),
            "has_errors": bool(errors),
            "has_insufficient": bool(insufficient),
        })

    # Sort: rows needing attention first — errors, then insufficient evidence,
    # then by violation severity. A clean, fully-evaluated PASS sinks to the bottom.
    results.sort(
        key=lambda r: (
            r["has_errors"],
            r["has_insufficient"],
            SEVERITY_RANK.get(r["highest_severity"], 0),
        ),
        reverse=True,
    )
    return results