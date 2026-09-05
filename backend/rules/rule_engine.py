"""Deterministic rule evaluation.

CONDITION LANGUAGE
------------------
A condition is a tree. A leaf tests one field; branches combine results.

    leaf:   {"field": "port", "operator": "==", "value": 22}
    AND:    {"all": [ <node>, <node>, ... ]}
    OR:     {"any": [ <node>, <node>, ... ]}
    NOT:    {"not": <node>}

The legacy flat form — a bare list of leaves — is still accepted and means AND,
so every rule written before the tree existed keeps working unchanged.

THREE-VALUED LOGIC
------------------
A branch can be TRUE, FALSE, or UNKNOWN (its evidence is missing). Collapsing
UNKNOWN into either TRUE or FALSE would produce findings that are not real, or
hide findings that are — so it is carried explicitly:

    any(TRUE, UNKNOWN)  = TRUE     one satisfied branch settles an OR
    any(FALSE, UNKNOWN) = UNKNOWN  the missing branch might have been true
    all(FALSE, UNKNOWN) = FALSE    one failed branch settles an AND
    all(TRUE, UNKNOWN)  = UNKNOWN  the missing branch might have been false
    not(UNKNOWN)        = UNKNOWN

This is Kleene logic, and it is what keeps "we could not check" distinct from
"we checked and it was fine" all the way through nested expressions.
"""

import json
import re

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

_LIST_OPERATORS = {"in", "not_in"}
# Operators that ask about PRESENCE. They must still answer when the field is
# absent — that absence is the thing being tested, not an obstacle to testing.
_PRESENCE_OPERATORS = {"exists", "not_exists"}

VALID_OPERATORS = {
    "==", "!=", ">", "<", ">=", "<=",
    "in", "not_in", "contains", "not_contains",
    "regex", "exists", "not_exists", "between",
}

MAX_DEPTH = 10          # guards against absurd or malicious nesting
MAX_REGEX_LENGTH = 200  # a crude bound on catastrophic backtracking


class Status:
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ConditionError(Exception):
    """The rule or the data is malformed and cannot be evaluated."""


class InsufficientEvidence(Exception):
    """The data required to evaluate is absent. Not a broken rule — a gap."""


# Sentinel for the third truth value. A class, not None, so it cannot be
# confused with a missing return.
class _Unknown:
    _reasons: list

    def __init__(self, reasons=None):
        self.reasons = reasons or []

    def __bool__(self):
        # Refuse implicit truthiness: `if unknown:` would silently pick a side.
        raise TypeError("UNKNOWN cannot be coerced to a boolean; handle it explicitly.")

    def __repr__(self):
        return f"UNKNOWN({'; '.join(self.reasons)})"


def _unknown(reason):
    return _Unknown([reason])


def _is_unknown(v):
    return isinstance(v, _Unknown)


def _is_missing(value):
    """True for values carrying no information: None, NaN, or blank text."""
    if value is None:
        return True
    # NaN is the only value that is not equal to itself. Checked directly rather
    # than via math.isnan so the function stays dependency-free.
    if isinstance(value, float) and value != value:  # noqa: PLR0124
        return True
    return bool(isinstance(value, str) and not value.strip())


# --------------------------------------------------------------------------
# Leaf evaluation
# --------------------------------------------------------------------------

def evaluate_condition(row, condition):
    """Evaluate ONE leaf condition. No eval(), no code execution.

    Returns True/False when the check ran, or an UNKNOWN marker when the
    evidence needed is absent. Raises ConditionError for malformed rules.
    """
    if not isinstance(condition, dict):
        raise ConditionError(f"Condition must be an object, got {type(condition).__name__}.")

    try:
        field = condition["field"]
        op = condition["operator"]
    except KeyError as exc:
        raise ConditionError(f"Condition missing {exc.args[0]!r}: {condition!r}")

    if op not in VALID_OPERATORS:
        raise ConditionError(
            f"Unknown operator {op!r}. Supported: {', '.join(sorted(VALID_OPERATORS))}"
        )

    present = field in row
    row_value = row[field] if present else None
    missing = (not present) or _is_missing(row_value)

    # Presence checks answer even when the field is absent.
    if op == "exists":
        return not missing
    if op == "not_exists":
        return missing

    if "value" not in condition and op != "between":
        raise ConditionError(f"Condition for {field!r} is missing 'value'.")
    value = condition.get("value")

    if missing:
        why = (f"Field {field!r} is not present in the record"
               if not present else f"Field {field!r} is present but empty")
        return _unknown(f"{why}; cannot evaluate.")

    if op in _LIST_OPERATORS and not isinstance(value, (list, tuple, set)):
        raise ConditionError(
            f"Operator {op!r} requires a list value, got {type(value).__name__}."
        )

    try:
        if op == "==":           return row_value == value
        if op == "!=":           return row_value != value
        if op == ">":            return row_value > value
        if op == "<":            return row_value < value
        if op == ">=":           return row_value >= value
        if op == "<=":           return row_value <= value
        if op == "in":           return row_value in value
        if op == "not_in":       return row_value not in value
        if op == "contains":     return str(value).lower() in str(row_value).lower()
        if op == "not_contains": return str(value).lower() not in str(row_value).lower()

        if op == "between":
            bounds = condition.get("value")
            if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
                raise ConditionError("Operator 'between' requires a [low, high] value.")
            low, high = bounds
            return low <= row_value <= high

        if op == "regex":
            pattern = str(value)
            if len(pattern) > MAX_REGEX_LENGTH:
                raise ConditionError(
                    f"Regex pattern exceeds {MAX_REGEX_LENGTH} characters; refusing to run it."
                )
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ConditionError(f"Invalid regex {pattern!r}: {exc}")
            return compiled.search(str(row_value)) is not None

    except ConditionError:
        raise
    except TypeError as exc:
        raise ConditionError(
            f"Cannot apply {op!r} between {row_value!r} and {value!r}."
        ) from exc

    raise ConditionError(f"Operator {op!r} is recognised but not implemented.")


# --------------------------------------------------------------------------
# Tree evaluation
# --------------------------------------------------------------------------

def evaluate_node(row, node, depth=0):
    """Evaluate a condition node, returning True, False, or UNKNOWN."""
    if depth > MAX_DEPTH:
        raise ConditionError(f"Condition nested deeper than {MAX_DEPTH} levels.")

    # Legacy flat list == implicit AND. Keeps pre-tree rules working.
    if isinstance(node, list):
        return _eval_all(row, node, depth)

    if not isinstance(node, dict):
        raise ConditionError(f"Condition node must be an object or list, got {type(node).__name__}.")

    combinators = [k for k in ("all", "any", "not") if k in node]
    if len(combinators) > 1:
        raise ConditionError(
            f"Node has multiple combinators ({', '.join(combinators)}); use one."
        )

    if "all" in node:
        return _eval_all(row, node["all"], depth)
    if "any" in node:
        return _eval_any(row, node["any"], depth)
    if "not" in node:
        inner = evaluate_node(row, node["not"], depth + 1)
        if _is_unknown(inner):
            return inner                       # not(UNKNOWN) is UNKNOWN
        return not inner

    return evaluate_condition(row, node)


def _eval_all(row, children, depth):
    """AND. A single FALSE settles it; otherwise UNKNOWN wins over TRUE."""
    if not isinstance(children, list) or not children:
        raise ConditionError("'all' requires a non-empty list of conditions.")

    unknowns = []
    for child in children:
        result = evaluate_node(row, child, depth + 1)
        if _is_unknown(result):
            unknowns.extend(result.reasons)
            continue
        if result is False:
            return False            # one failed branch settles an AND
    if unknowns:
        return _Unknown(unknowns)   # everything else true, but something unverifiable
    return True


def _eval_any(row, children, depth):
    """OR. A single TRUE settles it; otherwise UNKNOWN wins over FALSE."""
    if not isinstance(children, list) or not children:
        raise ConditionError("'any' requires a non-empty list of conditions.")

    unknowns = []
    for child in children:
        result = evaluate_node(row, child, depth + 1)
        if _is_unknown(result):
            unknowns.extend(result.reasons)
            continue
        if result is True:
            return True             # one satisfied branch settles an OR
    if unknowns:
        return _Unknown(unknowns)   # nothing true, but something unverifiable
    return False


def rule_matches(row, conditions):
    """Whether a rule fires. Raises InsufficientEvidence if it cannot be decided."""
    if not conditions:
        raise ConditionError("Rule has no conditions; refusing to match everything.")
    result = evaluate_node(row, conditions)
    if _is_unknown(result):
        raise InsufficientEvidence("; ".join(result.reasons))
    return result


# --------------------------------------------------------------------------
# Rule-level API (unchanged shape)
# --------------------------------------------------------------------------

def evaluate_rule_status(row, rule):
    """Evaluate ONE rule against ONE record, returning an explicit status."""
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
        result["reason"] = "Conditions matched."
    else:
        result["status"] = Status.PASS
        result["reason"] = "Conditions did not match; record is compliant with this rule."
    return result


def evaluate_row(row, rules):
    """Evaluate every rule against one record."""
    results = [evaluate_rule_status(row, rule) for rule in rules]

    violations = [
        {"rule": r["rule"], "severity": r["severity"], "message": r["message"],
         "framework": r["framework"], "remediation": r["remediation"]}
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

    results.sort(
        key=lambda r: (r["has_errors"], r["has_insufficient"],
                       SEVERITY_RANK.get(r["highest_severity"], 0)),
        reverse=True,
    )
    return results