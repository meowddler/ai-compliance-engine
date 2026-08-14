import json

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def evaluate_condition(row, condition):
    """Safely checks ONE condition against a row. No eval(), no code execution."""
    field = condition["field"]
    op = condition["operator"]
    value = condition["value"]

    if field not in row:
        return False

    row_value = row[field]

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
    return False


def rule_matches(row, conditions):
    """A rule fires only if ALL its conditions are true (AND logic)."""
    return all(evaluate_condition(row, c) for c in conditions)


def evaluate_row(row, rules):
    violations = []
    for rule in rules:
        try:
            conditions = json.loads(rule.condition)
            if rule_matches(row, conditions):
                violations.append({
                    "rule": rule.name,
                    "severity": rule.severity,
                    "message": rule.description,
                    "framework": rule.framework,
                    "remediation": rule.remediation
                })
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
    return violations


def evaluate_dataframe(df, rules):
    results = []
    for _, row in df.iterrows():
        violations = evaluate_row(row, rules)
        highest_severity = max(violations, key=lambda v: SEVERITY_RANK[v["severity"]])["severity"] if violations else "NONE"

        results.append({
            "server_id": row.get("server_id", "unknown"),
            "highest_severity": highest_severity,
            "violations": violations
        })

    results.sort(key=lambda r: SEVERITY_RANK[r["highest_severity"]], reverse=True)
    return results