"""Structured output handling.

Models return text. When we need machine-readable data, that text must be
parsed and VALIDATED before anything downstream trusts it. An unparseable or
schema-violating response is an error, never a silent partial success —
the same fail-closed principle the rule engine uses.
"""

import json
import re


class StructuredOutputError(Exception):
    """Raised when model output cannot be parsed or fails schema validation."""


def extract_json(text: str) -> dict:
    """Pull a JSON object out of a model response.

    Models sometimes wrap JSON in markdown fences or add stray prose despite
    instructions. We strip fences and take the outermost object. If that fails,
    we raise — we never guess at a partial result.
    """
    if not text or not text.strip():
        raise StructuredOutputError("Model returned an empty response.")

    cleaned = text.strip()
    # strip ```json ... ``` fences if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # fall back to the outermost {...} span
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise StructuredOutputError("No JSON object found in model response.")
    try:
        return json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError as exc:
        raise StructuredOutputError(f"Model response is not valid JSON: {exc}")


VALID_OPERATORS = {"==", "!=", ">", "<", ">=", "<=", "in"}
VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}


def validate_draft_control(data: dict) -> dict:
    """Validate an AI-proposed control against the schema the engine accepts.

    This is the gate between a model's suggestion and our domain. Anything that
    would not survive the real rule schema is rejected here, with a reason.
    """
    required = ["name", "description", "framework", "severity", "remediation", "condition"]
    missing = [f for f in required if f not in data]
    if missing:
        raise StructuredOutputError(f"Missing required fields: {', '.join(missing)}")

    if data["severity"] not in VALID_SEVERITIES:
        raise StructuredOutputError(
            f"Invalid severity {data['severity']!r}; must be one of {sorted(VALID_SEVERITIES)}"
        )

    conditions = data.get("condition")
    if not isinstance(conditions, list) or not conditions:
        raise StructuredOutputError("condition must be a non-empty list.")

    for i, c in enumerate(conditions):
        if not isinstance(c, dict):
            raise StructuredOutputError(f"condition[{i}] must be an object.")
        for key in ("field", "operator", "value"):
            if key not in c:
                raise StructuredOutputError(f"condition[{i}] missing {key!r}.")
        if c["operator"] not in VALID_OPERATORS:
            raise StructuredOutputError(
                f"condition[{i}] has unsupported operator {c['operator']!r}."
            )
        if not str(c["field"]).strip():
            raise StructuredOutputError(f"condition[{i}] has a blank field name.")
        if c["operator"] == "in" and not isinstance(c["value"], list):
            raise StructuredOutputError(f"condition[{i}] uses 'in' but value is not a list.")

    if not str(data["name"]).strip():
        raise StructuredOutputError("name cannot be blank.")

    return data