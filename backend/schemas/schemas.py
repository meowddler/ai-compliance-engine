"""API request schemas.

Validation mirrors the rule engine exactly — the operator set and structural
rules are IMPORTED from it rather than restated here. Two copies would drift,
and a rule that passes validation but errors during a scan is worse than one
rejected at the door.
"""

from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, field_validator

# Single source of truth. If the engine gains an operator, this follows.
from backend.rules.rule_engine import MAX_DEPTH, VALID_OPERATORS

# Operators that do not take a value — they test presence.
_PRESENCE_OPERATORS = {"exists", "not_exists"}
# Operators requiring a list value.
_LIST_OPERATORS = {"in", "not_in"}

COMBINATORS = ("all", "any", "not")


class Severity(str, Enum):
    """The only severity values the system accepts.

    A strict enum so an invalid value ("Critical", "high", a typo) is rejected
    at the boundary with a 422 rather than stored and later crashing a scan.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def _validate_leaf(node: dict, path: str) -> None:
    """Validate a single field test."""
    if "field" not in node:
        raise ValueError(f"{path}: condition is missing 'field'.")
    if "operator" not in node:
        raise ValueError(f"{path}: condition is missing 'operator'.")

    field, op = node["field"], node["operator"]

    if not isinstance(field, str) or not field.strip():
        raise ValueError(f"{path}: 'field' must be a non-empty string.")

    if op not in VALID_OPERATORS:
        raise ValueError(
            f"{path}: unsupported operator {op!r}. "
            f"Must be one of: {', '.join(sorted(VALID_OPERATORS))}"
        )

    if op in _PRESENCE_OPERATORS:
        return                                  # exists/not_exists take no value

    if "value" not in node:
        raise ValueError(f"{path}: operator {op!r} requires a 'value'.")

    value = node["value"]

    if op in _LIST_OPERATORS and not isinstance(value, list):
        raise ValueError(f"{path}: operator {op!r} requires a list value.")

    if op == "between":
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError(f"{path}: operator 'between' requires a [low, high] value.")

    if op == "regex":
        import re
        if not isinstance(value, str):
            raise ValueError(f"{path}: operator 'regex' requires a string pattern.")
        try:
            re.compile(value)
        except re.error as exc:
            # Catching this here means a broken pattern is a 422 at creation
            # rather than an ERROR on every future scan.
            raise ValueError(f"{path}: invalid regex — {exc}")


def _validate_node(node: Any, path: str = "condition", depth: int = 0) -> None:
    """Validate a condition node: a leaf, a combinator, or a legacy flat list."""
    if depth > MAX_DEPTH:
        raise ValueError(f"{path}: nested deeper than {MAX_DEPTH} levels.")

    # Legacy flat list — implicit AND. Still supported.
    if isinstance(node, list):
        if not node:
            raise ValueError(f"{path}: must contain at least one condition.")
        for i, child in enumerate(node):
            _validate_node(child, f"{path}[{i}]", depth + 1)
        return

    if not isinstance(node, dict):
        raise ValueError(f"{path}: must be an object or a list of objects.")

    present = [c for c in COMBINATORS if c in node]
    if len(present) > 1:
        raise ValueError(
            f"{path}: has multiple combinators ({', '.join(present)}); use exactly one."
        )

    if not present:
        _validate_leaf(node, path)
        return

    key = present[0]
    child = node[key]

    if key == "not":
        _validate_node(child, f"{path}.not", depth + 1)
        return

    if not isinstance(child, list) or not child:
        raise ValueError(f"{path}.{key}: requires a non-empty list of conditions.")
    for i, sub in enumerate(child):
        _validate_node(sub, f"{path}.{key}[{i}]", depth + 1)


class RuleCreate(BaseModel):
    name: str
    description: str
    framework: str
    severity: Severity
    remediation: str
    # Any, because the condition is a recursive tree. Structure is checked by
    # _validate_node, which mirrors the engine.
    condition: Any
    active: bool = True

    @field_validator("condition")
    @classmethod
    def condition_must_be_valid(cls, v):
        if v is None:
            raise ValueError("A rule must have a condition.")
        _validate_node(v)
        return v

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Rule name cannot be blank.")
        return v


class RuleUpdate(BaseModel):
    description: Optional[str] = None
    framework: Optional[str] = None
    severity: Optional[Severity] = None
    remediation: Optional[str] = None
    condition: Optional[Any] = None
    active: Optional[bool] = None

    @field_validator("condition")
    @classmethod
    def condition_must_be_valid_if_provided(cls, v):
        if v is None:
            return v
        _validate_node(v)
        return v