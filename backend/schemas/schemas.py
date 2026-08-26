from enum import Enum
from typing import List, Optional, Any

from pydantic import BaseModel, field_validator


class Severity(str, Enum):
    """The only severity values the system accepts.

    Defined as a strict enum so an invalid value (e.g. "Critical", "high",
    a typo) is rejected at the API boundary with a clean 422, instead of
    being stored and later crashing a scan when downstream code looks it up
    in a severity map. Validate at the edge; never let bad data in.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Operators the rule engine actually supports. Kept in sync with
# rule_engine.evaluate_condition so a rule can't be created with an operator
# the engine will later reject as an evaluation error.
VALID_OPERATORS = {"==", "!=", ">", "<", ">=", "<=", "in"}


class RuleCondition(BaseModel):
    field: str          # e.g. "port_exposed"
    operator: str        # ==, !=, >, <, >=, <=, in
    value: Any            # e.g. True, 5, [22, 3389]

    @field_validator("operator")
    @classmethod
    def operator_must_be_supported(cls, v: str) -> str:
        if v not in VALID_OPERATORS:
            raise ValueError(
                f"Unsupported operator {v!r}. Must be one of: {', '.join(sorted(VALID_OPERATORS))}"
            )
        return v

    @field_validator("field")
    @classmethod
    def field_must_not_be_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Condition field cannot be blank.")
        return v


class RuleCreate(BaseModel):
    name: str
    description: str
    framework: str
    severity: Severity
    remediation: str
    condition: List[RuleCondition]
    active: bool = True

    @field_validator("condition")
    @classmethod
    def must_have_at_least_one_condition(cls, v):
        # A rule with no conditions would match every row (see rule_engine),
        # which is almost never intended. Reject it at creation.
        if not v:
            raise ValueError("A rule must have at least one condition.")
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
    condition: Optional[List[RuleCondition]] = None
    active: Optional[bool] = None

    @field_validator("condition")
    @classmethod
    def condition_not_empty_if_provided(cls, v):
        # On update, condition is optional — but if it IS provided, it can't be
        # an empty list, for the same match-everything reason as on create.
        if v is not None and len(v) == 0:
            raise ValueError("A rule must have at least one condition.")
        return v