from pydantic import BaseModel
from typing import List, Optional, Any


class RuleCondition(BaseModel):
    field: str          # e.g. "port_exposed"
    operator: str        # ==, !=, >, <, >=, <=, in
    value: Any            # e.g. True, 5, [22, 3389]


class RuleCreate(BaseModel):
    name: str
    description: str
    framework: str
    severity: str
    remediation: str
    condition: List[RuleCondition]
    active: bool = True


class RuleUpdate(BaseModel):
    description: Optional[str] = None
    framework: Optional[str] = None
    severity: Optional[str] = None
    remediation: Optional[str] = None
    condition: Optional[List[RuleCondition]] = None
    active: Optional[bool] = None