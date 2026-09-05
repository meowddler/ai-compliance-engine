"""Capability-based authorisation.

Endpoints check CAPABILITIES, not role names. A role is a bundle of
capabilities, so changing what a role may do is a data change here rather than
an edit scattered across every endpoint — and a typo becomes an ImportError
instead of a silent authorisation hole.
"""

from fastapi import Depends, HTTPException

from backend.core.dependencies import get_current_user
from backend.models.models import User


class Capability:
    CONTROLS_READ = "controls.read"
    CONTROLS_CREATE = "controls.create"
    CONTROLS_EDIT = "controls.edit"
    CONTROLS_APPROVE = "controls.approve"
    CONTROLS_DELETE = "controls.delete"

    EVIDENCE_READ = "evidence.read"
    EVIDENCE_INGEST = "evidence.ingest"
    EVIDENCE_VERIFY = "evidence.verify"

    FINDINGS_READ = "findings.read"
    FINDINGS_UPDATE = "findings.update"
    RISK_ACCEPT = "risk.accept"

    AUDIT_READ = "audit.read"
    AUDIT_VERIFY = "audit.verify"

    REPORTS_GENERATE = "reports.generate"
    DATA_DELETE = "data.delete"
    AI_USE = "ai.use"
    AI_APPROVE_DRAFT = "ai.approve_draft"

    USER_MANAGE = "user.manage"
    ORGANIZATION_MANAGE = "organization.manage"


# Role definitions. An Analyst can supply evidence and work findings but cannot
# author or approve controls — the people who define what "compliant" means are
# deliberately separated from those who operate the system day to day.
ROLE_CAPABILITIES = {
    "Admin": {
        Capability.CONTROLS_READ, Capability.CONTROLS_CREATE, Capability.CONTROLS_EDIT,
        Capability.CONTROLS_DELETE,
        Capability.EVIDENCE_READ, Capability.EVIDENCE_INGEST, Capability.EVIDENCE_VERIFY,
        Capability.FINDINGS_READ, Capability.FINDINGS_UPDATE,
        Capability.AUDIT_READ, Capability.AUDIT_VERIFY,
        Capability.REPORTS_GENERATE, Capability.DATA_DELETE,
        Capability.AI_USE, Capability.AI_APPROVE_DRAFT,
        Capability.USER_MANAGE, Capability.ORGANIZATION_MANAGE,
        # Deliberately NOT granted: CONTROLS_APPROVE and RISK_ACCEPT.
        # An administrator who can create a control must not also be the one who
        # approves it — see separation of duties below.
    },
    "Auditor": {
        Capability.CONTROLS_READ, Capability.CONTROLS_EDIT, Capability.CONTROLS_APPROVE,
        Capability.EVIDENCE_READ, Capability.EVIDENCE_VERIFY,
        Capability.FINDINGS_READ, Capability.FINDINGS_UPDATE,
        Capability.RISK_ACCEPT,
        Capability.AUDIT_READ, Capability.AUDIT_VERIFY,
        Capability.REPORTS_GENERATE, Capability.AI_USE,
    },
    "Analyst": {
        Capability.CONTROLS_READ,
        Capability.EVIDENCE_READ, Capability.EVIDENCE_INGEST,
        Capability.FINDINGS_READ, Capability.FINDINGS_UPDATE,
        Capability.REPORTS_GENERATE, Capability.AI_USE,
    },
}


def capabilities_for(role: str) -> set:
    return ROLE_CAPABILITIES.get(role, set())


def has_capability(user: User, capability: str) -> bool:
    return capability in capabilities_for(user.role)


def require_capability(capability: str):
    """Dependency enforcing one capability.

    The role is read from the database-loaded user, so a token claim cannot
    grant a capability the account does not have.
    """
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if not has_capability(current_user, capability):
            raise HTTPException(
                status_code=403,
                detail=f"This action requires the {capability!r} capability."
            )
        return current_user
    return checker


# --- Separation of duties --------------------------------------------------

class SeparationOfDutiesError(Exception):
    """Raised when one person would occupy two roles that must stay distinct."""


def assert_not_self_approval(author_username: str, approver_username: str, subject: str):
    """A person may not approve their own work.

    Enforced in code rather than left to policy: a control whose author and
    approver are the same person has had no independent review, whatever the
    process document says.
    """
    if author_username and author_username == approver_username:
        raise SeparationOfDutiesError(
            f"{approver_username} cannot approve their own {subject}. "
            f"Independent approval is required."
        )