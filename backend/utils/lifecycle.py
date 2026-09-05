"""Finding lifecycle state machine.

A finding's lifecycle is how the ORGANISATION is handling it — distinct from
the engine's evaluation verdict, which never changes retroactively.

Transitions are validated: you cannot jump from OPEN straight to CLOSED without
passing through remediation and verification. That constraint is what makes the
workflow meaningful to an auditor — a CLOSED finding provably went through
verification.
"""


OPEN = "OPEN"
ACKNOWLEDGED = "ACKNOWLEDGED"
IN_PROGRESS = "IN_PROGRESS"
REMEDIATED = "REMEDIATED"
VERIFIED = "VERIFIED"
CLOSED = "CLOSED"
RISK_ACCEPTED = "RISK_ACCEPTED"
REOPENED = "REOPENED"

ALL_STATES = {OPEN, ACKNOWLEDGED, IN_PROGRESS, REMEDIATED, VERIFIED, CLOSED,
              RISK_ACCEPTED, REOPENED}

# Allowed moves. Anything not listed is rejected.
TRANSITIONS = {
    OPEN:          {ACKNOWLEDGED, RISK_ACCEPTED},
    ACKNOWLEDGED:  {IN_PROGRESS, RISK_ACCEPTED, OPEN},
    IN_PROGRESS:   {REMEDIATED, RISK_ACCEPTED, ACKNOWLEDGED},
    REMEDIATED:    {VERIFIED, REOPENED},
    VERIFIED:      {CLOSED, REOPENED},
    CLOSED:        {REOPENED},
    RISK_ACCEPTED: {REOPENED, ACKNOWLEDGED},
    REOPENED:      {ACKNOWLEDGED, IN_PROGRESS, RISK_ACCEPTED},
}


class InvalidTransition(Exception):
    """Raised when a lifecycle move is not permitted from the current state."""


def validate_transition(current, target):
    """Check a move is allowed. Fails loudly rather than silently accepting."""
    current = current or OPEN
    if target not in ALL_STATES:
        raise InvalidTransition(
            f"Unknown state {target!r}. Valid states: {', '.join(sorted(ALL_STATES))}"
        )
    allowed = TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidTransition(
            f"Cannot move from {current} to {target}. "
            f"Allowed from {current}: {', '.join(sorted(allowed)) or 'none'}"
        )
    return True


def allowed_next(current):
    """The states a finding can legally move to from here — used by the UI."""
    return sorted(TRANSITIONS.get(current or OPEN, set()))