"""Refresh-token lifecycle.

Access tokens are short-lived and stateless — revoking one is impossible, so
they expire quickly instead. Refresh tokens are long-lived and therefore stored
server-side, which makes revocation possible.

Two properties matter:

* Only a HASH of the token is stored. A database read must not yield a usable
  credential.
* Tokens ROTATE on use. If a rotated token is presented again, either it was
  stolen or the legitimate client replayed it — either way the entire family is
  revoked, because an attacker and the user now both hold descendants of the
  same original.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.models.models import RefreshToken, User

REFRESH_TOKEN_BYTES = 32
REFRESH_TOKEN_DAYS = 14


def _hash(token: str) -> str:
    """Tokens are high-entropy random values, so a plain SHA-256 is adequate —
    there is nothing to brute-force the way there is with a password."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_refresh_token(db: Session, user: User, *, family_id: str | None = None,
                        user_agent: str | None = None, ip_address: str | None = None):
    """Mint a refresh token. Returns (raw_token, record).

    The raw value is returned exactly once and never stored.
    """
    raw = secrets.token_urlsafe(REFRESH_TOKEN_BYTES)
    now = datetime.now(timezone.utc)

    record = RefreshToken(
        user_id=user.id,
        organization_id=user.organization_id,
        token_hash=_hash(raw),
        family_id=family_id or secrets.token_hex(16),
        issued_at=now,
        expires_at=now + timedelta(days=REFRESH_TOKEN_DAYS),
        user_agent=(user_agent or "")[:300] or None,
        ip_address=ip_address,
    )
    db.add(record)
    return raw, record


def revoke_family(db: Session, family_id: str, reason: str):
    """Revoke every live token descended from one original.

    Used on replay: once a rotated token reappears, no descendant can be
    trusted, because it is unknown whether the holder is the user or a thief.
    """
    now = datetime.now(timezone.utc)
    count = 0
    for tok in db.query(RefreshToken).filter(
        RefreshToken.family_id == family_id,
        RefreshToken.revoked_at.is_(None),
    ).all():
        tok.revoked_at = now
        tok.revoked_reason = reason
        count += 1
    return count


class RefreshResult:
    def __init__(self, ok, user=None, record=None, error=None, replay=False):
        self.ok, self.user, self.record = ok, user, record
        self.error, self.replay = error, replay


def consume_refresh_token(db: Session, raw_token: str) -> RefreshResult:
    """Validate and rotate a refresh token.

    Returns a result rather than raising: a rejected token is an expected
    outcome, and the caller needs to distinguish replay (a security event worth
    auditing) from ordinary expiry.
    """
    token_hash = _hash(raw_token)
    record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()

    if record is None:
        return RefreshResult(False, error="Invalid refresh token.")

    now = datetime.now(timezone.utc)

    if record.revoked_at is not None:
        # A revoked token being presented means it was rotated and then reused.
        # Treat the whole family as compromised.
        revoked = revoke_family(db, record.family_id, "Replay of a revoked token detected.")
        return RefreshResult(False, error="Refresh token has been revoked.",
                             replay=True, record=record)

    if record.expires_at and record.expires_at < now:
        return RefreshResult(False, error="Refresh token has expired.")

    user = db.query(User).filter(User.id == record.user_id).first()
    if user is None or user.is_active is False:
        revoke_family(db, record.family_id, "Account is no longer active.")
        return RefreshResult(False, error="Account is not active.")

    record.revoked_at = now
    record.revoked_reason = "Rotated on use."
    record.last_used_at = now

    return RefreshResult(True, user=user, record=record)


def active_sessions(db: Session, user: User):
    """Live refresh tokens for a user — one row per active session."""
    now = datetime.now(timezone.utc)
    return (db.query(RefreshToken)
              .filter(RefreshToken.user_id == user.id,
                      RefreshToken.revoked_at.is_(None),
                      RefreshToken.expires_at > now)
              .order_by(RefreshToken.issued_at.desc())
              .all())


def revoke_all_for_user(db: Session, user: User, reason: str) -> int:
    """Log out everywhere."""
    now = datetime.now(timezone.utc)
    count = 0
    for tok in db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked_at.is_(None),
    ).all():
        tok.revoked_at = now
        tok.revoked_reason = reason
        count += 1
    return count