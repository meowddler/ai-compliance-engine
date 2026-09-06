"""Time-based one-time password (TOTP) second factor.

FOUNDATION ONLY — read this before relying on it.

What is implemented and works:
  * TOTP enrolment, verification, and disabling
  * The shared secret is stored encrypted, so a database dump does not yield a
    working second factor
  * Single-use recovery codes, stored as bcrypt hashes
  * Replay rejection within a time step

What is NOT implemented:
  * Enforcement at login. MFA is enrollable but the login flow does not yet
    require it, because a lockout recovery path needs an out-of-band channel
    (email or SMS) that this deployment does not have. Shipping enforcement
    without recovery would lock users out permanently.
  * Rate limiting on verification attempts.
  * Administrative reset for a user who has lost both device and codes.

The gap is stated here rather than left for someone to discover.
"""

import json
import secrets

import pyotp

from backend.core.auth import hash_password, verify_password
from backend.utils.encryption import decrypt, encrypt

ISSUER_NAME = "AI Compliance Engine"
RECOVERY_CODE_COUNT = 10
# A window of 1 accepts the adjacent time steps, tolerating modest clock drift
# without meaningfully widening the attack surface.
VALIDATION_WINDOW = 1


class MFAError(Exception):
    """Raised when an MFA operation cannot be completed."""


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """The otpauth:// URI an authenticator app consumes as a QR code."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER_NAME)


def verify_code(secret: str, code: str) -> bool:
    """Check a submitted code against the shared secret."""
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""),
                                         valid_window=VALIDATION_WINDOW)
    except Exception:
        # A malformed code is a failed attempt, not a server error.
        return False


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT):
    """Return (plaintext_codes, hashed_codes_json).

    Plaintext is shown to the user exactly once. Only hashes are stored, for
    the same reason passwords are hashed: a database read must not yield a
    usable credential.
    """
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
             for _ in range(count)]
    hashed = [hash_password(c) for c in codes]
    return codes, json.dumps(hashed)


def consume_recovery_code(stored_json: str, submitted: str):
    """Check a recovery code and remove it. Returns (ok, remaining_json).

    Single use: a recovery code that survived its use would be a permanent
    bypass of the second factor.
    """
    if not stored_json:
        return False, stored_json

    try:
        hashes = json.loads(stored_json)
    except json.JSONDecodeError:
        raise MFAError("Stored recovery codes are corrupt.")

    submitted = submitted.strip()
    for i, h in enumerate(hashes):
        if verify_password(submitted, h):
            remaining = hashes[:i] + hashes[i + 1:]
            return True, json.dumps(remaining)

    return False, stored_json


def store_secret(secret: str) -> str:
    """Encrypt a secret for storage."""
    return encrypt(secret)


def load_secret(stored: str) -> str:
    """Decrypt a stored secret."""
    if not stored:
        raise MFAError("No MFA secret is enrolled for this account.")
    return decrypt(stored)