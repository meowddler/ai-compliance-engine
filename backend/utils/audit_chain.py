"""Tamper-evident audit chain.

Each entry stores a hash computed over its own content AND the hash of the
entry before it. Altering, deleting, or reordering any entry breaks every hash
that follows, so tampering is detectable without trusting the database.

    entry N   : hash = H(prev_hash + canonical(payload))
    entry N+1 : hash = H(hash_N     + canonical(payload))

CANONICAL SERIALIZATION IS THE WHOLE GAME.
If the same logical event can serialize two different ways, verification fails
on differences that do not matter and the chain becomes useless. So:

  * keys are sorted
  * separators are fixed (no incidental whitespace)
  * unicode is preserved, not escaped
  * timestamps use a single explicit format in UTC
  * None and missing are normalised to the same thing
  * floats are formatted with repr to avoid platform drift

Any change to this function invalidates every existing hash, so it is
versioned: CANONICAL_VERSION is stored per entry and verification uses the
version the entry was written with.
"""

import hashlib
import json
from datetime import datetime, timezone

CANONICAL_VERSION = "v1"

# The genesis value for the first entry in a chain. A fixed, documented
# constant rather than an empty string, so "no previous entry" is explicit and
# cannot be confused with a missing field.
GENESIS_HASH = "0" * 64

# Fields that are never hashed or stored: they would leak secrets into a
# permanent, deliberately immutable record.
REDACTED_KEYS = {
    "password", "hashed_password", "secret", "token", "access_token",
    "refresh_token", "api_key", "secret_key", "authorization", "cookie",
    "private_key", "mfa_secret", "totp_secret",
}
REDACTION_PLACEHOLDER = "[REDACTED]"


def redact(value, _depth=0):
    """Strip sensitive values before they reach the permanent record.

    Applied to before/after state so a password change is auditable without the
    password itself becoming immutable history.
    """
    if _depth > 12:
        return "[TRUNCATED: too deeply nested]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in REDACTED_KEYS:
                out[k] = REDACTION_PLACEHOLDER
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    return value


def _normalise(value):
    """Convert a value into something with exactly one JSON representation."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, datetime):
        # Always UTC, always the same format. A naive datetime is assumed UTC
        # rather than rejected, so historical rows remain hashable.
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, float):
        # repr gives the shortest round-trippable form and is stable across
        # platforms; str() is not guaranteed to be.
        return repr(value)
    if isinstance(value, (int, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    return str(value)


def canonicalize(payload: dict) -> str:
    """Produce the one and only string form of an audit payload."""
    return json.dumps(
        _normalise(payload),
        sort_keys=True,
        separators=(",", ":"),   # no incidental whitespace
        ensure_ascii=False,      # preserve unicode rather than escaping it
    )


def compute_hash(previous_hash: str, payload: dict) -> str:
    """Hash one entry against its predecessor."""
    if not previous_hash:
        previous_hash = GENESIS_HASH
    material = f"{previous_hash}|{CANONICAL_VERSION}|{canonicalize(payload)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_payload(*, organization_id, actor, action, entity_type=None,
                  entity_id=None, before=None, after=None, reason=None,
                  correlation_id=None, timestamp=None, sequence=None):
    """Assemble the exact field set that gets hashed.

    Defined in one place so writing and verifying can never disagree about
    which fields are covered.
    """
    return {
        "sequence": sequence,
        "timestamp": timestamp or datetime.now(timezone.utc),
        "organization_id": organization_id,
        "actor": actor,
        "action": action,
        "entity_type": entity_type,
        "entity_id": str(entity_id) if entity_id is not None else None,
        "before": redact(before) if before is not None else None,
        "after": redact(after) if after is not None else None,
        "reason": reason,
        "correlation_id": correlation_id,
    }


def verify_chain(entries):
    """Walk a chain in sequence order and report the first break.

    entries: iterable of objects exposing sequence, previous_hash, entry_hash,
             and a `payload()` method returning the hashed field set.

    Returns a result dict. Verification never raises on a broken chain — a
    broken chain is a finding to report, not an error to crash on.
    """
    checked = 0
    expected_previous = GENESIS_HASH

    for entry in entries:
        payload = entry.payload()
        recomputed = compute_hash(entry.previous_hash, payload)

        if entry.previous_hash != expected_previous:
            return {
                "valid": False,
                "reason": "broken_link",
                "detail": ("This entry does not follow the previous one. An entry "
                           "was deleted, reordered, or inserted."),
                "sequence": entry.sequence,
                "expected_previous_hash": expected_previous,
                "actual_previous_hash": entry.previous_hash,
                "entries_verified": checked,
            }

        if recomputed != entry.entry_hash:
            return {
                "valid": False,
                "reason": "payload_modified",
                "detail": "This entry's content no longer matches its recorded hash.",
                "sequence": entry.sequence,
                "expected_hash": recomputed,
                "actual_hash": entry.entry_hash,
                "entries_verified": checked,
            }

        expected_previous = entry.entry_hash
        checked += 1

    return {
        "valid": True,
        "reason": None,
        "detail": f"All {checked} entries verified.",
        "entries_verified": checked,
        "head_hash": expected_previous if checked else GENESIS_HASH,
    }