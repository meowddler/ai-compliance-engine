"""Application-level encryption with key rotation.

Fields are encrypted before they reach the database, so a database dump, a
backup file, or a compromised replica yields ciphertext rather than data.

KEY ROTATION IS THE HARD PART.
Rotating naively — swapping the key and re-encrypting — makes every historical
value unreadable the moment something goes wrong mid-migration. So each
ciphertext carries the ID of the key that produced it:

    <key_id>:<ciphertext>

New writes use the active key. Reads look up whichever key the value was
written with. Rotation is therefore a matter of changing which key is active;
old data stays readable until it is deliberately re-encrypted.

If no keys are configured, encryption is DISABLED and values are stored as
plaintext with an explicit marker. That is a deliberate development
convenience, and `encryption_status()` reports it plainly rather than letting
an operator assume data is protected when it is not.
"""

from cryptography.fernet import Fernet, InvalidToken

from backend.config import ENCRYPTION_ACTIVE_KEY_ID, ENCRYPTION_KEYS

# Marker for values stored without encryption. Explicit, so plaintext can never
# be mistaken for ciphertext under an unknown key.
PLAINTEXT_PREFIX = "plain"


class EncryptionError(Exception):
    """Raised when a value cannot be encrypted or decrypted."""


_ciphers = {}


def _cipher(key_id: str) -> Fernet:
    if key_id not in ENCRYPTION_KEYS:
        raise EncryptionError(
            f"No key configured with id {key_id!r}. The value cannot be read. "
            f"Configured key ids: {', '.join(sorted(ENCRYPTION_KEYS)) or 'none'}"
        )
    if key_id not in _ciphers:
        try:
            _ciphers[key_id] = Fernet(ENCRYPTION_KEYS[key_id].encode())
        except Exception as exc:
            raise EncryptionError(f"Key {key_id!r} is not a valid Fernet key: {exc}")
    return _ciphers[key_id]


def encryption_enabled() -> bool:
    return bool(ENCRYPTION_KEYS and ENCRYPTION_ACTIVE_KEY_ID)


def encrypt(plaintext: str) -> str:
    """Encrypt under the active key, tagging the ciphertext with its key id."""
    if plaintext is None:
        return None
    if not encryption_enabled():
        return f"{PLAINTEXT_PREFIX}:{plaintext}"

    token = _cipher(ENCRYPTION_ACTIVE_KEY_ID).encrypt(plaintext.encode("utf-8"))
    return f"{ENCRYPTION_ACTIVE_KEY_ID}:{token.decode('utf-8')}"


def decrypt(stored: str) -> str:
    """Decrypt using whichever key the value was written with."""
    if stored is None:
        return None
    if ":" not in stored:
        raise EncryptionError("Stored value has no key id prefix; it may be corrupt.")

    key_id, payload = stored.split(":", 1)

    if key_id == PLAINTEXT_PREFIX:
        return payload

    try:
        return _cipher(key_id).decrypt(payload.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # Either the wrong key, or the ciphertext was altered. Fernet
        # authenticates its payload, so tampering is detected rather than
        # silently producing garbage.
        raise EncryptionError(
            f"Could not decrypt a value written under key {key_id!r}. The key is "
            f"wrong or the data has been modified."
        )


def needs_rotation(stored: str) -> bool:
    """True if a value was written under a key that is no longer active."""
    if stored is None or ":" not in stored:
        return False
    key_id = stored.split(":", 1)[0]
    if key_id == PLAINTEXT_PREFIX:
        return encryption_enabled()
    return key_id != ENCRYPTION_ACTIVE_KEY_ID


def rotate(stored: str) -> str:
    """Re-encrypt a value under the active key.

    Decrypt-then-encrypt rather than any shortcut: the plaintext must be
    recoverable under the old key before the new ciphertext is written, so a
    failure leaves the original untouched.
    """
    if stored is None:
        return None
    if not needs_rotation(stored):
        return stored
    return encrypt(decrypt(stored))


def encryption_status() -> dict:
    """Report the real state, so nobody assumes protection that is absent."""
    return {
        "enabled": encryption_enabled(),
        "active_key_id": ENCRYPTION_ACTIVE_KEY_ID or None,
        "configured_key_ids": sorted(ENCRYPTION_KEYS.keys()),
        "note": (
            "Application-level encryption. Values are encrypted before storage, "
            "so a database dump yields ciphertext."
            if encryption_enabled() else
            "DISABLED — no keys configured. Values are stored as plaintext."
        ),
    }