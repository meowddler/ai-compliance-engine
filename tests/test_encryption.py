"""Encryption and key-rotation tests.

The property that matters most is not that encryption works — it is that
rotating a key does not destroy data written under the previous one.
"""
import pytest

import backend.utils.encryption as enc
from backend.utils.encryption import (
    EncryptionError, decrypt, encrypt, encryption_status, needs_rotation, rotate,
)


def test_ciphertext_does_not_contain_the_plaintext():
    secret = "server-admin-password-123"
    stored = encrypt(secret)
    assert secret not in stored


def test_roundtrip():
    secret = "sensitive/path/to/evidence.csv"
    assert decrypt(encrypt(secret)) == secret


def test_ciphertext_is_tagged_with_its_key_id():
    """Without the tag, a rotated key would make old data unreadable."""
    stored = encrypt("x")
    key_id = stored.split(":", 1)[0]
    assert key_id in encryption_status()["configured_key_ids"] or key_id == "plain"


def test_rotation_preserves_old_data(monkeypatch):
    """The critical property: switching keys must not orphan existing values."""
    status = encryption_status()
    if not status["enabled"] or len(status["configured_key_ids"]) < 2:
        pytest.skip("needs two configured keys")

    original_key = status["active_key_id"]
    other_key = next(k for k in status["configured_key_ids"] if k != original_key)

    secret = "written-under-the-old-key"
    old_ciphertext = encrypt(secret)
    assert needs_rotation(old_ciphertext) is False

    monkeypatch.setattr(enc, "ENCRYPTION_ACTIVE_KEY_ID", other_key)

    assert needs_rotation(old_ciphertext) is True
    # Still readable AFTER the key changed — this is what naive rotation breaks.
    assert decrypt(old_ciphertext) == secret

    rotated = rotate(old_ciphertext)
    assert rotated.split(":", 1)[0] == other_key
    assert decrypt(rotated) == secret
    # And the original remains readable, so a partial rotation is recoverable.
    assert decrypt(old_ciphertext) == secret


def test_tampered_ciphertext_is_rejected():
    """Fernet authenticates its payload, so modification is detected rather
    than silently decrypting to garbage."""
    if not encryption_status()["enabled"]:
        pytest.skip("encryption disabled")

    stored = encrypt("value")
    tampered = stored[:-6] + "AAAAAA"
    with pytest.raises(EncryptionError):
        decrypt(tampered)


def test_unknown_key_id_fails_loudly():
    with pytest.raises(EncryptionError):
        decrypt("nonexistent_key:gAAAAABsomethingsomething")


def test_missing_prefix_is_rejected():
    """A value with no key id is corrupt, not plaintext to be returned."""
    with pytest.raises(EncryptionError):
        decrypt("no-prefix-here")


def test_none_passes_through():
    assert encrypt(None) is None
    assert decrypt(None) is None


def test_status_reports_honestly():
    """An operator must never assume protection that is not configured."""
    status = encryption_status()
    assert "enabled" in status and "note" in status
    if not status["enabled"]:
        assert "DISABLED" in status["note"]