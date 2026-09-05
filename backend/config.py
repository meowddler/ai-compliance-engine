"""Central configuration.

Every environment-dependent value and secret is read here and nowhere else, so
there is a single place to audit what the application trusts from its
environment.

Configuration errors fail at startup, not at request time. A service that boots
with a missing secret or the wrong database is more dangerous than one that
refuses to boot at all.
"""

import os

from dotenv import load_dotenv

load_dotenv()

# Signing algorithms we are willing to accept. Reading this from the
# environment without a whitelist would allow "none", which disables signature
# verification entirely.
_ALLOWED_ALGORITHMS = {"HS256", "HS384", "HS512"}

# Short secrets are brute-forceable. 32 hex chars is the minimum we accept.
_MIN_SECRET_LENGTH = 32


def _required(key: str) -> str:
    """Fetch a required variable, or refuse to start."""
    value = os.getenv(key)
    if not value:
        raise RuntimeError(
            f"Required environment variable {key!r} is not set. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


def _int(key: str, default: str) -> int:
    """Integer setting with a clear error instead of a bare ValueError."""
    raw = os.getenv(key, default)
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"Environment variable {key!r} must be an integer, got {raw!r}.")


# --- Security ---------------------------------------------------------------

SECRET_KEY = _required("SECRET_KEY")
if len(SECRET_KEY) < _MIN_SECRET_LENGTH:
    raise RuntimeError(
        f"SECRET_KEY must be at least {_MIN_SECRET_LENGTH} characters. "
        f"Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

ALGORITHM = os.getenv("ALGORITHM", "HS256")
if ALGORITHM not in _ALLOWED_ALGORITHMS:
    raise RuntimeError(
        f"ALGORITHM {ALGORITHM!r} is not permitted. Allowed: {', '.join(sorted(_ALLOWED_ALGORITHMS))}"
    )

ACCESS_TOKEN_EXPIRE_MINUTES = _int("ACCESS_TOKEN_EXPIRE_MINUTES", "60")

# Empty by default: an unset allowlist blocks all cross-origin requests rather
# than permitting them.
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]


# --- Database ---------------------------------------------------------------

# Required, not defaulted. A silent fallback to SQLite would let the app boot
# against an empty local file while appearing to work — the worst kind of
# misconfiguration, because nothing looks wrong.
DATABASE_URL = _required("DATABASE_URL")


# --- Compliance settings ----------------------------------------------------

EVIDENCE_FRESHNESS_DAYS = _int("EVIDENCE_FRESHNESS_DAYS", "90")


# --- AI layer ---------------------------------------------------------------

_ALLOWED_PROVIDERS = {"nvidia", "stub"}

AI_PROVIDER = os.getenv("AI_PROVIDER", "nvidia")
if AI_PROVIDER not in _ALLOWED_PROVIDERS:
    raise RuntimeError(
        f"AI_PROVIDER {AI_PROVIDER!r} is not supported. "
        f"Allowed: {', '.join(sorted(_ALLOWED_PROVIDERS))}"
    )

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", "https://integrate.api.nvidia.com/v1")
AI_MODEL = os.getenv("AI_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")



# --- Encryption -------------------------------------------------------------
# Keys are held as id:key pairs so data encrypted under an old key stays
# readable after rotation. ENCRYPTION_ACTIVE_KEY_ID names which one is used for
# new writes; the others remain available for decryption only.
#
# Format: ENCRYPTION_KEYS=k1:<base64key>,k2:<base64key>

def _parse_keys(raw: str) -> dict:
    keys = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            raise RuntimeError("ENCRYPTION_KEYS entries must be 'key_id:key'.")
        key_id, key = pair.split(":", 1)
        keys[key_id.strip()] = key.strip()
    return keys


ENCRYPTION_KEYS = _parse_keys(os.getenv("ENCRYPTION_KEYS", ""))
ENCRYPTION_ACTIVE_KEY_ID = os.getenv("ENCRYPTION_ACTIVE_KEY_ID", "")

if ENCRYPTION_KEYS and ENCRYPTION_ACTIVE_KEY_ID not in ENCRYPTION_KEYS:
    raise RuntimeError(
        f"ENCRYPTION_ACTIVE_KEY_ID {ENCRYPTION_ACTIVE_KEY_ID!r} is not present in "
        f"ENCRYPTION_KEYS. Available: {', '.join(sorted(ENCRYPTION_KEYS)) or 'none'}"
    )