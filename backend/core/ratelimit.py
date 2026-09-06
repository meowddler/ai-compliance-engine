"""Rate limiting.

Limits are per-identity, not per-IP. Behind a proxy or NAT many users share an
address, so IP-based limiting either punishes innocent users or fails to
constrain a determined one. An authenticated request is limited by its
organisation; an unauthenticated one falls back to IP because that is all there
is.

Tiers reflect cost and risk rather than a single global number:

  auth   — strict. Unlimited password attempts is a brute-force invitation, and
           this is the one endpoint an attacker can reach without credentials.
  ai     — strict. Each call costs money and can hold a connection for a minute.
  write  — moderate. Uploads and mutations do real work.
  read   — generous. Cheap, and throttling them just makes the product feel broken.
"""

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.core.auth import decode_access_token

# Tier definitions. Kept in one place so a limit is changed once rather than
# hunted through decorators.
LIMIT_AUTH = "10/minute"
LIMIT_AI = "20/hour"
LIMIT_WRITE = "60/minute"
LIMIT_READ = "300/minute"


def identify_client(request: Request) -> str:
    """Derive the key a request is limited against.

    Reads the organisation from the token WITHOUT a database lookup — rate
    limiting runs before authentication and must not add a query to every
    request. The token signature is still verified, so a forged org id cannot
    be used to borrow another tenant's allowance.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        try:
            payload = decode_access_token(token)
            org = payload.get("org")
            sub = payload.get("sub")
            if org is not None:
                return f"org:{org}"
            if sub:
                return f"user:{sub}"
        except Exception:  # noqa: S110 - deliberate: see below
            # Any token that cannot be decoded — expired, forged, malformed —
            # falls through to IP-based limiting. Failing open here would let an
            # attacker escape the limiter simply by sending a bad token, and the
            # request is about to be rejected by authentication anyway.
            pass

    return f"ip:{get_remote_address(request)}"


limiter = Limiter(
    key_func=identify_client,
    default_limits=[LIMIT_READ],
    # Response headers are disabled deliberately. slowapi injects them by
    # mutating a Response parameter, which every limited endpoint would have to
    # declare — adding a parameter to each signature purely to satisfy the
    # library. The 429 response already states the limit that was exceeded,
    # which is the information a client actually needs.
    headers_enabled=False,
)