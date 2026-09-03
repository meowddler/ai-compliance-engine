"""Password hashing and JWT issue/verification."""

from datetime import datetime, timedelta, timezone

from jose import jwt
from passlib.context import CryptContext

from backend.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password, returning False rather than raising on a malformed hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # A corrupt or non-bcrypt hash must read as "wrong password", not as a
        # 500 that reveals the account exists.
        return False


def create_access_token(data: dict) -> str:
    """Issue a signed access token.

    Includes `iat` alongside `exp` so a token's age is verifiable, and marks the
    token type so a future refresh-token flow cannot accept the wrong kind.
    """
    now = datetime.now(timezone.utc)
    to_encode = data.copy()
    to_encode.update({
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "typ": "access",
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and verify a token. Raises JWTError if invalid or expired."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])