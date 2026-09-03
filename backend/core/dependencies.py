"""Authentication and authorisation dependencies.

Authorisation reads from the DATABASE, never from token claims. A token carries
a username; the role and organisation are resolved fresh on every request. This
means a privilege change or a disabled account takes effect immediately, and a
forged claim in a token body grants nothing.
"""

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from backend.core.auth import decode_access_token
from backend.database import get_db
from backend.models.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# One message for every authentication failure. Distinguishing "invalid token"
# from "user not found" tells an attacker which usernames exist.
_AUTH_FAILED = "Could not validate credentials"


def get_current_user(token: str = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)) -> User:
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED,
                            headers={"WWW-Authenticate": "Bearer"})
    except Exception:
        # Any other decoding failure is still an auth failure, not a 500.
        raise HTTPException(status_code=401, detail=_AUTH_FAILED,
                            headers={"WWW-Authenticate": "Bearer"})

    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail=_AUTH_FAILED)

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED)

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED)

    # A disabled account must lose access immediately, even while holding a
    # token that has not yet expired.
    if user.is_active is False:
        raise HTTPException(status_code=403, detail="Account is disabled")

    return user


def require_role(allowed_roles: list):
    """Restrict an endpoint to specific roles.

    The role is taken from the database-loaded user, so editing a token's role
    claim has no effect.
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Not authorized for this action")
        return current_user
    return role_checker