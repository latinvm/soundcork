"""Optional HTTP Basic auth for the human-facing admin and management routers.

Auth is enabled only when both ``ADMIN_BASIC_AUTH_USER`` and
``ADMIN_BASIC_AUTH_PASSWORD`` are set. When either is empty, the
returned dependency list is empty and the protected routers behave
exactly as they did before.

This is intentionally minimal: it is meant for trusted home-LAN
deployments. It does not replace running soundcork behind a firewall.
"""

import hmac

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from soundcork.config import Settings

_security = HTTPBasic()


def basic_auth_dependencies(settings: Settings) -> list:
    """Return a ``dependencies=`` list for ``app.include_router(...)``.

    Empty list when auth is disabled (default), so existing users see
    no behaviour change.
    """
    expected_user = settings.admin_basic_auth_user
    expected_password = settings.admin_basic_auth_password
    if not expected_user or not expected_password:
        return []

    expected_user_b = expected_user.encode()
    expected_password_b = expected_password.encode()

    def verify(credentials: HTTPBasicCredentials = Depends(_security)) -> None:
        user_ok = hmac.compare_digest(credentials.username.encode(), expected_user_b)
        pw_ok = hmac.compare_digest(credentials.password.encode(), expected_password_b)
        if not (user_ok and pw_ok):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

    return [Depends(verify)]
