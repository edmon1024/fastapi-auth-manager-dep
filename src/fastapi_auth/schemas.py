from typing import Any, Optional

from pydantic import BaseModel

from .enums import AuthMethod


class AuthPrincipal(BaseModel):
    """
    Authentication result returned by AuthDependency.

    Attributes
    ----------
    method  : Mechanism used (``"jwt"`` or ``"api_key"``).
    sub     : Subject identifier (``user_id`` for JWT, raw key value for api-key).
    role    : Api-key label/role (``"admin"``, ``"reports"``…). None for JWT.
    payload : Full JWT payload. None for api-key.
    """

    method: AuthMethod
    sub: str
    role: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
