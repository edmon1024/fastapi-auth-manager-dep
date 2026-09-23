import logging
from enum import Enum
from typing import Optional

import jwt as pyjwt
from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from .enums import AuthMethod
from .public import PublicRoute
from .schemas import AuthPrincipal
from .settings import AuthSettings, get_auth_settings

logger = logging.getLogger(__name__)

# Security schemes shared across all instances (module-level singletons)
_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Sentinel value for "allow all additional api-keys"
_ALL = object()


class AuthDependency:
    """
    Authentication dependency for FastAPI.

    Supported mechanisms
    --------------------
    - **API Key** via ``X-API-Key`` header
    - **JWT Bearer** via ``Authorization: Bearer <token>`` header
      (only when ``"jwt"`` is included in ``valid_token_types``)

    Api-key logic
    -------------
    The ADMIN key (``AUTH_ADMIN_API_KEY`` envvar) is a **super-key**: always valid on any
    endpoint, regardless of ``valid_token_types``.

    Additional keys are defined in the ``AUTH_API_KEYS`` envvar as JSON::

        AUTH_API_KEYS='{"key-abc": "reports", "key-xyz": "billing"}'

    Each key's label must be used for per-endpoint restrictions via ``valid_token_types``.

    Controlling which keys a given instance accepts
    -----------------------------------------------
    ``valid_token_types=None``
        ADMIN key only (default behaviour).

    ``valid_token_types={"reports"}``
        ADMIN key + all keys labelled ``"reports"``.

    ``valid_token_types="*"`` or ``valid_token_types=AuthDependency.ALL``
        ADMIN key + **all** additional keys with no label filter.

    Quick reference
    ---------------
    ::

        # Global: ADMIN key only
        app = FastAPI(dependencies=[Depends(AuthDependency())])

        # Endpoint: accept "reports" keys and user JWTs
        @router.get("/report", dependencies=[Depends(
            AuthDependency(valid_token_types={"reports", "jwt"})
        )])

        # Endpoint: accept all additional keys
        @router.get("/open", dependencies=[Depends(
            AuthDependency(valid_token_types=AuthDependency.ALL)
        )])

        # Access the authenticated principal inside the handler
        @router.get("/me")
        async def me(principal: AuthPrincipal = Depends(AuthDependency(...))):
            return principal

    Precedence
    ----------
    The most specific declaration wins. An instance applied globally (app or
    router ``dependencies``) defers to a ``PublicRoute`` or another
    ``AuthDependency`` declared later on the route (router, route
    ``dependencies`` or handler parameter). Only top-level route dependencies
    are considered, not ones nested inside other dependencies.
    """

    #: Sentinel to allow all additional api-keys without label filtering.
    ALL = _ALL

    def __init__(
        self,
        valid_token_types: "set[str | Enum] | object | None" = None,
        settings: AuthSettings | None = None,
    ) -> None:
        """
        Parameters
        ----------
        valid_token_types:
            - ``None``                       → ADMIN key only.
            - ``{"role-a"}``                 → ADMIN key + keys labelled ``"role-a"``.
            - ``AuthDependency.ALL`` / ``"*"`` → ADMIN key + all additional keys.
            - Include ``"jwt"`` to enable user JWT authentication
              (requires ``AUTH_JWT_SECRET_KEY``).
        settings:
            Configuration injection. Defaults to ``get_auth_settings()``.

        Raises
        ------
        ValueError if ``"jwt"`` is enabled but ``AUTH_JWT_SECRET_KEY`` is empty.
        """
        self._settings = settings or get_auth_settings()
        self._allow_all_keys: bool = valid_token_types is _ALL or valid_token_types == "*"

        if self._allow_all_keys:
            self._valid_token_types: set[str] = set()
        else:
            self._valid_token_types = self._normalize(valid_token_types)

        # Fail at startup instead of on every request
        if "jwt" in self._valid_token_types and not self._settings.AUTH_JWT_SECRET_KEY:
            raise ValueError(
                "AUTH_JWT_SECRET_KEY must be set when 'jwt' is in valid_token_types."
            )

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(raw: "set[str | Enum] | None") -> set[str]:
        """Converts a mixed Enum/str set to a plain set of strings."""
        if not raw:
            return set()
        result: set[str] = set()
        for item in raw:
            result.add(item.value if isinstance(item, Enum) else str(item))
        return result

    # ------------------------------------------------------------------
    # Allowed api-key set construction
    # ------------------------------------------------------------------

    def _allowed_api_keys(self) -> set[str]:
        """
        Returns the set of valid api-keys for this instance.

        Rules:
        1. ADMIN key is always included (super-key).
        2. If ``_allow_all_keys`` → every key from ``AUTH_API_KEYS``.
        3. Otherwise → only keys whose label is in ``_valid_token_types``.
        """
        allowed: set[str] = set()

        # 1. ADMIN super-key (always)
        if self._settings.AUTH_ADMIN_API_KEY:
            allowed.add(self._settings.AUTH_ADMIN_API_KEY)

        # 2. Additional keys according to policy
        if self._allow_all_keys:
            allowed.update(k for k in self._settings.AUTH_API_KEYS if k)
        else:
            for label in self._valid_token_types:
                if label == "jwt":
                    continue  # label is "jwt", which indicates JWT auth, not an api-key
                allowed.update(self._settings.keys_for_label(label))

        return allowed

    # ------------------------------------------------------------------
    # JWT verification
    # ------------------------------------------------------------------

    def _verify_jwt(self, token: str) -> dict:
        """
        Decodes and validates an HMAC JWT.

        Raises
        ------
        HTTPException 401 for invalid, expired, or disallowed-algorithm tokens.
        """
        try:
            header = pyjwt.get_unverified_header(token)
            alg = header.get("alg")
            if alg not in self._settings.AUTH_JWT_ALGORITHMS:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"JWT algorithm not allowed: {alg}",
                )
            payload = pyjwt.decode(
                token,
                self._settings.AUTH_JWT_SECRET_KEY,
                algorithms=self._settings.AUTH_JWT_ALGORITHMS,
            )
            return payload
        except HTTPException:
            raise
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="JWT token has expired",
            )
        except pyjwt.InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid JWT token: {exc}",
            )
        except pyjwt.PyJWTError:
            # e.g. InvalidKeyError: a server-side key problem, not the caller's
            # token; don't leak details and don't turn it into a 500.
            logger.exception("AUTH: JWT verification failed due to a key error")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )

    # ------------------------------------------------------------------
    # Api-key verification
    # ------------------------------------------------------------------

    def _verify_api_key(self, api_key: str) -> str:
        """
        Validates the api-key against the allowed set.

        Returns
        -------
        The label/role associated with the key (``"admin"`` for the ADMIN key).

        Raises
        ------
        HTTPException 401 if the key is not in the allowed set.
        """
        if api_key not in self._allowed_api_keys():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        return self._settings.label_for_key(api_key) or "unknown"

    # ------------------------------------------------------------------
    # Route precedence
    # ------------------------------------------------------------------

    def _overriding_dependency(
        self, request: Optional[Request]
    ) -> "AuthDependency | PublicRoute | None":
        """
        Returns the more specific ``AuthDependency`` / ``PublicRoute`` declared
        on the matched route, or ``None`` if this instance is the one to apply.
        """
        route = request.scope.get("route") if request is not None else None
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            return None

        calls = [dep.call for dep in dependant.dependencies]
        # Not in the route's list → applied globally, every route declaration
        # is more specific. Otherwise only the ones declared after it are.
        later = calls[calls.index(self) + 1:] if self in calls else calls
        markers = [c for c in later if isinstance(c, (AuthDependency, PublicRoute))]
        return markers[-1] if markers else None

    # ------------------------------------------------------------------
    # Main callable
    # ------------------------------------------------------------------

    async def __call__(
        self,
        request: Request = None,  # type: ignore[assignment]
        credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
        api_key: Optional[str] = Security(_api_key_header),
    ) -> Optional[AuthPrincipal]:
        """
        Evaluation order:
        0. Precedence  → defer to a more specific ``PublicRoute`` (no auth,
           returns ``None``) or ``AuthDependency`` on the route.
        1. JWT Bearer  → if ``"jwt"`` is enabled and a Bearer token is present.
        2. API Key     → if the ``X-API-Key`` header is present.
        3. 401         → no valid mechanism found.

        Returns
        -------
        :class:`AuthPrincipal` with method, sub, role, and optional payload,
        or ``None`` on a public route.
        """
        # 0. A more specific declaration on the route takes over
        override = self._overriding_dependency(request)
        if isinstance(override, PublicRoute):
            return None
        if override is not None:
            return await override(request, credentials, api_key)

        # 1. JWT
        jwt_enabled = "jwt" in self._valid_token_types
        if jwt_enabled and credentials and credentials.scheme.lower() == "bearer":
            payload = self._verify_jwt(credentials.credentials)
            return AuthPrincipal(
                method=AuthMethod.JWT,
                sub=payload.get("sub", ""),
                payload=payload,
            )

        # 2. API Key
        if api_key:
            label = self._verify_api_key(api_key)
            return AuthPrincipal(
                method=AuthMethod.AUTH_ADMIN_API_KEY,
                sub=api_key,
                role=label,
            )

        # 3. No credentials → 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials are required",
        )
