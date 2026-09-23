from typing import Optional

from fastapi import Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from .schemas import AuthPrincipal

_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class PublicRoute:
    """
    No-auth dependency for public endpoints.

    When authentication is configured globally on the app
    (via ``app = FastAPI(dependencies=[Depends(AuthDependency())])``),
    use this dependency to opt specific endpoints out of authentication.
    It accepts any request without validation; the global ``AuthDependency``
    detects it on the matched route and skips authentication.

    Usage
    -----
    ```python
    @router.get("/health", dependencies=[Depends(PublicRoute())])
    async def health():
        return {"status": "ok"}
    ```
    """

    async def __call__(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
        api_key: Optional[str] = Security(_api_key_header),
    ) -> None:
        """Always returns None without validating anything."""
        return None
