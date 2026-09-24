"""
Smoke test run against the built wheel and sdist in CI and the release workflow.

Run in an isolated environment with only the built distribution installed,
without and with the ``jwt`` extra (pyjwt):
    uv run --isolated --no-project --with dist/*.whl scripts/smoke_test.py
    uv run --isolated --no-project --with dist/*.whl --with pyjwt scripts/smoke_test.py
"""

import asyncio
import importlib.util
import time

import fastapi_auth
from fastapi_auth import AuthDependency, AuthMethod
from fastapi_auth.settings import AuthSettings

assert set(fastapi_auth.__all__) == {
    "AuthDependency",
    "AuthMethod",
    "PublicRoute",
    "AuthPrincipal",
}

settings = AuthSettings(
    _env_file=None,
    AUTH_ADMIN_API_KEY="smoke-admin",
    AUTH_API_KEYS={"smoke-reports": "reports"},
    AUTH_JWT_KEYS={"smoke": {"secret": "smoke-secret-0123456789-0123456789"}},
)
dep = AuthDependency(valid_token_types={"reports"}, settings=settings)
principal = asyncio.run(dep(credentials=None, api_key="smoke-reports"))
assert principal.method == AuthMethod.AUTH_ADMIN_API_KEY
assert principal.role == "reports"

if importlib.util.find_spec("jwt") is None:
    try:
        AuthDependency(valid_token_types={"jwt"}, settings=settings)
    except ImportError as exc:
        assert "fastapi-auth-manager-dep[jwt]" in str(exc)
    else:
        raise AssertionError("JWT enabled without pyjwt must raise ImportError")
    print("Smoke test passed (without jwt extra)")
else:
    import jwt
    from fastapi.security import HTTPAuthorizationCredentials

    token = jwt.encode(
        {"sub": "smoke-user", "exp": int(time.time()) + 60},
        "smoke-secret-0123456789-0123456789",
        headers={"kid": "smoke"},
    )
    dep = AuthDependency(valid_token_types={"jwt:smoke"}, settings=settings)
    creds = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
    principal = asyncio.run(dep(credentials=creds, api_key=None))
    assert principal.method == AuthMethod.JWT
    assert principal.key_id == "smoke"
    print("Smoke test passed (with jwt extra)")