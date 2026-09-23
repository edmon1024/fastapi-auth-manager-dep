"""
Smoke test run against the built wheel and sdist in the release workflow.

Run in an isolated environment with only the built distribution installed:
    uv run --isolated --no-project --with dist/*.whl scripts/smoke_test.py
"""

import asyncio

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
    AUTH_ADMIN_API_KEY="smoke-admin",
    AUTH_API_KEYS={"smoke-reports": "reports"},
    AUTH_JWT_SECRET_KEY="",
)
dep = AuthDependency(valid_token_types={"reports"}, settings=settings)
principal = asyncio.run(dep(credentials=None, api_key="smoke-reports"))
assert principal.method == AuthMethod.AUTH_ADMIN_API_KEY
assert principal.role == "reports"

print("Smoke test passed")