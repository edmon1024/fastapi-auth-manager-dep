"""
Full usage example for the authentication dependency.

Required environment variables for this example:
    AUTH_ADMIN_API_KEY=super-secret-admin
    AUTH_API_KEYS='{"key-reports-1": "reports", "key-billing-1": "billing", "key-billing-2": "billing"}'
    AUTH_JWT_SECRET_KEY=jwt-secret
"""

from fastapi import Depends, FastAPI

from fastapi_auth_manager_dep import AuthDependency, AuthPrincipal, PublicRoute

# Labels must match the values defined in AUTH_API_KEYS

# ---------------------------------------------------------------------------
# 1. GLOBAL auth: every endpoint requires at least the ADMIN key
# ---------------------------------------------------------------------------
app = FastAPI(
    title="My API",
    dependencies=[Depends(AuthDependency())],
)


# ---------------------------------------------------------------------------
# 2. ADMIN-key-only endpoint (inherits global, no extra declaration needed)
# ---------------------------------------------------------------------------
@app.get("/admin-only")
async def admin_only():
    return {"message": "Accessible with the ADMIN key only"}


# ---------------------------------------------------------------------------
# 3. Endpoint accepting keys labelled "reports" (+ ADMIN always)
# ---------------------------------------------------------------------------
@app.get(
    "/reports",
    dependencies=[Depends(AuthDependency(valid_token_types={"reports"}))],
)
async def reports():
    return {"message": "Accessible with a 'reports' key or ADMIN"}


# ---------------------------------------------------------------------------
# 4. Endpoint accepting "billing" keys and user JWTs
# ---------------------------------------------------------------------------
@app.get("/billing")
async def billing(
    principal: AuthPrincipal = Depends(
        AuthDependency(valid_token_types={"billing", "jwt"})
    ),
):
    return {
        "message": "Accessible with a 'billing' key, user JWT, or ADMIN",
        "method": principal.method,
        "role": principal.role,
        "sub": principal.sub,
    }


# ---------------------------------------------------------------------------
# 5. Endpoint accepting ALL additional keys with no label filter
# ---------------------------------------------------------------------------
@app.get(
    "/any-key",
    dependencies=[Depends(AuthDependency(valid_token_types=AuthDependency.ALL))],
)
async def any_key():
    return {"message": "Accessible with any api-key defined in AUTH_API_KEYS, or ADMIN"}


# ---------------------------------------------------------------------------
# 6. User JWT + ADMIN key (no additional keys)
# ---------------------------------------------------------------------------
@app.get("/me")
async def me(
    principal: AuthPrincipal = Depends(AuthDependency(valid_token_types={"jwt"})),
):
    return {"sub": principal.sub, "jwt_payload": principal.payload}


# ---------------------------------------------------------------------------
# 7. Public endpoint (opt-out of global auth)
# ---------------------------------------------------------------------------
@app.get("/health", dependencies=[Depends(PublicRoute())])
async def health():
    return {"status": "ok"}
