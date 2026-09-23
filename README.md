# fastapi-auth-manager-dep

Reusable authentication dependency for FastAPI with **API Key** and **JWT Bearer** support.

- One mandatory ADMIN key via envvar (super-key, always valid)
- Additional api-keys with labels/roles via JSON envvar
- Fine-grained per-endpoint control: which roles each endpoint accepts
- HMAC JWT with configurable algorithms
- Public endpoints via explicit opt-out

---

## Install

```bash
pip install fastapi-auth-manager-dep
```

---

## Environment variables

| Variable          | Required | Description                                                                   |
|-------------------|----------|-------------------------------------------------------------------------------|
| `AUTH_ADMIN_API_KEY`         | Yes      | Administrator api-key. Super-key: valid on every endpoint.                    |
| `AUTH_API_KEYS`        | No       | JSON object mapping api-keys to their labels. See format below.               |
| `AUTH_JWT_SECRET_KEY`| No*      | HMAC secret key for verifying user JWTs. Required when using `"jwt"`. |
| `AUTH_JWT_ALGORITHMS`  | No       | List of allowed algorithms (default: `["HS256", "HS384", "HS512"]`).          |

### `AUTH_API_KEYS` format

A JSON object where each key is the raw api-key value and the value is its label/role:

```bash
AUTH_API_KEYS='{"key-abc123": "reports", "key-xyz789": "billing", "key-qrs456": "billing"}'
```

- Multiple keys can share the same label (same role).
- Empty string (`AUTH_API_KEYS=""`) is equivalent to having no additional keys.

### `.env` example

```dotenv
AUTH_ADMIN_API_KEY=super-secret-admin-key
AUTH_API_KEYS={"key-reports-1": "reports", "key-billing-1": "billing", "key-billing-2": "billing"}
AUTH_JWT_SECRET_KEY=my-jwt-secret-key
```

---

## Usage

### 1. Global authentication (entire app)

All endpoints are protected with the ADMIN key by default:

```python
from fastapi import Depends, FastAPI
from fastapi_auth import AuthDependency

app = FastAPI(dependencies=[Depends(AuthDependency())])
```

The most specific declaration wins: an `AuthDependency` or `PublicRoute` declared on a
router, on a route's `dependencies` or as a handler parameter replaces the global one for
that route, so it can widen access (e.g. accept `"reports"` keys) as well as narrow it.
Only top-level route dependencies count, not ones nested inside your own dependencies.

### 2. Restrict by api-key label

Only the ADMIN key and keys labelled `"reports"` can access:

```python
from fastapi_auth import AuthDependency

@app.get(
    "/reports",
    dependencies=[Depends(AuthDependency(valid_token_types={"reports"}))]
)
async def get_reports():
    ...
```

### 3. Combine api-key and JWT on the same endpoint

```python
from fastapi_auth import AuthDependency

@app.get(
    "/billing",
    dependencies=[Depends(AuthDependency(valid_token_types={"billing", "jwt"}))]
)
async def get_billing():
    ...
```

### 4. Allow all additional api-keys

```python
from fastapi_auth import AuthDependency

# Using the AuthDependency.ALL sentinel
@app.get(
    "/any",
    dependencies=[Depends(AuthDependency(valid_token_types=AuthDependency.ALL))]
)
async def any_key_endpoint():
    ...

# Equivalent using a string
AuthDependency(valid_token_types="*")
```

### 5. Access the authenticated principal inside a handler

`AuthDependency` returns an `AuthPrincipal` with the method used, role, and JWT payload:

```python
from fastapi_auth import AuthDependency, AuthPrincipal

@app.get("/me")
async def me(
    principal: AuthPrincipal = Depends(
        AuthDependency(valid_token_types={"jwt", "billing"})
    )
):
    return {
        "method":  principal.method,   # "jwt" | "api_key"
        "sub":     principal.sub,       # user_id (JWT) or raw key value (api-key)
        "role":    principal.role,      # "admin" | "reports" | "billing" | None (JWT)
        "payload": principal.payload,   # full JWT dict | None
    }
```

### 6. Public endpoint (opt-out of global auth)

When auth is configured globally, use `PublicRoute` to exclude specific endpoints
(requests are accepted with or without credentials):

```python
from fastapi_auth import PublicRoute

@app.get("/health", dependencies=[Depends(PublicRoute())])
async def health():
    return {"status": "ok"}
```

---

## `valid_token_types` behaviour reference

| `valid_token_types`          | ADMIN key | Additional keys         | User JWT |
|------------------------------|-----------|-------------------------|----------|
| `None` (default)             | Yes       | No                      | No       |
| `{"reports"}`                | Yes       | `reports` label only    | No       |
| `{"billing", "jwt"}`         | Yes       | `billing` label only    | Yes      |
| `AuthDependency.ALL` / `"*"` | Yes       | All                     | No       |
| `{"jwt"}`                    | Yes       | No                      | Yes      |

> The ADMIN key is always valid regardless of the endpoint configuration.

---

## `AuthPrincipal` — return object

```python
class AuthPrincipal(BaseModel):
    method:  AuthMethod           # AuthMethod.JWT | AuthMethod.AUTH_ADMIN_API_KEY
    sub:     str                  # user_id (JWT) or raw api-key value
    role:    str | None = None    # key role/label; None for JWT
    payload: dict | None = None   # full JWT payload; None for api-key
```

---

## Error responses

All authentication errors return HTTP `401 Unauthorized` with a `detail` field:

| Situation                            | `detail`                                  |
|--------------------------------------|-------------------------------------------|
| No credentials provided              | `"Authentication credentials are required"` |
| Api-key not found or not allowed     | `"Invalid authentication credentials"`   |
| Expired JWT                          | `"JWT token has expired"`                 |
| Invalid JWT signature                | `"Invalid JWT token: ..."`               |
| Disallowed JWT algorithm             | `"JWT algorithm not allowed: RS256"`      |
| JWT key misconfigured on the server  | `"Invalid authentication credentials"`   |

> Enabling `"jwt"` without `AUTH_JWT_SECRET_KEY` raises `ValueError` when the
> `AuthDependency` is created, so the misconfiguration fails at startup.

---

## Tests

Development uses [uv](https://docs.astral.sh/uv/); test tools are in the `dev` dependency group:

```bash
uv run pytest -v
```

Test coverage includes:

- ADMIN key as super-key across endpoints with different restrictions
- Label-based restriction: accepts the correct label, rejects others
- Multiple keys sharing the same label
- `ALL` sentinel and its `"*"` string equivalent
- Valid JWT, expired JWT, JWT ignored when `"jwt"` is not enabled
- JWT enabled without a secret (fails at startup, never HTTP 500)
- No credentials
- Global auth over HTTP: `PublicRoute` opt-out, route-level widening/narrowing, principal from a handler parameter
- `AUTH_API_KEYS` validation in settings (JSON string, dict, invalid JSON)

---

## Full example

```python
from fastapi import Depends, FastAPI
from fastapi_auth import AuthDependency, AuthPrincipal, PublicRoute

app = FastAPI(dependencies=[Depends(AuthDependency())])  # global: ADMIN key only

@app.get("/health", dependencies=[Depends(PublicRoute())])
async def health():
    return {"status": "ok"}

@app.get("/reports", dependencies=[Depends(AuthDependency(valid_token_types={"reports"}))])
async def reports():
    return {"data": "..."}

@app.get("/me")
async def me(
    principal: AuthPrincipal = Depends(AuthDependency(valid_token_types={"jwt"}))
):
    return {"sub": principal.sub, "payload": principal.payload}

@app.get("/internal", dependencies=[Depends(AuthDependency(valid_token_types=AuthDependency.ALL))])
async def internal():
    return {"message": "any valid api-key accepted"}
```

A runnable version lives in [`examples/example_app.py`](https://github.com/edmon1024/fastapi-auth-manager-dep/blob/main/examples/example_app.py).
