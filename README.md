# fastapi-auth-manager-dep

[![CI](https://img.shields.io/github/actions/workflow/status/edmon1024/fastapi-auth-manager-dep/ci.yml?branch=main&logo=github&label=CI)](https://github.com/edmon1024/fastapi-auth-manager-dep/actions?query=event%3Apush+branch%3Amain+workflow%3ACI)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/edmon1024/fastapi-auth-manager-dep/codeql.yml?branch=main&logo=github&label=CodeQL)](https://github.com/edmon1024/fastapi-auth-manager-dep/actions?query=workflow%3ACodeQL)
[![Coverage](https://codecov.io/gh/edmon1024/fastapi-auth-manager-dep/graph/badge.svg?branch=main)](https://codecov.io/gh/edmon1024/fastapi-auth-manager-dep)
[![pypi](https://img.shields.io/pypi/v/fastapi-auth-manager-dep.svg)](https://pypi.org/project/fastapi-auth-manager-dep/)
[![versions](https://img.shields.io/pypi/pyversions/fastapi-auth-manager-dep.svg)](https://pypi.org/project/fastapi-auth-manager-dep/)
[![license](https://img.shields.io/github/license/edmon1024/fastapi-auth-manager-dep.svg)](https://github.com/edmon1024/fastapi-auth-manager-dep/blob/main/LICENSE)

Reusable authentication dependency for FastAPI with **API Key** and **JWT Bearer** support.

- One mandatory ADMIN key via envvar (super-key, always valid)
- Additional api-keys with labels/roles via JSON envvar
- Fine-grained per-endpoint control: which roles each endpoint accepts
- HMAC JWT with multiple keys (`kid`), per-key algorithms, audience, issuer and required claims
- Public endpoints via explicit opt-out

---

## Install

```bash
pip install fastapi-auth-manager-dep          # api-keys only
pip install "fastapi-auth-manager-dep[jwt]"   # + JWT Bearer (installs pyjwt)
pip install "fastapi-auth-manager-dep[all]"   # everything
```

JWT support needs the `jwt` extra: enabling `"jwt"` without pyjwt installed raises
`ImportError` when the `AuthDependency` is created.

---

## Environment variables

| Variable          | Required | Description                                                                   |
|-------------------|----------|-------------------------------------------------------------------------------|
| `AUTH_ADMIN_API_KEY`         | Yes      | Administrator api-key. Super-key: valid on every endpoint.                    |
| `AUTH_API_KEYS`        | No       | JSON object mapping api-keys to their labels. See format below.               |
| `AUTH_JWT_KEYS`        | No*      | JSON object mapping JWT key ids to their settings. See format below. Required when using `"jwt"`. |
| `AUTH_JWT_SECRET_KEY`| No       | **Deprecated** — single HMAC secret, same as `AUTH_JWT_KEYS={"default": {...}}` with no required claims. |
| `AUTH_JWT_ALGORITHMS`  | No       | **Deprecated** — algorithms for `AUTH_JWT_SECRET_KEY` (default: `["HS256", "HS384", "HS512"]`). |

### `AUTH_API_KEYS` format

A JSON object where each key is the raw api-key value and the value is its label/role:

```bash
AUTH_API_KEYS='{"key-abc123": "reports", "key-xyz789": "billing", "key-qrs456": "billing"}'
```

- Multiple keys can share the same label (same role).
- Empty string (`AUTH_API_KEYS=""`) is equivalent to having no additional keys.

### `AUTH_JWT_KEYS` format

A JSON object where each key is a key id and the value its settings:

```bash
AUTH_JWT_KEYS='{
  "mobile":  {"secret": "mobile-secret", "algorithms": ["HS256"]},
  "partner": {"secret": "partner-secret", "algorithms": ["HS512"], "audience": "billing-api",
              "issuer": "partner-sso", "leeway": 30, "require": ["exp", "sub"]}
}'
```

| Field        | Required | Default                        | Description |
|--------------|----------|--------------------------------|-------------|
| `secret`     | Yes      | —                              | HMAC secret (non-empty). |
| `algorithms` | No       | `["HS256", "HS384", "HS512"]`  | Allowed algorithms; HMAC only. |
| `audience`   | No       | not checked                    | Expected `aud` claim (string or list). |
| `issuer`     | No       | not checked                    | Expected `iss` claim. |
| `leeway`     | No       | `0`                            | Clock-skew tolerance in seconds for `exp`/`nbf`/`iat`. |
| `require`    | No       | `["exp"]`                      | Claims that must be present; `[]` disables it. |

- Tokens select their key with the `kid` header. Tokens without `kid` are verified
  with the key whose id is `"default"`, if there is one; otherwise they are rejected.
- Key ids cannot be empty or contain `:`.
- Migrating from `AUTH_JWT_SECRET_KEY`: move the secret to
  `AUTH_JWT_KEYS='{"default": {"secret": "...", "require": []}}'` — tokens without `kid`
  keep working. Setting both `AUTH_JWT_SECRET_KEY` and a `"default"` key is an error.

### Issuing JWT tokens with `kid`

The service that issues tokens puts the key id in the JWT **header** (`kid`) and signs
with that key's `secret`, using one of its `algorithms`. With the `AUTH_JWT_KEYS` example
above, using [PyJWT](https://pyjwt.readthedocs.io/):

```python
import time

import jwt

now = int(time.time())

# "mobile" key: HS256, requires exp (default)
mobile_token = jwt.encode(
    {"sub": "user-123", "exp": now + 3600},
    "mobile-secret",
    algorithm="HS256",
    headers={"kid": "mobile"},
)

# "partner" key: HS512, audience, issuer, requires exp and sub
partner_token = jwt.encode(
    {"sub": "partner-42", "aud": "billing-api", "iss": "partner-sso", "exp": now + 3600},
    "partner-secret",
    algorithm="HS512",
    headers={"kid": "partner"},
)
```

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/me
```

The token's header decodes to `{"alg": "HS256", "kid": "mobile", "typ": "JWT"}`. How the
server handles it:

1. It reads `kid` from the unverified header and looks up that key. A `kid` not in
   `AUTH_JWT_KEYS`, or not allowed on the endpoint (`"jwt:<id>"`), is rejected with
   `"JWT key not allowed"`.
2. It checks `alg` against that key's `algorithms`.
3. It verifies the signature with that key's `secret`, and the claims with its
   `audience` / `issuer` / `leeway` / `require`.
4. The handler receives the key id in `AuthPrincipal.key_id` (`"mobile"`).

Things to know:

- `kid` goes in the header (`headers={"kid": ...}`). A `kid` **claim** in the payload is
  ignored: the token counts as having no `kid`.
- Without `kid`, the token is verified with the [`"default"` key](#the-default-key). If
  there is none, it is rejected with `"JWT key id (kid) is required"`.
- `kid` does not grant anything by itself. A token that says `kid: "partner"` but was
  signed with another secret fails the signature check.
- Use a different secret per key. HMAC secrets should be at least as long as the hash
  (32 bytes for HS256, 64 for HS512); PyJWT warns about shorter ones.

### The `"default"` key

`"default"` is a reserved key id: it is the key used by tokens **without** `kid`. It comes
from one of two places, never both:

| Configuration | `"default"` key |
|---|---|
| Single secret (deprecated): `AUTH_JWT_SECRET_KEY=...` | Created from that secret, with `AUTH_JWT_ALGORITHMS` and no required claims (0.1.x behaviour) |
| `AUTH_JWT_KEYS='{"default": {"secret": "..."}}'` | The entry you define, with its own algorithms, audience, issuer, leeway and `require` (default `["exp"]`) |

Setting `AUTH_JWT_SECRET_KEY` together with a `"default"` entry in `AUTH_JWT_KEYS` raises a
`ValueError`. The single secret can be combined with other keys (`"mobile"`, `"partner"`...):
it becomes `"default"` next to them.

Like any other key, it can be selected on an endpoint with `"jwt:default"`:

```python
# Only tokens verified with the "default" key (plus the ADMIN key)
@app.get("/legacy", dependencies=[Depends(AuthDependency(valid_token_types={"jwt:default"}))])
async def legacy():
    ...
```

- Tokens without `kid`, or with `kid: "default"`, are accepted there. Tokens signed with
  other keys (`kid: "mobile"`) get `"JWT key not allowed"`.
- `"jwt:default"` with no `"default"` key configured raises `ValueError` at startup.
- With only one token issuer, you can use either `"jwt"` or `"jwt:default"`: both accept the
  same tokens. `"jwt:default"` keeps the endpoint closed to keys added later.

### `.env` example

```dotenv
AUTH_ADMIN_API_KEY=super-secret-admin-key
AUTH_API_KEYS={"key-reports-1": "reports", "key-billing-1": "billing", "key-billing-2": "billing"}
AUTH_JWT_KEYS={"mobile": {"secret": "mobile-secret"}, "partner": {"secret": "partner-secret", "audience": "billing-api"}}
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

Tokens pick their key with the `kid` header; see
[Issuing JWT tokens with `kid`](#issuing-jwt-tokens-with-kid).

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
| `{"jwt"}`                    | Yes       | No                      | Any key  |
| `{"jwt:partner"}`            | Yes       | No                      | `partner` key only |
| `{"jwt:default"}`            | Yes       | No                      | `default` key only (tokens without `kid`) |

> The ADMIN key is always valid regardless of the endpoint configuration.

---

## `AuthPrincipal` — return object

```python
class AuthPrincipal(BaseModel):
    method:  AuthMethod           # AuthMethod.JWT | AuthMethod.AUTH_ADMIN_API_KEY
    sub:     str                  # user_id (JWT) or raw api-key value
    role:    str | None = None    # key role/label; None for JWT
    payload: dict | None = None   # full JWT payload; None for api-key
    key_id:  str | None = None    # id of the JWT key that verified the token; None for api-key
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
| JWT `kid` unknown or not allowed on the endpoint | `"JWT key not allowed"`       |
| JWT without `kid` and no `"default"` key | `"JWT key id (kid) is required"`      |
| Missing required claim, wrong audience/issuer | `"Invalid JWT token: ..."`       |
| JWT key misconfigured on the server  | `"Invalid authentication credentials"`   |

> Enabling `"jwt"` without any JWT key configured, or `"jwt:<id>"` with an unknown id,
> raises `ValueError` when the `AuthDependency` is created, so the misconfiguration
> fails at startup.

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
- Multiple JWT keys: `kid` selection, `"jwt:<id>"` restriction, `"default"` key for tokens without `kid`, `kid` only read from the header (a `kid` claim is ignored), `"jwt:default"` with the single secret or an explicit `"default"` key, per-key algorithms, audience, issuer, leeway and required claims
- `AUTH_JWT_KEYS` validation and the deprecated `AUTH_JWT_SECRET_KEY` alias
- Installing without the `jwt` extra
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
