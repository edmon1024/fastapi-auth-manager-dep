"""
Tests for multiple JWT keys (AUTH_JWT_KEYS), "jwt:<key-id>" and the optional pyjwt extra.
Run with: uv run pytest tests/test_jwt_keys.py -v
"""

import time

import jwt as pyjwt
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from fastapi_auth import dependency
from fastapi_auth.dependency import AuthDependency
from fastapi_auth.settings import AuthSettings

ADMIN_KEY = "admin-key"
MOBILE_SECRET = "mobile-secret-0123456789-0123456789"
PARTNER_SECRET = "partner-secret-" + "0123456789" * 5  # >= 64 bytes for HS512
DEFAULT_SECRET = "default-secret-0123456789-0123456789"

JWT_KEYS = {
    "mobile": {"secret": MOBILE_SECRET, "algorithms": ["HS256"]},
    "partner": {
        "secret": PARTNER_SECRET,
        "algorithms": ["HS512"],
        "audience": "billing-api",
        "issuer": "partner-sso",
        "leeway": 30,
        "require": ["exp", "sub"],
    },
}


def make_settings(**overrides) -> AuthSettings:
    # _env_file=None: a local .env must not leak into the tests
    values = {"AUTH_ADMIN_API_KEY": ADMIN_KEY, "AUTH_JWT_SECRET_KEY": "", "AUTH_JWT_KEYS": JWT_KEYS}
    values.update(overrides)
    return AuthSettings(_env_file=None, **values)


def make_token(secret, kid=None, algorithm="HS256", **claims) -> str:
    headers = {"kid": kid} if kid is not None else None
    return pyjwt.encode(claims, secret, algorithm=algorithm, headers=headers)


def bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="bearer", credentials=token)


def exp_in(seconds: int) -> int:
    return int(time.time()) + seconds


async def assert_401(dep, token, detail=None):
    with pytest.raises(HTTPException) as exc:
        await dep(credentials=bearer(token), api_key=None)
    assert exc.value.status_code == 401
    if detail is not None:
        assert exc.value.detail == detail
    return exc.value.detail


# ---------------------------------------------------------------------------
# Settings: AUTH_JWT_KEYS parsing and validation
# ---------------------------------------------------------------------------

def test_jwt_keys_from_env_json(monkeypatch):
    monkeypatch.setenv("AUTH_ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("AUTH_JWT_KEYS", '{"mobile": {"secret": "s3cret"}}')
    s = AuthSettings(_env_file=None)
    key = s.AUTH_JWT_KEYS["mobile"]
    assert key.secret == "s3cret"
    assert key.algorithms == ["HS256", "HS384", "HS512"]
    assert key.require == ["exp"]
    assert (key.audience, key.issuer, key.leeway) == (None, None, 0)


@pytest.mark.parametrize("raw", ["", "   "])
def test_jwt_keys_empty_string(raw):
    assert make_settings(AUTH_JWT_KEYS=raw).AUTH_JWT_KEYS == {}


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        '["mobile"]',
        {"mobile": {"secret": ""}},
        {"mobile": {"secret": "s", "algorithms": ["RS256"]}},
        {"mobile": {"secret": "s", "algorithms": []}},
        {"mobile": {"secret": "s", "leeway": -1}},
        {"mobile": {"secret": "s", "unknown": 1}},
        {"mo:bile": {"secret": "s"}},
        {" ": {"secret": "s"}},
        42,
    ],
)
def test_jwt_keys_invalid(raw):
    with pytest.raises(ValueError):
        make_settings(AUTH_JWT_KEYS=raw)


def test_legacy_secret_is_deprecated_default_key():
    with pytest.warns(DeprecationWarning, match="AUTH_JWT_KEYS"):
        s = make_settings(AUTH_JWT_KEYS={}, AUTH_JWT_SECRET_KEY=DEFAULT_SECRET)
    key = s.jwt_keys()["default"]
    assert key.secret == DEFAULT_SECRET
    assert key.require == []  # 0.1.x behaviour: no required claims


def test_legacy_secret_conflicts_with_default_key():
    with pytest.raises(ValueError, match="both set"):
        make_settings(
            AUTH_JWT_KEYS={"default": {"secret": "x"}},
            AUTH_JWT_SECRET_KEY=DEFAULT_SECRET,
        )


# ---------------------------------------------------------------------------
# AuthDependency: startup checks
# ---------------------------------------------------------------------------

def test_unknown_key_id_raises_at_init():
    with pytest.raises(ValueError, match="nope"):
        AuthDependency(valid_token_types={"jwt:nope"}, settings=make_settings())


def test_jwt_key_selector_without_keys_raises_at_init():
    with pytest.raises(ValueError, match="AUTH_JWT_KEYS"):
        AuthDependency(valid_token_types={"jwt:mobile"}, settings=make_settings(AUTH_JWT_KEYS={}))


@pytest.mark.anyio
async def test_without_pyjwt_jwt_raises_and_api_keys_work(monkeypatch):
    monkeypatch.setattr(dependency, "pyjwt", None)
    settings = make_settings(AUTH_API_KEYS={"k1": "reports"})
    with pytest.raises(ImportError, match=r"fastapi-auth-manager-dep\[jwt\]"):
        AuthDependency(valid_token_types={"jwt"}, settings=settings)
    dep = AuthDependency(valid_token_types={"reports"}, settings=settings)
    principal = await dep(credentials=None, api_key="k1")
    assert principal.role == "reports"


# ---------------------------------------------------------------------------
# AuthDependency: key selection by kid
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_any_jwt():
    return AuthDependency(valid_token_types={"jwt"}, settings=make_settings())


@pytest.mark.anyio
async def test_kid_selects_key_and_sets_key_id(auth_any_jwt):
    token = make_token(MOBILE_SECRET, kid="mobile", sub="user-1", exp=exp_in(60))
    principal = await auth_any_jwt(credentials=bearer(token), api_key=None)
    assert principal.method == "jwt"
    assert principal.sub == "user-1"
    assert principal.key_id == "mobile"


@pytest.mark.anyio
async def test_kid_with_wrong_secret_rejected(auth_any_jwt):
    token = make_token(PARTNER_SECRET, kid="mobile", exp=exp_in(60))
    detail = await assert_401(auth_any_jwt, token)
    assert detail.startswith("Invalid JWT token")


@pytest.mark.anyio
async def test_unknown_kid_rejected(auth_any_jwt):
    token = make_token(MOBILE_SECRET, kid="unknown", exp=exp_in(60))
    await assert_401(auth_any_jwt, token, "JWT key not allowed")


@pytest.mark.anyio
async def test_key_selector_restricts_endpoint():
    dep = AuthDependency(valid_token_types={"jwt:partner"}, settings=make_settings())
    token = make_token(MOBILE_SECRET, kid="mobile", exp=exp_in(60))
    await assert_401(dep, token, "JWT key not allowed")


@pytest.mark.anyio
async def test_missing_kid_without_default_key_rejected(auth_any_jwt):
    token = make_token(MOBILE_SECRET, exp=exp_in(60))
    await assert_401(auth_any_jwt, token, "JWT key id (kid) is required")


@pytest.mark.anyio
async def test_missing_kid_uses_default_key():
    keys = {**JWT_KEYS, "default": {"secret": DEFAULT_SECRET}}
    dep = AuthDependency(valid_token_types={"jwt"}, settings=make_settings(AUTH_JWT_KEYS=keys))
    token = make_token(DEFAULT_SECRET, sub="user-2", exp=exp_in(60))
    principal = await dep(credentials=bearer(token), api_key=None)
    assert principal.key_id == "default"


@pytest.mark.anyio
async def test_legacy_secret_accepts_tokens_without_kid_or_exp():
    with pytest.warns(DeprecationWarning):
        settings = make_settings(AUTH_JWT_KEYS={}, AUTH_JWT_SECRET_KEY=DEFAULT_SECRET)
    dep = AuthDependency(valid_token_types={"jwt"}, settings=settings)
    principal = await dep(credentials=bearer(make_token(DEFAULT_SECRET, sub="u")), api_key=None)
    assert principal.key_id == "default"


@pytest.mark.anyio
@pytest.mark.filterwarnings("ignore:.*HMAC key.*")  # short key on purpose: the token must be rejected
async def test_algorithm_not_allowed_for_key(auth_any_jwt):
    token = make_token(MOBILE_SECRET, kid="mobile", algorithm="HS512", exp=exp_in(60))
    await assert_401(auth_any_jwt, token, "JWT algorithm not allowed: HS512")


# ---------------------------------------------------------------------------
# AuthDependency: per-key claim checks
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_exp_required_by_default(auth_any_jwt):
    token = make_token(MOBILE_SECRET, kid="mobile", sub="u")
    detail = await assert_401(auth_any_jwt, token)
    assert "exp" in detail


@pytest.mark.anyio
async def test_require_can_be_disabled_per_key():
    keys = {"svc": {"secret": MOBILE_SECRET, "require": []}}
    dep = AuthDependency(valid_token_types={"jwt"}, settings=make_settings(AUTH_JWT_KEYS=keys))
    principal = await dep(credentials=bearer(make_token(MOBILE_SECRET, kid="svc", sub="u")), api_key=None)
    assert principal.sub == "u"


def partner_token(**claims) -> str:
    """Valid partner token; a claim set to None is left out."""
    base = {"sub": "p-1", "aud": "billing-api", "iss": "partner-sso", "exp": exp_in(60)}
    base.update(claims)
    base = {k: v for k, v in base.items() if v is not None}
    return make_token(PARTNER_SECRET, kid="partner", algorithm="HS512", **base)


@pytest.mark.anyio
async def test_partner_token_with_expected_claims_accepted(auth_any_jwt):
    principal = await auth_any_jwt(credentials=bearer(partner_token()), api_key=None)
    assert principal.key_id == "partner"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "claims",
    [{"aud": "other-api"}, {"iss": "other-sso"}, {"sub": None}],
)
async def test_partner_claim_checks(auth_any_jwt, claims):
    token = partner_token(**claims)
    detail = await assert_401(auth_any_jwt, token)
    assert detail.startswith("Invalid JWT token")


@pytest.mark.anyio
async def test_leeway_tolerates_clock_skew(auth_any_jwt):
    # partner has leeway=30
    principal = await auth_any_jwt(credentials=bearer(partner_token(exp=exp_in(-10))), api_key=None)
    assert principal.sub == "p-1"
    await assert_401(auth_any_jwt, partner_token(exp=exp_in(-60)), "JWT token has expired")
    # mobile has no leeway
    await assert_401(
        auth_any_jwt,
        make_token(MOBILE_SECRET, kid="mobile", exp=exp_in(-10)),
        "JWT token has expired",
    )


# ---------------------------------------------------------------------------
# HTTP level
# ---------------------------------------------------------------------------

def test_http_bearer_with_key_selector():
    settings = make_settings()
    app = FastAPI(dependencies=[Depends(AuthDependency(settings=settings))])

    @app.get("/me")
    async def me(principal=Depends(AuthDependency(valid_token_types={"jwt:mobile"}, settings=settings))):
        return {"sub": principal.sub, "key_id": principal.key_id}

    client = TestClient(app)
    token = make_token(MOBILE_SECRET, kid="mobile", sub="user-1", exp=exp_in(60))
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"sub": "user-1", "key_id": "mobile"}

    response = client.get("/me", headers={"Authorization": f"Bearer {partner_token()}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "JWT key not allowed"}