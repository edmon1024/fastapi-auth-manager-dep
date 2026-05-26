"""
Unit tests for AuthDependency with the AUTH_API_KEYS system.
Run with: pytest tests/test_auth.py -v
"""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from fastapi_auth_manager.dependency import AuthDependency
from fastapi_auth_manager.settings import AuthSettings

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ADMIN_KEY = "admin-key-secret"
REPORTS_KEY_1 = "key-reports-1"
REPORTS_KEY_2 = "key-reports-2"
BILLING_KEY = "key-billing-1"
JWT_SECRET = "jwt-super-secret"

AUTH_API_KEYS = {
    REPORTS_KEY_1: "reports",
    REPORTS_KEY_2: "reports",
    BILLING_KEY: "billing",
}


@pytest.fixture
def settings():
    return AuthSettings(
        AUTH_ADMIN_API_KEY=ADMIN_KEY,
        AUTH_API_KEYS=AUTH_API_KEYS,
        AUTH_JWT_SECRET_KEY=JWT_SECRET,
    )


@pytest.fixture
def auth_default(settings):
    """ADMIN key only (default behaviour)."""
    return AuthDependency(settings=settings)


@pytest.fixture
def auth_reports(settings):
    """ADMIN + keys labelled 'reports'."""
    return AuthDependency(valid_token_types={"reports"}, settings=settings)


@pytest.fixture
def auth_all(settings):
    """ADMIN + all additional keys."""
    return AuthDependency(valid_token_types=AuthDependency.ALL, settings=settings)


@pytest.fixture
def auth_jwt(settings):
    """ADMIN + user JWT."""
    return AuthDependency(valid_token_types={"jwt"}, settings=settings)


@pytest.fixture
def auth_billing_and_jwt(settings):
    """ADMIN + 'billing' keys + user JWT."""
    return AuthDependency(valid_token_types={"billing", "jwt"}, settings=settings)


# ---------------------------------------------------------------------------
# ADMIN key (super-key)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_admin_key_accepted_in_default(auth_default):
    principal = await auth_default(credentials=None, api_key=ADMIN_KEY)
    assert principal.sub == ADMIN_KEY
    assert principal.role == "admin"
    assert principal.method == "api_key"


@pytest.mark.anyio
async def test_admin_key_accepted_in_reports_endpoint(auth_reports):
    """ADMIN key passes even when the endpoint is restricted to 'reports'."""
    principal = await auth_reports(credentials=None, api_key=ADMIN_KEY)
    assert principal.role == "admin"


@pytest.mark.anyio
async def test_admin_key_accepted_in_billing_endpoint(settings):
    dep = AuthDependency(valid_token_types={"billing"}, settings=settings)
    principal = await dep(credentials=None, api_key=ADMIN_KEY)
    assert principal.role == "admin"


# ---------------------------------------------------------------------------
# Label-based restriction
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_reports_key_accepted_in_reports_endpoint(auth_reports):
    principal = await auth_reports(credentials=None, api_key=REPORTS_KEY_1)
    assert principal.role == "reports"


@pytest.mark.anyio
async def test_second_reports_key_accepted(auth_reports):
    """Multiple keys sharing the same label must all be accepted."""
    principal = await auth_reports(credentials=None, api_key=REPORTS_KEY_2)
    assert principal.role == "reports"


@pytest.mark.anyio
async def test_billing_key_rejected_in_reports_endpoint(auth_reports):
    with pytest.raises(HTTPException) as exc:
        await auth_reports(credentials=None, api_key=BILLING_KEY)
    assert exc.value.status_code == 401


@pytest.mark.anyio
async def test_reports_key_rejected_in_default_endpoint(auth_default):
    """Additional keys are NOT accepted when valid_token_types is None."""
    with pytest.raises(HTTPException) as exc:
        await auth_default(credentials=None, api_key=REPORTS_KEY_1)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# ALL sentinel
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_all_accepts_any_extra_key(auth_all):
    for key in [REPORTS_KEY_1, REPORTS_KEY_2, BILLING_KEY]:
        principal = await auth_all(credentials=None, api_key=key)
        assert principal.sub == key


@pytest.mark.anyio
async def test_all_still_accepts_admin(auth_all):
    principal = await auth_all(credentials=None, api_key=ADMIN_KEY)
    assert principal.role == "admin"


@pytest.mark.anyio
async def test_all_rejects_unknown_key(auth_all):
    with pytest.raises(HTTPException) as exc:
        await auth_all(credentials=None, api_key="not-registered-key")
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# "*" string is equivalent to ALL
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_star_string_equivalent_to_all(settings):
    dep = AuthDependency(valid_token_types="*", settings=settings)
    principal = await dep(credentials=None, api_key=BILLING_KEY)
    assert principal.role == "billing"


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_valid_jwt_accepted(auth_jwt):
    import jwt as pyjwt
    token = pyjwt.encode({"sub": "user-123"}, JWT_SECRET, algorithm="HS256")
    creds = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
    principal = await auth_jwt(credentials=creds, api_key=None)
    assert principal.sub == "user-123"
    assert principal.method == "jwt"
    assert principal.role is None


@pytest.mark.anyio
async def test_expired_jwt_raises_401(auth_jwt):
    import time
    import jwt as pyjwt
    token = pyjwt.encode(
        {"sub": "user-x", "exp": int(time.time()) - 10},
        JWT_SECRET,
        algorithm="HS256",
    )
    creds = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
    with pytest.raises(HTTPException) as exc:
        await auth_jwt(credentials=creds, api_key=None)
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()


@pytest.mark.anyio
async def test_jwt_ignored_when_p_not_in_token_types(auth_default):
    import jwt as pyjwt
    token = pyjwt.encode({"sub": "user-x"}, JWT_SECRET, algorithm="HS256")
    creds = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
    with pytest.raises(HTTPException) as exc:
        await auth_default(credentials=creds, api_key=None)
    assert exc.value.status_code == 401


@pytest.mark.anyio
async def test_billing_endpoint_accepts_jwt(auth_billing_and_jwt):
    import jwt as pyjwt
    token = pyjwt.encode({"sub": "user-456"}, JWT_SECRET, algorithm="HS256")
    creds = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
    principal = await auth_billing_and_jwt(credentials=creds, api_key=None)
    assert principal.sub == "user-456"
    assert principal.method == "jwt"


# ---------------------------------------------------------------------------
# No credentials
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_no_credentials_raises_401(auth_default):
    with pytest.raises(HTTPException) as exc:
        await auth_default(credentials=None, api_key=None)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# AuthSettings: AUTH_API_KEYS validation
# ---------------------------------------------------------------------------

def test_settings_parse_json_string():
    s = AuthSettings(
        AUTH_ADMIN_API_KEY="admin",
        AUTH_API_KEYS='{"key-a": "role-a", "key-b": "role-b"}',
    )
    assert s.AUTH_API_KEYS == {"key-a": "role-a", "key-b": "role-b"}


def test_settings_empty_api_keys_string():
    s = AuthSettings(AUTH_ADMIN_API_KEY="admin", AUTH_API_KEYS="")
    assert s.AUTH_API_KEYS == {}


def test_settings_invalid_json_raises():
    with pytest.raises(Exception):
        AuthSettings(AUTH_ADMIN_API_KEY="admin", AUTH_API_KEYS="not-json")


def test_settings_label_for_key():
    s = AuthSettings(AUTH_ADMIN_API_KEY="admin-k", AUTH_API_KEYS={"key-x": "reports"})
    assert s.label_for_key("admin-k") == "admin"
    assert s.label_for_key("key-x") == "reports"
    assert s.label_for_key("unknown") is None


def test_settings_keys_for_label():
    s = AuthSettings(
        AUTH_ADMIN_API_KEY="admin",
        AUTH_API_KEYS={"k1": "reports", "k2": "reports", "k3": "billing"},
    )
    assert s.keys_for_label("reports") == {"k1", "k2"}
    assert s.keys_for_label("billing") == {"k3"}
    assert s.keys_for_label("nonexistent") == set()
