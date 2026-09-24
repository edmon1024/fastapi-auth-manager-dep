import json
import logging
import warnings
from functools import lru_cache
from typing import Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

#: Id of the JWT key used for tokens without a ``kid`` header, and the id the
#: legacy ``AUTH_JWT_SECRET_KEY`` / ``AUTH_JWT_ALGORITHMS`` pair is mapped to.
DEFAULT_JWT_KEY_ID = "default"

_HMAC_ALGORITHMS = ["HS256", "HS384", "HS512"]


class JWTKeyConfig(BaseModel):
    """
    One HMAC JWT key from ``AUTH_JWT_KEYS``.

    Attributes
    ----------
    secret     : HMAC secret (non-empty).
    algorithms : Allowed algorithms, HS256/HS384/HS512 only.
    audience   : Expected ``aud`` claim. None → not checked.
    issuer     : Expected ``iss`` claim. None → not checked.
    leeway     : Clock-skew tolerance in seconds for ``exp``/``nbf``/``iat``.
    require    : Claims that must be present (default ``["exp"]``).
    """

    secret: str = Field(min_length=1)
    algorithms: list[str] = Field(default_factory=lambda: list(_HMAC_ALGORITHMS), min_length=1)
    audience: Optional[Union[str, list[str]]] = None
    issuer: Optional[str] = None
    leeway: float = Field(default=0, ge=0)
    require: list[str] = Field(default_factory=lambda: ["exp"])

    model_config = {"extra": "forbid"}

    @field_validator("algorithms")
    @classmethod
    def _validate_algorithms(cls, v: list[str]) -> list[str]:
        """Only HMAC algorithms: the secret is a shared key, not a public key."""
        invalid = [alg for alg in v if alg not in _HMAC_ALGORITHMS]
        if invalid:
            raise ValueError(f"Unsupported JWT algorithms {invalid}; allowed: {_HMAC_ALGORITHMS}")
        return v


class AuthSettings(BaseSettings):
    """
    Environment variables for the authentication module.

    Required
    --------
    AUTH_ADMIN_API_KEY           Admin api-key (super-key, always required).

    Optional
    --------
    AUTH_API_KEYS          JSON object mapping raw api-keys to their labels/roles.
                      Format: '{"key-abc": "reports", "key-xyz": "billing"}'
                      Labels are used with valid_token_types in AuthDependency.

    AUTH_JWT_KEYS    JSON object mapping key ids to JWT key settings
                      (see JWTKeyConfig). Format:
                      '{"mobile": {"secret": "...", "algorithms": ["HS256"]}}'
                      Tokens select a key with the ``kid`` header; tokens
                      without ``kid`` use the key with id "default".

    AUTH_JWT_SECRET_KEY  Deprecated: single HMAC secret, mapped to key id
                      "default" (no required claims).

    AUTH_JWT_ALGORITHMS    Deprecated: algorithms for AUTH_JWT_SECRET_KEY
                      (default: HS256/384/512).
    """

    # --- Admin api-key (required) ---
    AUTH_ADMIN_API_KEY: str

    # --- Additional api-keys: {"<raw-key>": "<label>", ...} ---
    AUTH_API_KEYS: dict[str, str] = {}

    # --- JWT keys: {"<key-id>": {"secret": "...", ...}, ...} ---
    AUTH_JWT_KEYS: dict[str, JWTKeyConfig] = {}

    # --- JWT, single secret (deprecated alias of AUTH_JWT_KEYS["default"]) ---
    AUTH_JWT_SECRET_KEY: str = ""
    AUTH_JWT_ALGORITHMS: list[str] = list(_HMAC_ALGORITHMS)

    @field_validator("AUTH_API_KEYS", mode="before")
    @classmethod
    def _parse_api_keys(cls, v: object) -> dict[str, str]:
        """Accepts the envvar as a JSON string or as a dict (useful for test injection)."""
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return {}
            try:
                parsed = json.loads(v)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"AUTH_API_KEYS must be a valid JSON string: {exc}. "
                    'Example: \'{"key-abc": "reports", "key-xyz": "billing"}\''
                ) from exc
            if not isinstance(parsed, dict):
                raise ValueError("AUTH_API_KEYS must be a JSON object (dict).")
            return parsed
        if isinstance(v, dict):
            return v
        raise ValueError(f"Unexpected type for AUTH_API_KEYS: {type(v)}")

    @field_validator("AUTH_API_KEYS")
    @classmethod
    def _validate_api_keys_structure(cls, v: dict[str, str]) -> dict[str, str]:
        """Ensures all keys and labels are non-empty strings."""
        for key, label in v.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(f"Api-key '{key}' cannot be an empty string.")
            if not isinstance(label, str) or not label.strip():
                raise ValueError(
                    f"Label for api-key '{key}' cannot be an empty string."
                )
        return v

    @field_validator("AUTH_JWT_KEYS", mode="before")
    @classmethod
    def _parse_jwt_keys(cls, v: object) -> dict:
        """Accepts the envvar as a JSON string or as a dict (useful for test injection)."""
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return {}
            try:
                parsed = json.loads(v)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"AUTH_JWT_KEYS must be a valid JSON string: {exc}. "
                    'Example: \'{"mobile": {"secret": "...", "algorithms": ["HS256"]}}\''
                ) from exc
            if not isinstance(parsed, dict):
                raise ValueError("AUTH_JWT_KEYS must be a JSON object (dict).")
            return parsed
        if isinstance(v, dict):
            return v
        raise ValueError(f"Unexpected type for AUTH_JWT_KEYS: {type(v)}")

    @field_validator("AUTH_JWT_KEYS")
    @classmethod
    def _validate_jwt_key_ids(cls, v: dict[str, JWTKeyConfig]) -> dict[str, JWTKeyConfig]:
        """Key ids are used in "jwt:<id>", so they must be non-empty and colon-free."""
        for key_id in v:
            if not key_id.strip() or ":" in key_id:
                raise ValueError(f"Invalid JWT key id '{key_id}': must be non-empty and contain no ':'.")
        return v

    @model_validator(mode="after")
    def _check_legacy_jwt_secret(self) -> "AuthSettings":
        """AUTH_JWT_SECRET_KEY is a deprecated alias of AUTH_JWT_KEYS["default"]."""
        if self.AUTH_JWT_SECRET_KEY:
            if DEFAULT_JWT_KEY_ID in self.AUTH_JWT_KEYS:
                raise ValueError(
                    f'AUTH_JWT_SECRET_KEY and AUTH_JWT_KEYS["{DEFAULT_JWT_KEY_ID}"] are both set; '
                    "keep only AUTH_JWT_KEYS."
                )
            warnings.warn(
                "AUTH_JWT_SECRET_KEY / AUTH_JWT_ALGORITHMS are deprecated; "
                f'use AUTH_JWT_KEYS=\'{{"{DEFAULT_JWT_KEY_ID}": {{"secret": "..."}}}}\' instead.',
                DeprecationWarning,
                stacklevel=2,
            )
        return self

    @model_validator(mode="after")
    def _warn_duplicate_keys(self) -> "AuthSettings":
        """Warns if any additional key shares the same value as the ADMIN key."""
        duplicates = [k for k in self.AUTH_API_KEYS if k == self.AUTH_ADMIN_API_KEY]
        if duplicates:
            logger.warning(
                "AUTH: One of the AUTH_API_KEYS has the same value as AUTH_ADMIN_API_KEY (admin). "
                "Consider using unique keys per role."
            )
        return self

    # ------------------------------------------------------------------
    # Query helpers (used by AuthDependency)
    # ------------------------------------------------------------------

    def label_for_key(self, api_key: str) -> str | None:
        """
        Returns the label/role associated with an api-key.
        The ADMIN key always returns "admin".
        """
        if api_key == self.AUTH_ADMIN_API_KEY:
            return "admin"
        return self.AUTH_API_KEYS.get(api_key)

    def keys_for_label(self, label: str) -> set[str]:
        """Returns all api-keys that share a given label."""
        return {k for k, lbl in self.AUTH_API_KEYS.items() if lbl == label}

    def all_extra_labels(self) -> set[str]:
        """Returns the set of unique labels defined in AUTH_API_KEYS."""
        return set(self.AUTH_API_KEYS.values())

    def jwt_keys(self) -> dict[str, JWTKeyConfig]:
        """
        Returns every configured JWT key by id: ``AUTH_JWT_KEYS`` plus, if set,
        the legacy ``AUTH_JWT_SECRET_KEY`` as id ``"default"``. The legacy key
        keeps its 0.1.x behaviour: no required claims.
        """
        keys = dict(self.AUTH_JWT_KEYS)
        if self.AUTH_JWT_SECRET_KEY:
            keys[DEFAULT_JWT_KEY_ID] = JWTKeyConfig.model_construct(
                secret=self.AUTH_JWT_SECRET_KEY,
                algorithms=self.AUTH_JWT_ALGORITHMS,
                audience=None,
                issuer=None,
                leeway=0,
                require=[],
            )
        return keys

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_auth_settings() -> AuthSettings:
    return AuthSettings()
