import json
import logging
from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


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

    AUTH_JWT_SECRET_KEY  HMAC secret key for verifying user JWTs.
                      Required only when using "jwt" in valid_token_types.

    AUTH_JWT_ALGORITHMS    List of allowed HMAC algorithms (default: HS256/384/512).
    """

    # --- Admin api-key (required) ---
    AUTH_ADMIN_API_KEY: str

    # --- Additional api-keys: {"<raw-key>": "<label>", ...} ---
    AUTH_API_KEYS: dict[str, str] = {}

    # --- JWT ---
    AUTH_JWT_SECRET_KEY: str = ""
    AUTH_JWT_ALGORITHMS: list[str] = ["HS256", "HS384", "HS512"]

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

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_auth_settings() -> AuthSettings:
    return AuthSettings()
