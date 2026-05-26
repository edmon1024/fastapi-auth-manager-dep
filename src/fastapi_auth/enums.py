from enum import Enum


class AuthMethod(str, Enum):
    JWT = "jwt"
    AUTH_ADMIN_API_KEY = "api_key"
