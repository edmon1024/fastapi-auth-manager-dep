# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - Unreleased

### Fixed

- Enabling `"jwt"` in `valid_token_types` without `AUTH_JWT_SECRET_KEY` returned
  HTTP 500 on every JWT request. `AuthDependency` now raises `ValueError` at
  creation, so the misconfiguration fails at startup.
- Any other server-side JWT key error now returns `401` with
  `"Invalid authentication credentials"` instead of an unhandled exception.
- Package metadata: added the `MIT` license (`license` / `license-files`), plain-text
  summary on PyPI, and a working `Changelog` URL.

### Changed

- Test tools moved from the public `test` extra to the `dev` dependency group;
  `pytest-asyncio` removed (unused).
- Tests moved to the repository root `tests/`, and the example app to `examples/`;
  neither is shipped in the package.

### Added

- GitHub Actions: CI (tests on Python 3.10–3.14 with a 90% coverage minimum, dependency
  audit with `pip-audit`, build and smoke tests), CodeQL analysis, Dependabot, and a
  release workflow that publishes to PyPI with Trusted Publishing.

## [0.1.0] - 2026-05-27

### Added

- `AuthDependency`: FastAPI dependency supporting API keys (`X-API-Key` header) and
  HMAC JWT Bearer tokens.
  - `AUTH_ADMIN_API_KEY`: super-key, valid on every endpoint.
  - `AUTH_API_KEYS`: additional keys with labels/roles (JSON object), restricted per
    endpoint through `valid_token_types`.
  - `AuthDependency.ALL` / `"*"` to accept every additional key.
  - `"jwt"` in `valid_token_types` enables JWT authentication with
    `AUTH_JWT_SECRET_KEY` and `AUTH_JWT_ALGORITHMS` (default HS256/HS384/HS512).
- `AuthPrincipal`: authenticated principal (`method`, `sub`, `role`, `payload`).
- `AuthMethod` enum.
- `PublicRoute`: opt-out dependency for public endpoints under global authentication.
- `401 Unauthorized` responses with specific `detail` messages.

[0.1.1]: https://github.com/edmon1024/fastapi-auth-manager-dep/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/edmon1024/fastapi-auth-manager-dep/releases/tag/v0.1.0