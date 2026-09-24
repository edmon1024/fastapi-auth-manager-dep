# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-09-24

### Changed

- README: how to issue JWT tokens with the `kid` header (PyJWT example, how the server
  selects and verifies the key, common mistakes), and the reserved `"default"` key: where
  it comes from (single secret or `AUTH_JWT_KEYS`) and how to select it with
  `"jwt:default"`.
- Tests for `"jwt:default"`, a `kid` claim in the payload (ignored) and a non-string `kid`.

## [0.2.1] - 2026-09-24

### Changed

- README: badges for CI, CodeQL, coverage, PyPI version, supported Python versions and
  license (also shown on PyPI).
- CI uploads the coverage report to Codecov (OIDC, no token).

## [0.2.0] - 2026-09-24

### Added

- `AUTH_JWT_KEYS`: multiple JWT keys selected by the token's `kid` header, each with its
  own secret, algorithms (HMAC only), `audience`, `issuer`, `leeway` and required claims.
  Tokens without `kid` use the key with id `"default"`.
- `"jwt:<key-id>"` in `valid_token_types` restricts an endpoint to specific JWT keys;
  unknown ids raise `ValueError` at startup.
- `AuthPrincipal.key_id`: id of the JWT key that verified the token.
- `jwt` and `all` extras.

### Changed

- **Breaking:** `pyjwt` is now optional. Install `fastapi-auth-manager-dep[jwt]` to use
  JWT; enabling `"jwt"` without it raises `ImportError` at startup.
- **Breaking:** keys defined in `AUTH_JWT_KEYS` require the `exp` claim by default
  (`"require": []` disables it). The deprecated `AUTH_JWT_SECRET_KEY` keeps the 0.1.x
  behaviour.
- New 401 details: `"JWT key not allowed"` and `"JWT key id (kid) is required"`.
- Tests use `httpx2` for Starlette's `TestClient`; CI smoke-tests the wheel with and
  without the `jwt` extra and audits all extras.

### Deprecated

- `AUTH_JWT_SECRET_KEY` and `AUTH_JWT_ALGORITHMS`: still accepted as the `"default"`
  key (with a `DeprecationWarning`); use `AUTH_JWT_KEYS`. Setting both
  `AUTH_JWT_SECRET_KEY` and a `"default"` key is an error.

## [0.1.1] - 2026-09-24

### Fixed

- With authentication applied globally (`FastAPI(dependencies=[...])`), `PublicRoute`
  did not opt endpoints out and a route-level `AuthDependency` could not accept keys
  the global one rejected, so both documented patterns returned `401`. The most
  specific declaration on the route now takes precedence; on a `PublicRoute` the
  global dependency returns `None`.
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

[0.2.2]: https://github.com/edmon1024/fastapi-auth-manager-dep/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/edmon1024/fastapi-auth-manager-dep/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/edmon1024/fastapi-auth-manager-dep/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/edmon1024/fastapi-auth-manager-dep/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/edmon1024/fastapi-auth-manager-dep/releases/tag/v0.1.0