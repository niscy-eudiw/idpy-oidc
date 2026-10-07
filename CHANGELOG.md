# Change Log

## 0.1.0

### Changed
- Updated implementation to align with EUDI TS3 v1.5 specification.

## 0.1.1

### Changed
- Wallet attestation (`wallet_attestation`) client authentication verifies the WIA signature with the `x5c` leaf certificate in every case. With `trust_validator_url` only the certificate chain was sent to the validator: a WIA signed by any key with a genuine wallet provider chain was accepted.
- Without a trust validator, the `x5c` chain must contain, or be issued by, a certificate in `trusted_attesters_path`; certificate validity dates are checked. The algorithm is checked before the signature.
- The WIA `sub` must match the request `client_id`. The check could be skipped by any client sending `redirect_uri=preauth`; only the server can now skip it (`skip_client_id_check`, for its internal pre-authorized code call).
- The PoP `aud` must be this server (issuer or endpoint URL), its `iss` must be the WIA `sub`, and a PoP `jti` is accepted once.
- The WIA `iat` is required (maximum age) and `client_status.exp` is checked.
- Client registration from a WIA is merged into the existing client entry instead of replacing it (redirect URIs of other in-flight flows were lost).
- DPoP add-on: the proof algorithm must be in `dpop_signing_alg_values_supported` (default `ES256`); symmetric or private `jwk`s are rejected; the proof `iat` must be within 5 minutes.
- Removed the legacy `client_assertion` attestation check in pushed authorization (`verify_client_attestation` / `verify_pop_attestation`), which decoded the attestation without verifying its signature.

### Fixed
- Local `trusted_attesters_path` verification always failed (NameError after the signature check).
- Malformed attestations, a missing `x5c` or `client_id`, or missing `http_info` raised errors that became 500s instead of authentication errors.
- `token_args` (DPoP) raised `KeyError` for clients without a DPoP key; the token endpoint `kwargs` lookup raised `KeyError` when the endpoint had none.
- Removed `print` calls that wrote client attestations, tokens, request headers and the authentication JWS to stdout; the raw WIA and PoP are no longer logged.

## Unreleased

### Changed
- CI: `python-app.yml` replaced by `tests.yml` (Python 3.12/3.13, pinned actions); Gitleaks, Dependency-Check and SonarCloud workflows added. `pytest-black` removed from `requirements-dev.txt` (it cannot load under pytest 9). `JWTToken` logs a missing session instead of a silent `try/except/pass`.
- PKCE add-on: `code_challenge_methods` also takes a list of method names (JSON configuration); the misspelt `code_challenge_method` option is refused at start-up instead of being ignored (which allowed every method, `plain` included). The check also runs on pushed authorization requests. A client's `pkce_essential` can only make PKCE stricter. The server can skip it for its own pre-authorized code request (`pre_authorized_code=True` parse argument).
- `EudiwIssuer`: the authentication hand-off JWT has a lifetime (`token_lifetime`, default 1800 s) and `unpack_token` accepts it only signed by this server (`iss`), with its algorithm, and with `exp`.
- The access token's `client_status` comes from the wallet attestation verified in the current request (`client_authn.VERIFIED_CLIENT_STATUS`), not from the client database entry other wallet instances with the same `client_id` share.
- `BearerHeader` no longer takes the client id from the request (and no longer raises `KeyError` without one): it is the client the token was issued to.
- `PublicAuthn` accepts a request that carries a DPoP proof: DPoP is not client authentication (RFC 9449), so a public client could not use DPoP-bound tokens. Requests with wallet attestation or `Authorization` headers are still not treated as public.

### Fixed
- `util.sanitize` returned its input unchanged, so codes, `code_verifier`s, tokens and client secrets were logged; it now redacts them (dicts, Messages and strings) and escapes line breaks. Registration logs `ClientInfo` through it.

### Tests
- `tests/test_niscy_hardening.py` covers the changes above.
- `tests/conftest.py` lists the upstream tests that fail because of intentional fork changes (re-authentication on every request, introspection for the issuer backend, refresh tokens, optional scope) as strict xfails with the reason; 2 are marked as not yet triaged.
