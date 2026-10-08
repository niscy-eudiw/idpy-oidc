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

### Fixed
- DPoP add-on (RFC 9449), taking over the checks the EUDIW authorization server did itself: `verify_proof()` checks the signature (public asymmetric `jwk`, allowed `alg`), `typ` = dpop+jwt, `htm`, `htu` against the configured `allowed_htu` (stored by `add_support`; it was read from nowhere, so the internal request URL was used), `iat` (at most 300 s old and 60 s ahead, was +-300 s), `ath` as base64url SHA-256 (was a hex digest, which no client sends) and a single-use `jti` (`JtiCache`, in `context.add_on["dpop"]["jti_cache"]`; replaceable by a shared store). A refused proof at the token endpoint gives `invalid_dpop_proof` (`DPoPErrorResponse`) instead of an exception. A refresh of a DPoP-bound grant needs a proof by the same key. `/introspection` returns `cnf.jkt` for access tokens of a DPoP-bound grant (`TokenIntrospectionResponse` has `cnf`, a JSON object).
- SonarCloud findings: `StandAloneClient.init_authorization` caught `[MissingRequiredAttribute, ValueError]` (a list, so those errors became a `TypeError`); the JAR add-on created but did not raise the `AttributeError` for unsupported request object encryption (now refused); an unreachable `except JSONDecodeError` was removed (it is a `ValueError`, caught above: behaviour unchanged); `construct.py` replaced a backtracking regular expression with string checks (same matches); `utcnow()`, `list(...)[0]` and dict comprehensions replaced.
- Client cookie MAC is HMAC-SHA256 (was HMAC-SHA1: cookies signed before the upgrade are refused); generated client secrets use HMAC-SHA256 (was SHA-224). Reviewed false positives are marked `# NOSONAR` with the reason: spec-defined `http://` identifiers, a server-side TLS context without client certificates, a translated `passwd_title` label.
- Authorization code redemption: concurrent token requests with one code all passed the "code unused" check before any marked it used, and each got an access token. `AccessTokenHelper.process_request` (oauth2 and oidc) now redeems a code under a per-code lock (`token_helper.redemption_lock`, 64 striped locks) and checks it again under that lock (`invalid_grant`). Sessions are in process memory, so this covers one server process. Tests: `test_code_parsed_twice_is_redeemed_once`, `test_concurrent_redemptions_mint_one_token`.
- `util.sanitize` returned its input unchanged, so codes, `code_verifier`s, tokens and client secrets were logged; it now redacts them (dicts, Messages and strings) and escapes line breaks. Registration logs `ClientInfo` through it.

### Changed
- CI: `python-app.yml` replaced by `tests.yml` (Python 3.12/3.13, pinned actions); Gitleaks, Dependency-Check and SonarCloud workflows added. `pytest-black` removed from `requirements-dev.txt` (it cannot load under pytest 9). `JWTToken` logs a missing session instead of a silent `try/except/pass`.
- PKCE add-on: `code_challenge_methods` also takes a list of method names (JSON configuration); the misspelt `code_challenge_method` option is refused at start-up instead of being ignored (which allowed every method, `plain` included). The check also runs on pushed authorization requests. A client's `pkce_essential` can only make PKCE stricter. The server can skip it for its own pre-authorized code request (`pre_authorized_code=True` parse argument).
- `EudiwIssuer`: the authentication hand-off JWT has a lifetime (`token_lifetime`, default 1800 s) and `unpack_token` accepts it only signed by this server (`iss`), with its algorithm, and with `exp`.
- The access token's `client_status` comes from the wallet attestation verified in the current request (`client_authn.VERIFIED_CLIENT_STATUS`), not from the client database entry other wallet instances with the same `client_id` share.
- `BearerHeader` no longer takes the client id from the request (and no longer raises `KeyError` without one): it is the client the token was issued to.
- `PublicAuthn` accepts a request that carries a DPoP proof: DPoP is not client authentication (RFC 9449), so a public client could not use DPoP-bound tokens. Requests with wallet attestation or `Authorization` headers are still not treated as public.

### Tests
- `tests/test_niscy_hardening.py` covers the changes above.
- `tests/conftest.py` lists the upstream tests that fail because of intentional fork changes (re-authentication on every request, introspection for the issuer backend, refresh tokens, optional scope) as strict xfails with the reason; 2 are marked as not yet triaged.
- Unit tests for modules that had little or none (`tests/test_cov_*.py`, about 800 tests): identity assurance messages and client add-on, the session (logout) endpoint, CIBA server endpoint and messages, device authorization messages, `metadata`, `converter`, `combo`, `claims`, `node`, `context`, `user_authn.user` (including the pinned issuer, algorithm and expiry of `EudiwIssuer.unpack_token`), the PKCE add-on, server `util`, `extra_args`, `custom_scopes`, the resource owner password grant, `authz`, `storage`, `ssl_context`, and the client registration, PAR, DPoP, JAR and status-check add-ons, `StandAloneClient`, `http` and `RPHandler`. Line and branch coverage 74% -> 88% (2064 tests). No network access, no dependence on the wall clock.

### Known issues
Bugs found while writing those tests. None is fixed here: each is pinned by a test marked `xfail(strict=True)` (reason starting with `BUG:`), which starts failing the suite once the bug is fixed, so the marker is removed with the fix. The authorization server of the EUDIW issuer does not run this code, except the first PKCE item.

Server:
- `server/oauth2/add_on/pkce.py:113`: `post_token_parse` only catches `KeyError`; an undecryptable code raises `UnknownToken` out of the hook (the token endpoint still answers `invalid_grant`).
- `server/oauth2/token_helper/resource_owner_password_credentials.py`: a second request for the same user and client raises `TypeError` (`ClientSessionInfo` indexed with `["grant"]`, lines 69-70); a wrong password is not caught (it imports `idpyoidc.exception.FailedAuthentication`, `UserPass` raises `idpyoidc.server.exception.FailedAuthentication`, lines 5/63); a request with an `acr` raises `TypeError` (`authn_broker.pick` returns a list, line 48).
- `server/util.py:124`: `allow_refresh_token` returns early, so the "grant type supported but no refresh handler" error (lines 139-143) can not happen.
- `server/authz/__init__.py:110`: `Implicit.__call__` iterates a dict without `.items()`; any non-empty `grant_config` raises `ValueError`.
- `storage/listfile.py` (`__getitem__`, `__len__`): reading an unchanged file a second time raises `UnboundLocalError`.
- `storage/abfile.py:129`: `__delitem__` does not apply `key_conv`; a key that needs quoting is never deleted.
- `server/user_authn/user.py:317`: `SymKeyAuthn` lets cryptography's `InvalidTag` escape instead of `FailedAuthentication`; `user.py:269`: `BasicAuthn.verify_password` raises `KeyError` for an unknown user.
- `server/oidc/session.py:378`: `Session.parse_request` reads `auth_info["token"]`, which client authentication does not return (`KeyError`).
- `server/oidc/backchannel_authentication.py`: `CIBATokenHelper.post_parse_request` compares full session keys with a bare grant id (lines 150-154), and `process_request` reads `_session_info["branch_id"]`, which is never set (line 243): the CIBA token request can not succeed.

Messages and metadata:
- `metadata.py:75`: `"form_post" in self.supports` tests a method, not the `_supports` dict (`TypeError`); `construct_redirect_uris()` fails without callbacks.
- `message/oidc/identity_assurance.py`: `document_details_deser` builds a `Document` (line 328); `verified_claims_deser` empties a Message input and returns a `VerificationElement` for a dict (lines 681/686); `ClaimsConstructor.__setitem__` refuses `{"essential": True}` for a str claim (line 807); `ClaimsDeconstructor` raises `TypeError` for any populated standard Message (lines 859-866).

Client:
- `client/oauth2/add_on/identity_assurance.py:6-7`: imports `match_verified_claims` and `verification_per_claim`, which do not exist; the add-on can not be imported.
- `client/oauth2/add_on/status_check.py:43`: uses `service.service_context`, which no longer exists.
- `client/oauth2/add_on/dpop.py`: `IndexError` when no configured algorithm is supported (line 131); the server's `nonce` is dropped from the proof (`DPoPProof.body_params` has no `nonce`, lines 39/155), against RFC 9449.
- `client/oauth2/add_on/jar.py`: `request_uri` mode passes `"request_uri"` as the audience and raises `TypeError` (lines 112/159); the configured `request_dir` is stored under another name and ignored (lines 146/208).
- `client/oauth2/stand_alone_client.py`: `request_args` from the client configuration are ignored (line 228); `refresh_access_token` forces the token endpoint's authentication method on the refresh service and fails with the default configuration (line 339); `logout` gets `AttributeError` instead of `OidcServiceError` (lines 667-670).
- `client/oauth2/utils.py:51`: `pick_redirect_uri` returns the whole list for an explicit non-`form_post` `response_mode`.
- `client/http.py:89-97`: cookies and request callbacks change a copy of the request arguments that is not sent.
- `client/oauth2/__init__.py:106`: an `idpyoidc.client.configure.Configuration` is not recognised, so its `add_ons` are ignored.
- `client/rp_handler.py`: `get_response_type` uses the removed `service_context` (line 443); `refresh_access_token` drops the caller's scope (line 495); `client_type`, `preference` and `add_ons` are written into the shared `DEFAULT_CLIENT_CONFIGS` (lines 92-96).
