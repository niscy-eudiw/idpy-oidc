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
