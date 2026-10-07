import logging
import time
from hashlib import sha256
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWS
from cryptojwt import as_unicode
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory

from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_INT
from idpyoidc.message import SINGLE_REQUIRED_JSON
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.message import Message
from idpyoidc.metadata import get_signing_algs
from idpyoidc.server.client_authn import BearerHeader

logger = logging.getLogger(__name__)

#: Accepted distance (seconds) between a proof's iat and the server clock
DPOP_IAT_WINDOW = 300
#: JWK members that only a private or symmetric key has
NON_PUBLIC_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k"}


class DPoPProof(Message):
    c_param = {
        # header
        "typ": SINGLE_REQUIRED_STRING,
        "alg": SINGLE_REQUIRED_STRING,
        "jwk": SINGLE_REQUIRED_JSON,
        # body
        "jti": SINGLE_REQUIRED_STRING,
        "htm": SINGLE_REQUIRED_STRING,
        "htu": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
        "ath": SINGLE_OPTIONAL_STRING,
    }
    header_params = {"typ", "alg", "jwk"}
    body_params = {"jti", "htm", "htu", "iat"}

    def __init__(self, set_defaults=True, **kwargs):
        self.key = None
        Message.__init__(self, set_defaults=set_defaults, **kwargs)

        if self.key:
            pass
        elif "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

    def from_dict(self, dictionary, **kwargs):
        Message.from_dict(self, dictionary, **kwargs)

        if "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

        return self

    def verify(self, **kwargs):
        Message.verify(self, **kwargs)
        if self["typ"] != "dpop+jwt":
            raise ValueError("Wrong type")
        if self["alg"] == "none":
            raise ValueError("'none' is not allowed as signing algorithm")

    def create_header(self) -> str:
        payload = {k: self[k] for k in self.body_params}
        _jws = JWS(payload, alg=self["alg"])
        _headers = {k: self[k] for k in self.header_params}
        self.key.kid = ""
        _sjwt = _jws.sign_compact(keys=[self.key], **_headers)
        return _sjwt

    def verify_header(self, dpop_header, allowed_algs=None) -> Optional["DPoPProof"]:
        """Verify the proof's signature with its own (public, asymmetric) jwk.

        :param allowed_algs: the accepted signing algorithms; any asymmetric one if None
        """
        _jws = factory(dpop_header)
        if _jws:
            _jwt = _jws.jwt
            if "jwk" in _jwt.headers:
                _jwk = _jwt.headers["jwk"]
                if not isinstance(_jwk, dict) or _jwk.get("kty") == "oct" or NON_PUBLIC_JWK_MEMBERS & set(_jwk):
                    raise ValueError("DPoP 'jwk' must be a public asymmetric key")
                _alg = _jwt.headers.get("alg")
                if not _alg or _alg == "none" or _alg.startswith("HS"):
                    raise ValueError("DPoP must be signed with an asymmetric algorithm")
                if allowed_algs is not None and _alg not in allowed_algs:
                    raise ValueError(f"DPoP signing algorithm {_alg} is not supported")
                _pub_key = key_from_jwk_dict(_jwk)
                _pub_key.deserialize()
                _info = _jws.verify_compact(keys=[_pub_key], sigalg=_jwt.headers["alg"])
                for k, v in _jwt.headers.items():
                    self[k] = v

                for k, v in _info.items():
                    self[k] = v
            else:
                raise Exception()

            return self
        else:
            return None


def _allowed_algs(context):
    return (getattr(context, "add_on", {}) or {}).get("dpop", {}).get("algs_supported")


def _check_iat(dpop):
    _iat = dpop.get("iat")
    if not isinstance(_iat, int) or abs(time.time() - _iat) > DPOP_IAT_WINDOW:
        raise ValueError("DPoP 'iat' is outside the accepted window")


def token_post_parse_request(request, client_id, context, **kwargs):
    """
    Expect http_info attribute in kwargs. http_info should be a dictionary
    containing HTTP information.

    :param request:
    :param client_id:
    :param context:
    :param kwargs:
    :return:
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    if "dpop" not in _http_info["headers"]:
        return request

    _dpop = DPoPProof().verify_header(_http_info["headers"]["dpop"], _allowed_algs(context))

    # The signature of the JWS is verified, now for checking the
    # content
    allowed_htu = kwargs.get("allowed_htu") or [_http_info.get("url", "").split("?")[0]]

    if _dpop.get("htu") not in allowed_htu:
        raise ValueError("htu in DPoP does not match the HTTP URI")
    _check_iat(_dpop)

    if _dpop["htm"] != _http_info["method"]:
        raise ValueError("htm in DPoP does not match the HTTP method")

    if not _dpop.key:
        _dpop.key = key_from_jwk_dict(_dpop["jwk"])

    # Need something I can add as a reference when minting tokens
    request["dpop_jkt"] = as_unicode(_dpop.key.thumbprint("SHA-256"))
    return request


def userinfo_post_parse_request(request, client_id, context, auth_info, **kwargs):
    """
    Expect http_info attribute in kwargs. http_info should be a dictionary
    containing HTTP information.

    :param request:
    :param client_id:
    :param context:
    :param kwargs:
    :return:
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    _dpop = DPoPProof().verify_header(_http_info["headers"]["dpop"], _allowed_algs(context))

    # The signature of the JWS is verified, now for checking the
    # content

    if _dpop["htu"] != _http_info["url"].split("?")[0]:
        raise ValueError("htu in DPoP does not match the HTTP URI")
    _check_iat(_dpop)

    if _dpop["htm"] != _http_info["method"]:
        raise ValueError("htm in DPoP does not match the HTTP method")

    if not _dpop.key:
        _dpop.key = key_from_jwk_dict(_dpop["jwk"])

    ath = sha256(auth_info["token"].encode("utf8")).hexdigest()

    if _dpop["ath"] != ath:
        raise ValueError("'ath' in DPoP does not match the token hash")

    # Need something I can add as a reference when minting tokens
    request["dpop_jkt"] = as_unicode(_dpop.key.thumbprint("SHA-256"))
    logger.debug("DPoP verified")
    return request


def token_args(context, client_id, token_args: Optional[dict] = None):
    dpop_jkt = context.cdb.get(client_id, {}).get("dpop_jkt")
    if dpop_jkt:
        _jkt = list(dpop_jkt.keys())[0] if isinstance(dpop_jkt, dict) else dpop_jkt
        if token_args is None:
            token_args = {}
        token_args["cnf"] = {"jkt": _jkt}

    return token_args


def add_support(endpoint: dict, **kwargs):
    # Pick one endpoint
    # _endp_name = list(endpoint.keys())[0]

    token_endpoint = endpoint.get("token")

    token_endpoint.post_parse_request.append(token_post_parse_request)

    # _endp = endpoint[_endp_name]
    # _endp.post_parse_request.append(token_post_parse_request)

    _algs_supported = kwargs.get("dpop_signing_alg_values_supported")
    if not _algs_supported:
        _algs_supported = ["ES256"]
    else:
        _algs_supported = [alg for alg in _algs_supported if alg in get_signing_algs()]

    _context = token_endpoint.upstream_get("context")
    _context.provider_info["dpop_signing_alg_values_supported"] = _algs_supported
    _context.add_on["dpop"] = {"algs_supported": _algs_supported}
    _context.client_authn_methods["dpop"] = DPoPClientAuth(BearerHeader)

    for _dpop_endpoint in kwargs.get("dpop_endpoints", ["userinfo"]):
        _endpoint = endpoint.get(_dpop_endpoint, None)
        if _endpoint:
            _endpoint.post_parse_request.append(userinfo_post_parse_request)


# DPoP-bound access token in the "Authorization" header and the DPoP proof in the "DPoP" header


class DPoPClientAuth(BearerHeader):
    tag = "dpop_client_auth"

    def is_usable(
        self,
        request=None,
        authorization_token=None,
        http_headers=None,
        http_info: Optional[dict] = None,
    ):
        if authorization_token is not None and authorization_token.startswith("DPoP "):
            return True
        return False

    def verify(
        self,
        request: Optional[Union[dict, Message]] = None,
        authorization_token: Optional[str] = None,
        endpoint=None,  # Optional[Endpoint]
        get_client_id_from_token: Optional[Callable] = None,
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        # info contains token and client_id
        info = BearerHeader._verify(
            self,
            request,
            authorization_token,
            endpoint,
            get_client_id_from_token,
            **kwargs,
        )
        return info
