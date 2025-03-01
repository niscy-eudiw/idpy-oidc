import logging
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from uuid import uuid1

from idpyoidc.impexp import ImpExp
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.authn_event import AuthnEvent
from idpyoidc.server.session.token import TOKEN_MAP
from idpyoidc.server.token import Token as TokenHandler
from idpyoidc.util import importer

from ...message.oauth2 import TokenExchangeRequest
from ...util import qualified_name
from . import MintingNotAllowed
from .claims import claims_match
from .token import Item
from .token import SessionToken

logger = logging.getLogger(__name__)


class GrantMessage(ImpExp):
    parameter = {
        "authorization_details": {},  # As defined in draft-lodderstedt-oauth-rar
        "claims": {},  # As defined in OIDC core
        "resources": [],  # As defined in RFC8707
        "scope": "",  # As defined in RFC6749
    }

    def __init__(
        self,
        scope: Optional[str] = "",
        authorization_details: Optional[dict] = None,
        claims: Optional[list] = None,
        resources: Optional[list] = None,
    ):
        ImpExp.__init__(self)
        self.scope = scope
        self.authorization_details = authorization_details
        self.claims = claims
        self.resources = resources


def find_token(issued, token_id):
    for iss in issued:
        if iss.id == token_id:
            return iss
    return None


def issued_token_load(items: List[dict], **kwargs):
    res = []
    for item in items:
        _class_name = list(item.keys())[0]
        _cls = importer(_class_name)
        _cls = _cls().load(item[_class_name])
        res.append(_cls)
    return res


def issued_token_dump(items: List, exclude_attributes, **kwargs):
    res = []
    for item in items:
        _dump = item.dump(exclude_attributes=exclude_attributes)
        res.append({qualified_name(item): _dump})
    return res


def token_map_dump(info: dict, **kwargs):
    return {k: qualified_name(v) for k, v in info.items()}


def token_map_load(items: dict, **kwargs):
    return {k: importer(v) for k, v in items.items()}


def remember_token(token):
    logger.info(str(token))


class Grant(Item):
    parameter = Item.parameter.copy()
    parameter.update(
        {
            "authentication_event": AuthnEvent,
            "authorization_details": {},
            "authorization_request": AuthorizationRequest,
            "claims": {},
            "extra": {},
            "issued_token": [SessionToken],
            "resources": [],
            "scope": [],
            "sub": "",
            "token_map": {},
        }
    )
    type = "grant"
    special_load_dump = {
        "issued_token": {"load": issued_token_load, "dump": issued_token_dump},
        "token_map": {"load": token_map_load, "dump": token_map_dump},
    }

    def __init__(
        self,
        scope: Optional[list] = None,
        claims: Optional[dict] = None,
        resources: Optional[list] = None,
        authorization_details: Optional[dict] = None,
        authorization_request: Optional[Message] = None,
        authentication_event: Optional[AuthnEvent] = None,
        issued_token: Optional[list] = None,
        usage_rules: Optional[dict] = None,
        issued_at: int = 0,
        expires_in: int = 0,
        expires_at: int = 0,
        revoked: bool = False,
        token_map: Optional[dict] = None,
        sub: Optional[str] = "",
        extra: Optional[Dict[str, str]] = None,
        remember_token: Optional[Callable] = None,
        remove_inactive_token: Optional[bool] = False,
    ):
        Item.__init__(
            self,
            usage_rules=usage_rules,
            issued_at=issued_at,
            expires_in=expires_in,
            expires_at=expires_at,
            revoked=revoked,
        )
        self.scope = scope or []
        self.authorization_details = authorization_details or None
        self.authorization_request = authorization_request or None
        self.authentication_event = authentication_event or None
        self.claims = claims or {}  # default is to not release any user information
        self.resources = resources or []
        self.issued_token = issued_token or []
        self.id = uuid1().hex
        self.sub = sub
        self.extra = extra or {}
        self.remember_token = remember_token
        self.remove_inactive_token = remove_inactive_token

        if token_map is None:
            self.token_map = TOKEN_MAP
        else:
            self.token_map = token_map

    def get_message(self) -> object:
        return GrantMessage(
            scope=self.scope,
            claims=self.claims,
            authorization_details=self.authorization_details,
            resources=self.resources,
        )

    def find_scope(self, based_on):
        if isinstance(based_on, str):
            based_on = self.get_token(based_on)

        if based_on:
            if based_on.scope:
                return based_on.scope

            if based_on.based_on:
                return self.find_scope(based_on.based_on)

        return self.scope

    def add_acr_value(self, claims_release_point):
        # if claims_release_point == "userinfo":
        #     return False

        _release = self.claims.get(claims_release_point)
        if _release:
            _acr_request = _release.get("acr")
            _used_acr = self.authentication_event.get("authn_info")
            return claims_match(_used_acr, _acr_request)
        return False

    def payload_arguments(
        self,
        session_id: str,
        context: object,
        item: SessionToken,
        claims_release_point: str,
        scope: Optional[dict] = None,
        extra_payload: Optional[dict] = None,
        secondary_identifier: str = "",
    ) -> dict:
        """

        :param session_id: Session ID
        :param context: EndPoint Context
        :param item: A SessionToken instance
        :param claims_release_point: One of "userinfo", "introspection", "id_token", "access_token"
        :param extra_payload:
        :param secondary_identifier: Used if the claims returned are also based on rules for
            another release_point
        :type item: SessionToken
        :return: dictionary containing information to place in a token value
        """
        payload = {}
        for _in, _out in [("scope", "scope"), ("resources", "aud")]:
            _val = getattr(item, _in)
            if _val:
                payload[_out] = _val
            else:
                _val = getattr(self, _in)
                if _val:
                    payload[_out] = _val

        payload["jti"] = uuid1().hex

        if scope is None:
            scope = self.scope
        payload["scope"] = scope

        if extra_payload:
            payload.update(extra_payload)

        _jkt = self.extra.get("dpop_jkt")
        if _jkt:
            payload["cnf"] = {"jkt": _jkt}

        if self.authorization_request:
            client_id = self.authorization_request.get("client_id")
            if client_id:
                payload.update({"client_id": client_id, "sub": self.sub})

        if item.claims:
            _claims_restriction = item.claims
        else:
            _claims_restriction = context.claims_interface.get_claims(
                session_id,
                scopes=payload["scope"],
                claims_release_point=claims_release_point,
                secondary_identifier=secondary_identifier,
            )

        if _claims_restriction and context.session_manager.node_type[0] == "user":
            user_id, _, _ = context.session_manager.decrypt_branch_id(session_id)
            user_info = context.claims_interface.get_user_claims(user_id, _claims_restriction)
            payload.update(user_info)

        # Should I add the acr value
        if self.add_acr_value(claims_release_point):
            payload["acr"] = self.authentication_event["authn_info"]
        elif self.add_acr_value(secondary_identifier):
            payload["acr"] = self.authentication_event["authn_info"]

        return payload

    def mint_token(
        self,
        session_id: str,
        context: object,
        token_class: str,
        token_handler: TokenHandler = None,
        based_on: Optional[SessionToken] = None,
        usage_rules: Optional[dict] = None,
        scope: Optional[list] = None,
        token_type: Optional[str] = "",
        expires_in: Optional[int] = 0,
        not_before: Optional[int] = 0,
        claims: Optional[List[str]] = None,
        **kwargs,
    ) -> Optional[SessionToken]:
        """

        :param session_id:
        :param context:
        :param token_type:
        :param token_handler:
        :param based_on:
        :param usage_rules:
        :param scope:
        :param kwargs:
        :return:
        """
        if self.is_active() is False:
            return None

        if based_on:
            if based_on.supports_minting(token_class) is False:
                raise MintingNotAllowed(f"Minting of {token_class} not supported")
            if not based_on.is_active():
                raise MintingNotAllowed("Token inactive")
            _base_on_ref = based_on.value
        else:
            _base_on_ref = None

        if usage_rules is None and token_class in self.usage_rules:
            usage_rules = self.usage_rules[token_class]

        if claims:  # convert list to claims specification dict
            claims = {x: None for x in claims}

        _class = self.token_map.get(token_class)
        if token_class == "id_token":
            class_args = {
                k: v for k, v in kwargs.items() if k not in ["code", "access_token", "as_if"]
            }
            handler_args = {k: v for k, v in kwargs.items() if k in ["code", "access_token"]}
        else:
            class_args = kwargs
            handler_args = {}

        _aud = set(class_args.get("resources", []))
        for param in ["audience", "aud"]:
            _val = class_args.get(param)
            if _val:
                if isinstance(_val, list):
                    _aud = _aud.union(set(_val))
                else:
                    _val = [_val]
                    _aud = _aud.union(set(_val))
                del class_args[param]

        if _aud != set():
            class_args["resources"] = list(_aud)

        if token_class == "access_token" and token_type:
            class_args["token_type"] = token_type

        if _class:
            if scope is None:
                if based_on:
                    scope = self.find_scope(based_on)
                else:
                    scope = self.scope

            _token_args = kwargs.get("token_args")
            if _token_args:
                del kwargs["token_args"]
                class_args.update(_token_args)

            item = _class(
                token_class=token_class,
                based_on=_base_on_ref,
                usage_rules=usage_rules,
                scope=scope,
                expires_in=expires_in,
                not_before=not_before,
                claims=claims,
                **class_args,
            )
            if token_handler is None:
                token_handler = context.session_manager.token_handler.handler[token_class]

            if token_class in context.claims_interface.claims_release_points:
                claims_release_point = token_class
            else:
                claims_release_point = ""

            _secondary_identifier = kwargs.get("as_if")
            logger.debug(
                f"claims_release_point: {claims_release_point}, secondary_identifier: "
                f"{_secondary_identifier}"
            )

            if token_class == "id_token":
                item.session_id = session_id

            token_payload = self.payload_arguments(
                session_id,
                context,
                item=item,
                claims_release_point=claims_release_point,
                scope=scope,
                extra_payload=handler_args,
                secondary_identifier=_secondary_identifier,
            )

            logger.debug(f"token_payload: {token_payload}")

            item.value = token_handler(
                session_id=session_id, usage_rules=usage_rules, **token_payload
            )

        else:
            raise ValueError("Can not mint that kind of token")

        self.issued_token.append(item)
        self.used += 1
        return item

    def get_token(self, value: str) -> Optional[SessionToken]:
        for t in self.issued_token:
            if t.value == value:
                return t
        return None

    def revoke_token(
        self, value: Optional[str] = "", based_on: Optional[str] = "", recursive: bool = True
    ):
        remain = []
        for t in self.issued_token:
            if not value and not based_on:
                t.revoked = True
            elif value and based_on:
                if value == t.value and based_on == t.based_on:
                    t.revoked = True
            elif value and t.value == value:
                t.revoked = True
                if recursive:
                    self.revoke_token(based_on=t.value)
            elif based_on and t.based_on == based_on:
                t.revoked = True
                if recursive:
                    self.revoke_token(based_on=t.value)

            if t.revoked:
                if self.remove_inactive_token:
                    if self.remember_token:
                        self.remember_token(t)
                else:
                    remain.append(t)
            else:
                remain.append(t)

        self.issued_token = remain

    def get_spec(self, token: SessionToken) -> Optional[dict]:
        if self.is_active() is False or token.is_active is False:
            return None

        res = {}
        for attr in ["scope", "claims", "resources"]:
            _val = getattr(token, attr)
            if _val:
                res[attr] = _val
            else:
                _val = getattr(self, attr)
                if _val:
                    res[attr] = _val
        return res

    def last_issued_token_of_type(self, token_class):
        res = None
        for t in self.issued_token:
            if t.token_class == token_class:
                if res is None:
                    res = t
                elif t.issued_at > res.issued_at:
                    res = t
        return res


DEFAULT_USAGE = {
    "authorization_code": {
        "max_usage": 1,
        "supports_minting": ["access_token", "refresh_token", "id_token"],
        "expires_in": 300,
    },
    "access_token": {"supports_minting": [], "expires_in": 3600},
    "refresh_token": {"supports_minting": ["access_token", "refresh_token", "id_token"]},
}


def get_usage_rules(token_type, context, grant, client_id):
    """
    The order of importance:
    Grant, Client, EndPointContext, Default

    :param token_type: The type of token
    :param context: An EndpointContext instance
    :param grant: A Grant instance
    :param client_id: The client identifier
    :return: Usage specification
    """

    _usage = context.authz.usage_rules_for(client_id, token_type)
    if not _usage:
        _usage = DEFAULT_USAGE[token_type]

    _grant_usage = grant.usage_rules.get(token_type)
    if _grant_usage:
        _usage.update(_grant_usage)

    return _usage


class ExchangeGrant(Grant):
    parameter = Grant.parameter.copy()
    parameter.update({"exchange_request": TokenExchangeRequest, "original_session_id": ""})
    type = "exchange_grant"

    def __init__(
        self,
        scope: Optional[list] = None,
        claims: Optional[dict] = None,
        resources: Optional[list] = None,
        authorization_details: Optional[dict] = None,
        authorization_request: Optional[Message] = None,
        authentication_event: Optional[AuthnEvent] = None,
        issued_token: Optional[list] = None,
        usage_rules: Optional[dict] = None,
        exchange_request: Optional[TokenExchangeRequest] = None,
        original_branch_id: str = "",
        issued_at: int = 0,
        expires_in: int = 0,
        expires_at: int = 0,
        revoked: bool = False,
        token_map: Optional[dict] = None,
        users: list = None,
        sub: Optional[str] = "",
    ):
        Grant.__init__(
            self,
            scope=scope,
            claims=claims,
            resources=resources,
            authorization_details=authorization_details,
            authorization_request=authorization_request,
            authentication_event=authentication_event,
            issued_token=issued_token,
            usage_rules=usage_rules,
            issued_at=issued_at,
            expires_in=expires_in,
            expires_at=expires_at,
            revoked=revoked,
            token_map=token_map,
            sub=sub,
        )

        self.users = users or []
        self.usage_rules = {
            "access_token": {"supports_minting": ["access_token"], "expires_in": 60}
        }
        self.exchange_request = exchange_request
        self.original_branch_id = original_branch_id

    def payload_arguments(
        self,
        session_id: str,
        endpoint_context,
        item: SessionToken,
        claims_release_point: str,
        scope: Optional[dict] = None,
        extra_payload: Optional[dict] = None,
        secondary_identifier: str = "",
    ) -> dict:
        """
        :param session_id: Session ID
        :param endpoint_context: EndPoint Context
        :param claims_release_point: One of "userinfo", "introspection", "id_token", "access_token"
        :param scope: scope from the request
        :param extra_payload:
        :param secondary_identifier: Used if the claims returned are also based on rules for
            another release_point
        :param item: A SessionToken instance
        :type item: SessionToken
        :return: dictionary containing information to place in a token value
        """
        payload = {}
        for _in, _out in [("scope", "scope"), ("resources", "aud")]:
            _val = getattr(item, _in)
            if _val:
                payload[_out] = _val
            else:
                _val = getattr(self, _in)
                if _val:
                    payload[_out] = _val

        payload["jti"] = uuid1().hex

        if scope is None:
            scope = self.scope

        payload = {"scope": scope, "aud": self.resources, "jti": uuid1().hex}

        if extra_payload:
            payload.update(extra_payload)

        _jkt = self.extra.get("dpop_jkt")
        if _jkt:
            payload["cnf"] = {"jkt": _jkt}

        if self.exchange_request:
            client_id = self.exchange_request.get("client_id")
            if client_id:
                payload.update({"client_id": client_id, "sub": self.sub})

        if item.claims:
            _claims_restriction = item.claims
        else:
            _claims_restriction = endpoint_context.claims_interface.get_claims(
                session_id,
                scopes=scope,
                claims_release_point=claims_release_point,
                secondary_identifier=secondary_identifier,
            )

        user_id, _, _ = endpoint_context.session_manager.decrypt_session_id(session_id)
        user_info = endpoint_context.claims_interface.get_user_claims(user_id, _claims_restriction)
        payload.update(user_info)

        # Should I add the acr value
        if self.add_acr_value(claims_release_point):
            payload["acr"] = self.authentication_event["authn_info"]
        elif self.add_acr_value(secondary_identifier):
            payload["acr"] = self.authentication_event["authn_info"]

        return payload
