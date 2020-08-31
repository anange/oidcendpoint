import os

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import init_key_jar
from oidcendpoint import user_info
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.session import setup_session
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=KEYDEFS, issuer_id=ISSUER)
KEYJAR.import_jwks(KEYJAR.export_jwks(True, ISSUER), "")

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}
                    ],
                },
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcendpoint.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims": [
                            "email",
                            "email_verified",
                            "phone_number",
                            "phone_number_verified",
                        ],
                        "add_claim_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
            },
            "endpoint": {
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {"path": "{}/token", "class": AccessToken, "kwargs": {}},
                "session": {"path": "{}/end_session", "class": Session},
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            "id_token": {"class": IDToken},
        }

        endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint = Session(endpoint_context)

    def test_parse(self):
        session_id = setup_session(
            self.endpoint.endpoint_context, AUTH_REQ, uid="diana"
        )
        _dic = self.endpoint.endpoint_context.sdb.upgrade_to_token(key=session_id)

        _verifier = JWT(self.endpoint.endpoint_context.keyjar)
        _info = _verifier.unpack(_dic["access_token"])

        assert _info["ttype"] == "T"
        assert _info["phone_number"] == "+46907865000"
        assert set(_info["aud"]) == {"client_1", "https://example.org/appl"}

    def test_info(self):
        session_id = setup_session(
            self.endpoint.endpoint_context, AUTH_REQ, uid="diana"
        )
        _dic = self.endpoint.endpoint_context.sdb.upgrade_to_token(key=session_id)

        handler = self.endpoint.endpoint_context.sdb.handler.handler["access_token"]
        _info = handler.info(_dic["access_token"])
        assert _info["type"] == "T"
        assert _info["sid"] == session_id

    @pytest.mark.parametrize("enable_claims_per_client", [True, False])
    def test_client_claims(self, enable_claims_per_client):
        ec = self.endpoint.endpoint_context
        handler = ec.sdb.handler.handler["access_token"]
        session_id = setup_session(ec, AUTH_REQ, uid="diana")
        ec.cdb["client_1"]["access_token_claims"] = {"address": None}
        handler.enable_claims_per_client = enable_claims_per_client
        _dic = ec.sdb.upgrade_to_token(key=session_id)

        token = _dic["access_token"]
        _jwt = JWT(key_jar=KEYJAR, iss="client_1")
        res = _jwt.unpack(token)
        assert enable_claims_per_client is ("address" in res)

    def test_is_expired(self):
        session_id = setup_session(
            self.endpoint.endpoint_context, AUTH_REQ, uid="diana"
        )
        _dic = self.endpoint.endpoint_context.sdb.upgrade_to_token(key=session_id)

        handler = self.endpoint.endpoint_context.sdb.handler.handler["access_token"]
        assert handler.is_expired(_dic["access_token"]) is False

        assert (
            handler.is_expired(_dic["access_token"], utc_time_sans_frac() + 4000)
            is True
        )
