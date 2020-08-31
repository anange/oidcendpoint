import json
import os
import shutil

import pytest
from cryptojwt.jwt import utc_time_sans_frac
from oidcendpoint import user_info
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.session import setup_session
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

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
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
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


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

ENDPOINT_CONTEXT_CONFIG = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": CAPABILITIES,
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "id_token": {"class": IDToken, "kwargs": {}},
    "endpoint": {
        "provider_config": {
            "path": ".well-known/openid-configuration",
            "class": ProviderConfiguration,
            "kwargs": {},
        },
        "registration": {"path": "registration", "class": Registration, "kwargs": {},},
        "authorization": {
            "path": "authorization",
            "class": Authorization,
            "kwargs": {},
        },
        "token": {
            "path": "token",
            "class": AccessToken,
            "kwargs": {
                "client_authn_methods": [
                    "client_secret_post",
                    "client_secret_basic",
                    "client_secret_jwt",
                    "private_key_jwt",
                ]
            },
        },
        "userinfo": {
            "path": "userinfo",
            "class": userinfo.UserInfo,
            "kwargs": {
                "claim_types_supported": ["normal", "aggregated", "distributed",],
                "client_authn_method": ["bearer_header"],
            },
        },
    },
    "userinfo": {
        "class": user_info.UserInfo,
        "kwargs": {"db_file": full_path("users.json")},
    },
    # "client_authn": verify_client,
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcendpoint.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "template_dir": "template",
    "add_on": {
        "custom_scopes": {
            "function": "oidcendpoint.oidc.add_on.custom_scopes.add_custom_scopes",
            "kwargs": {
                "research_and_scholarship": [
                    "name",
                    "given_name",
                    "family_name",
                    "email",
                    "email_verified",
                    "sub",
                    "eduperson_scoped_affiliation",
                ]
            },
        }
    },
    "db_conf": {
        "keyjar": {
            "handler": "oidcmsg.storage.abfile.LabeledAbstractFileSystem",
            "fdir": "db/keyjar",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "cryptojwt.serialize.item.KeyIssuer",
            "label": "keyjar",
        },
        "default": {
            "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
            "fdir": "db",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "oidcmsg.storage.converter.JSON",
        },
        "sso": {
            "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
            "fdir": "db/sso",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "oidcmsg.storage.converter.JSON",
        },
        "session": {
            "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
            "fdir": "db/session",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "oidcmsg.storage.converter.JSON",
        },
        "client": {
            "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
            "fdir": "db/client",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "oidcmsg.storage.converter.JSON",
        },
        "registration_access_token": {
            "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
            "fdir": "db/rat",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "oidcmsg.storage.converter.JSON",
        },
        "jti": {
            "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
            "fdir": "db/jti",
            "key_conv": "oidcmsg.storage.converter.QPKey",
            "value_conv": "oidcmsg.storage.converter.JSON",
        },
    },
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):

        try:
            shutil.rmtree("db")
        except FileNotFoundError:
            pass

        endpoint_context1 = EndpointContext(ENDPOINT_CONTEXT_CONFIG)
        endpoint_context1.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint1 = endpoint_context1.endpoint["userinfo"]
        endpoint_context2 = EndpointContext(ENDPOINT_CONTEXT_CONFIG)
        self.endpoint2 = endpoint_context2.endpoint["userinfo"]

    def test_init(self):
        assert self.endpoint1
        assert set(
            self.endpoint1.endpoint_context.provider_info["claims_supported"]
        ) == {
            "address",
            "birthdate",
            "email",
            "email_verified",
            "eduperson_scoped_affiliation",
            "family_name",
            "gender",
            "given_name",
            "locale",
            "middle_name",
            "name",
            "nickname",
            "phone_number",
            "phone_number_verified",
            "picture",
            "preferred_username",
            "profile",
            "sub",
            "updated_at",
            "website",
            "zoneinfo",
        }
        assert set(
            self.endpoint1.endpoint_context.provider_info["claims_supported"]
        ) == set(self.endpoint2.endpoint_context.provider_info["claims_supported"])

    def test_parse(self):
        session_id = setup_session(
            self.endpoint1.endpoint_context,
            AUTH_REQ,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
                "valid_until": utc_time_sans_frac() + 3600,
            },
        )
        _dic = self.endpoint1.endpoint_context.sdb.upgrade_to_token(key=session_id)
        # switch to another endpoint context instance
        _req = self.endpoint2.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )

        assert set(_req.keys()) == {"client_id", "access_token"}

    def test_process_request(self):
        session_id = setup_session(
            self.endpoint1.endpoint_context,
            AUTH_REQ,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
                "valid_until": utc_time_sans_frac() + 3600,
            },
        )
        _dic = self.endpoint1.endpoint_context.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint2.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )
        args = self.endpoint2.process_request(_req)
        assert args

    def test_process_request_not_allowed(self):
        session_id = setup_session(
            self.endpoint2.endpoint_context,
            AUTH_REQ,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac() - 7200,
                "valid_until": utc_time_sans_frac() - 3600,
            },
        )
        _dic = self.endpoint2.endpoint_context.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint1.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )
        args = self.endpoint1.process_request(_req)
        assert set(args["response_args"].keys()) == {"error", "error_description"}

    def test_process_request_offline_access(self):
        auth_req = AUTH_REQ.copy()
        auth_req["scope"] = ["openid", "offline_access"]
        session_id = setup_session(
            self.endpoint2.endpoint_context,
            auth_req,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
                "valid_until": utc_time_sans_frac() + 3600,
            },
        )
        _dic = self.endpoint2.endpoint_context.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint1.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )
        args = self.endpoint1.process_request(_req)
        assert set(args["response_args"].keys()) == {"sub"}

    def test_do_response(self):
        session_id = setup_session(
            self.endpoint2.endpoint_context,
            AUTH_REQ,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
                "valid_until": utc_time_sans_frac() + 3600,
            },
        )
        _dic = self.endpoint2.endpoint_context.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint1.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )
        args = self.endpoint1.process_request(_req)
        assert args
        res = self.endpoint2.do_response(request=_req, **args)
        assert res

    def test_do_signed_response(self):
        self.endpoint2.endpoint_context.cdb["client_1"][
            "userinfo_signed_response_alg"
        ] = "ES256"

        session_id = setup_session(
            self.endpoint2.endpoint_context,
            AUTH_REQ,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
                "valid_until": utc_time_sans_frac() + 3600,
            },
        )
        _dic = self.endpoint2.endpoint_context.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint1.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )
        args = self.endpoint1.process_request(_req)
        assert args
        res = self.endpoint1.do_response(request=_req, **args)
        assert res

    def test_custom_scope(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]
        session_id = setup_session(
            self.endpoint2.endpoint_context,
            _auth_req,
            uid="userID",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
                "valid_until": utc_time_sans_frac() + 3600,
            },
        )
        _dic = self.endpoint2.endpoint_context.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint1.parse_request(
            {}, auth="Bearer {}".format(_dic["access_token"])
        )
        args = self.endpoint1.process_request(_req)
        assert set(args["response_args"].keys()) == {
            "sub",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "eduperson_scoped_affiliation",
        }
