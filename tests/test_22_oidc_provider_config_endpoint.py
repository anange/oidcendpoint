import copy
import json

import pytest

from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.token import AccessToken

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
        "refresh_token",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "token": {"path": "token", "class": AccessToken, "kwargs": {}},
            },
            "template_dir": "template",
        }
        self.endpoint_context = EndpointContext(conf)
        self.endpoint = self.endpoint_context.endpoint["provider_config"]

    def test_do_response(self):
        args = self.endpoint.process_request()
        msg = self.endpoint.do_response(args["response_args"])
        assert isinstance(msg, dict)
        _msg = json.loads(msg["response"])
        assert _msg
        assert _msg["token_endpoint"] == "https://example.com/token"
        assert _msg["jwks_uri"] == "https://example.com/static/jwks.json"
        assert set(_msg["claims_supported"]) == {
            "gender",
            "zoneinfo",
            "website",
            "phone_number_verified",
            "middle_name",
            "family_name",
            "nickname",
            "email",
            "preferred_username",
            "profile",
            "name",
            "phone_number",
            "given_name",
            "email_verified",
            "sub",
            "locale",
            "picture",
            "address",
            "updated_at",
            "birthdate",
        }
        assert ("Content-type", "application/json; charset=utf-8") in msg["http_headers"]


class TestEndpointExtraClaimsSupported(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        _capabilities = copy.copy(CAPABILITIES)
        _capabilities['claims_supported'] = ['phone_number_verified', 'middle_name', 'family_name',
                                             'nickname', 'email', 'preferred_username', 'profile',
                                             'name', 'phone_number',
                                             'given_name', 'email_verified', 'sub', 'locale',
                                             'entitlements', 'affiliation']
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": _capabilities,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "token": {"path": "token", "class": AccessToken, "kwargs": {}},
            },
            "template_dir": "template",
        }
        self.endpoint_context = EndpointContext(conf)
        self.endpoint = self.endpoint_context.endpoint["provider_config"]

    def test_do_response(self):
        args = self.endpoint.process_request()
        msg = self.endpoint.do_response(args["response_args"])
        assert isinstance(msg, dict)
        _msg = json.loads(msg["response"])
        assert _msg
        assert _msg["token_endpoint"] == "https://example.com/token"
        assert _msg["jwks_uri"] == "https://example.com/static/jwks.json"
        assert set(_msg["claims_supported"]) == {
            'affiliation', 'email', 'email_verified', 'entitlements',
            'family_name', 'given_name', 'locale', 'middle_name', 'name',
            'nickname', 'phone_number', 'phone_number_verified', 'preferred_username',
            'profile', 'sub'}
        assert ("Content-type", "application/json") in msg["http_headers"]
