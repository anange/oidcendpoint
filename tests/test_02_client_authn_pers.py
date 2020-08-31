import base64
import shutil

import pytest
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import build_keyjar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from oidcendpoint import JWT_BEARER
from oidcendpoint.client_authn import AuthnFailure
from oidcendpoint.client_authn import BearerBody
from oidcendpoint.client_authn import BearerHeader
from oidcendpoint.client_authn import ClientSecretBasic
from oidcendpoint.client_authn import ClientSecretJWT
from oidcendpoint.client_authn import ClientSecretPost
from oidcendpoint.client_authn import JWSAuthnMethod
from oidcendpoint.client_authn import PrivateKeyJWT
from oidcendpoint.client_authn import basic_authn
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import MultipleUsage
from oidcendpoint.exception import NotForMe
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc.userinfo import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)

CONF = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "endpoint": {
        "token": {
            "path": "token",
            "class": AccessToken,
            "kwargs": {
                "client_authn_method": [
                    "private_key_jwt",
                    "client_secret_jwt",
                    "client_secret_post",
                    "client_secret_basic"
                ]
            }
        },
        "authorization": {
            "path": "auth",
            "class": Authorization,
            "kwargs": {
                "client_authn_method": ["bearer_header", "none"]
            }
        },
        "registration": {
            "path": "registration",
            "class": Registration,
            "kwargs": {}
        },
        "userinfo": {
            "path": "user",
            "class": UserInfo,
            "kwargs": {"client_authn_method": ["bearer_body"]}
        }
    },
    "template_dir": "template",
    "keys": {
        "private_path": "own/jwks.json",
        "key_defs": KEYDEFS,
        "uri_path": "static/jwks.json",
    }
}

client_id = "client_id"
client_secret = "a_longer_client_secret"
# Need to add the client_secret as a symmetric key bound to the client_id
KEYJAR.add_symmetric(client_id, client_secret, ["sig"])


def get_client_id_from_token(endpoint_context, token, request=None):
    if "client_id" in request:
        if request["client_id"] == endpoint_context.registration_access_token[token]:
            return request["client_id"]
    return ""


class TestClientSecretBasic():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass

        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = ClientSecretBasic(endpoint_context)

    def test_client_secret_basic(self):
        _token = "{}:{}".format(client_id, client_secret)
        token = as_unicode(base64.b64encode(as_bytes(_token)))

        authz_token = "Basic {}".format(token)

        assert self.method.is_usable(authorization_info=authz_token)
        authn_info = self.method.verify(authorization_info=authz_token)

        assert authn_info["client_id"] == client_id

    def test_wrong_type(self):
        assert self.method.is_usable(authorization_info="Foppa toffel") is False

    def test_csb_wrong_secret(self):
        _token = "{}:{}".format(client_id, "pillow")
        token = as_unicode(base64.b64encode(as_bytes(_token)))

        authz_token = "Basic {}".format(token)

        assert self.method.is_usable(authorization_info=authz_token)

        with pytest.raises(AuthnFailure):
            self.method.verify(authorization_info=authz_token)


class TestClientSecretPost():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = ClientSecretPost(endpoint_context)

    def test_client_secret_post(self):
        request = {"client_id": client_id, "client_secret": client_secret}

        assert self.method.is_usable(request=request)
        authn_info = self.method.verify(request)

        assert authn_info["client_id"] == client_id

    def test_client_secret_post_wrong_secret(self):
        request = {"client_id": client_id, "client_secret": "pillow"}
        assert self.method.is_usable(request=request)
        with pytest.raises(AuthnFailure):
            self.method.verify(request)


class TestClientSecretJWT():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = ClientSecretJWT(endpoint_context)

    def test_client_secret_jwt(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [CONF["issuer"]]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        assert self.method.is_usable(request=request)
        authn_info = self.method.verify(request)

        assert authn_info["client_id"] == client_id
        assert "jwt" in authn_info


class TestPrivateKeyJWT():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = PrivateKeyJWT(endpoint_context)

    def test_private_key_jwt(self):
        # Own dynamic keys
        client_keyjar = build_keyjar(KEYDEFS)
        # The servers keys
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])

        _jwks = client_keyjar.export_jwks()
        self.method.endpoint_context.keyjar.import_jwks(_jwks, client_id)

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [CONF["issuer"]]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        assert self.method.is_usable(request=request)
        authn_info = self.method.verify(request=request)

        assert authn_info["client_id"] == client_id
        assert "jwt" in authn_info

    def test_private_key_jwt_reusage_other_endpoint(self):
        # Own dynamic keys
        client_keyjar = build_keyjar(KEYDEFS)
        # The servers keys
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])

        _jwks = client_keyjar.export_jwks()
        self.method.endpoint_context.keyjar.import_jwks(_jwks, client_id)

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [self.method.endpoint_context.endpoint["token"].full_path]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        # This should be OK
        assert self.method.is_usable(request=request)
        self.method.verify(request=request, endpoint="token")

        # This should NOT be OK
        with pytest.raises(NotForMe):
            self.method.verify(request, endpoint="authorization")

        # This should NOT be OK because this is the second time the token appears
        with pytest.raises(MultipleUsage):
            self.method.verify(request, endpoint="token")

    def test_private_key_jwt_auth_endpoint(self):
        # Own dynamic keys
        client_keyjar = build_keyjar(KEYDEFS)
        # The servers keys
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])

        _jwks = client_keyjar.export_jwks()
        self.method.endpoint_context.keyjar.import_jwks(_jwks, client_id)

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack(
            {"aud": [self.method.endpoint_context.endpoint["authorization"].full_path]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        assert self.method.is_usable(request=request)
        authn_info = self.method.verify(request=request, endpoint="authorization")

        assert authn_info["client_id"] == client_id
        assert "jwt" in authn_info


class TestBearerHeader():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = BearerHeader(endpoint_context)

    def test_bearerheader(self):
        authorization_info = "Bearer 1234567890"
        assert self.method.verify(authorization_info=authorization_info) == {
            "token": "1234567890"
        }

    def test_bearerheader_wrong_type(self):
        authorization_info = "Thrower 1234567890"
        assert self.method.is_usable(authorization_info=authorization_info) is False


class TestBearerBody():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = BearerBody(endpoint_context)

    def test_bearer_body(self):
        request = {"access_token": "1234567890"}
        assert self.method.verify(request) == {"token": "1234567890"}

    def test_bearer_body_no_token(self):
        request = {}
        with pytest.raises(AuthnFailure):
            self.method.verify(request=request)


class TestJWSAuthnMethod():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        endpoint_context.cdb[client_id] = {"client_secret": client_secret}
        self.method = JWSAuthnMethod(endpoint_context)

    def test_jws_authn_method_wrong_key(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # Fake symmetric key
        client_keyjar.add_symmetric("", "client_secret:client_secret", ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
        _assertion = _jwt.pack({"aud": [CONF["issuer"]]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        with pytest.raises(NoSuitableSigningKeys):
            self.method.verify(request=request, key_type='private_key')

    def test_jws_authn_method_aud_iss(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
        # Audience is OP issuer ID
        aud = CONF["issuer"]
        _assertion = _jwt.pack({"aud": [aud]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        assert self.method.verify(request=request, key_type='client_secret')

    def test_jws_authn_method_aud_token_endpoint(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")

        # audience is OP token endpoint - that's OK
        aud = "{}token".format(CONF["issuer"])
        _assertion = _jwt.pack({"aud": [aud]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        assert self.method.verify(request=request, endpoint="token", key_type='client_secret')

    def test_jws_authn_method_aud_not_me(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")

        # Other audiences not OK
        aud = "https://example.org"

        _assertion = _jwt.pack({"aud": [aud]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        with pytest.raises(NotForMe):
            self.method.verify(request=request, key_type='client_secret')

    def test_jws_authn_method_aud_userinfo_endpoint(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")

        # audience is the OP - not specifically the user info endpoint
        _assertion = _jwt.pack({"aud": [CONF["issuer"]]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        assert self.method.verify(request=request, endpoint="userinfo", key_type='client_secret')


def test_basic_auth():
    _token = "{}:{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    res = basic_authn("Basic {}".format(token))
    assert res


def test_basic_auth_wrong_label():
    _token = "{}:{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    with pytest.raises(AuthnFailure):
        basic_authn("Expanded {}".format(token))


def test_basic_auth_wrong_token():
    _token = "{}:{}:foo".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))
    with pytest.raises(ValueError):
        basic_authn("Basic {}".format(token))

    _token = "{}:{}".format(client_id, client_secret)
    with pytest.raises(ValueError):
        basic_authn("Basic {}".format(_token))

    _token = "{}{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))
    with pytest.raises(ValueError):
        basic_authn("Basic {}".format(token))


class TestVerify():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        self.endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        self.endpoint_context.cdb[client_id] = {"client_secret": client_secret}

    def test_verify_client_jws_authn_method(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
        # Audience is OP issuer ID
        aud = "{}token".format(CONF["issuer"])  # aud == Token endpoint
        _assertion = _jwt.pack({"aud": [aud]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        res = verify_client(self.endpoint_context, request, endpoint="token")
        assert res["method"] == "client_secret_jwt"
        assert res["client_id"] == "client_id"

    def test_verify_client_bearer_body(self):
        request = {"access_token": "1234567890", "client_id": client_id}
        self.endpoint_context.registration_access_token["1234567890"] = client_id
        res = verify_client(self.endpoint_context, request,
                            get_client_id_from_token=get_client_id_from_token,
                            endpoint="userinfo")
        assert set(res.keys()) == {"token", "method", "client_id"}
        assert res["method"] == "bearer_body"

    def test_verify_client_client_secret_post(self):
        request = {"client_id": client_id, "client_secret": client_secret}
        res = verify_client(self.endpoint_context, request, endpoint="token")
        assert set(res.keys()) == {"method", "client_id"}
        assert res["method"] == "client_secret_post"

    def test_verify_client_client_secret_basic(self):
        _token = "{}:{}".format(client_id, client_secret)
        token = as_unicode(base64.b64encode(as_bytes(_token)))
        authz_token = "Basic {}".format(token)
        res = verify_client(self.endpoint_context, {}, authorization_info=authz_token,
                            endpoint="token")
        assert set(res.keys()) == {"method", "client_id"}
        assert res["method"] == "client_secret_basic"

    def test_verify_client_bearer_header(self):
        # A prerequisite for the get_client_id_from_token function
        self.endpoint_context.registration_access_token["1234567890"] = client_id

        token = "Bearer 1234567890"
        request = {"client_id": client_id}
        res = verify_client(
            self.endpoint_context,
            request,
            authorization_info=token,
            get_client_id_from_token=get_client_id_from_token,
            endpoint="authorization"
        )
        assert set(res.keys()) == {"token", "method", "client_id"}
        assert res["method"] == "bearer_header"


class TestVerify2():
    @pytest.fixture(autouse=True)
    def create_method(self):
        try:
            shutil.rmtree('db')
        except FileNotFoundError:
            pass
        self.endpoint_context = EndpointContext(CONF, keyjar=KEYJAR)
        self.endpoint_context.cdb[client_id] = {"client_secret": client_secret}

    def test_verify_client_jws_authn_method(self):
        client_keyjar = KeyJar()
        client_keyjar.import_jwks(KEYJAR.export_jwks(private=True), CONF["issuer"])
        # The only own key the client has a this point
        client_keyjar.add_symmetric("", client_secret, ["sig"])

        _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
        # Audience is OP issuer ID
        aud = CONF["issuer"] + "token"
        _assertion = _jwt.pack({"aud": [aud]})

        request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

        res = verify_client(self.endpoint_context, request, endpoint="token")
        assert res["method"] == "client_secret_jwt"
        assert res["client_id"] == "client_id"

    def test_verify_client_bearer_body(self):
        request = {"access_token": "1234567890", "client_id": client_id}
        self.endpoint_context.registration_access_token["1234567890"] = client_id
        res = verify_client(self.endpoint_context, request,
                            get_client_id_from_token=get_client_id_from_token,
                            endpoint="userinfo")
        assert set(res.keys()) == {"token", "method", "client_id"}
        assert res["method"] == "bearer_body"

    def test_verify_client_client_secret_post(self):
        request = {"client_id": client_id, "client_secret": client_secret}
        res = verify_client(self.endpoint_context, request, endpoint="token")
        assert set(res.keys()) == {"method", "client_id"}
        assert res["method"] == "client_secret_post"

    def test_verify_client_client_secret_basic(self):
        _token = "{}:{}".format(client_id, client_secret)
        token = as_unicode(base64.b64encode(as_bytes(_token)))
        authz_token = "Basic {}".format(token)
        res = verify_client(self.endpoint_context, {}, authorization_info=authz_token,
                            endpoint="token")
        assert set(res.keys()) == {"method", "client_id"}
        assert res["method"] == "client_secret_basic"

    def test_verify_client_bearer_header(self):
        # A prerequisite for the get_client_id_from_token function
        self.endpoint_context.registration_access_token["1234567890"] = client_id

        token = "Bearer 1234567890"
        request = {"client_id": client_id}
        res = verify_client(
            self.endpoint_context,
            request,
            authorization_info=token,
            get_client_id_from_token=get_client_id_from_token,
            endpoint="authorization"
        )
        assert set(res.keys()) == {"token", "method", "client_id"}
        assert res["method"] == "bearer_header"

    def test_verify_client_authorization_none(self):
        # This is when it's explicitly said that no client auth method is allowed
        request = {"client_id": client_id}
        res = verify_client(
            self.endpoint_context,
            request,
            authorization_info=None,
            endpoint="authorization"
        )
        assert res["method"] == "none"
        assert res["client_id"] == "client_id"

    def test_verify_client_registration_none(self):
        # This is when no special auth method is configured
        request = {"redirect_uris": ["https://example.com/cb"]}
        res = verify_client(
            self.endpoint_context,
            request,
            authorization_info=None,
            endpoint="registration"
        )
        assert res == {}
