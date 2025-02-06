# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import time
import traceback
import uuid
from datetime import datetime, timedelta
from typing import Any, Literal, Optional
from unittest.mock import MagicMock, Mock, mock_open, patch
from urllib.parse import parse_qs, urlparse

import jwt

#from rucio.tests.common_server import get_vo
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwkest.jwt import JWT
from jwt.algorithms import RSAAlgorithm
from oic import rndstr
from sqlalchemy import select
from your_module import IDPSecretLoad  # Import the class you want to test

from rucio.common.config import config_get_bool
from rucio.common.exception import CannotAuthenticate, DatabaseException, Duplicate
from rucio.common.types import InternalAccount
from rucio.core.account import add_account
from rucio.core.authentication import redirect_auth_oidc, validate_auth_token
from rucio.core.identity import add_account_identity
from rucio.core.oidc import IDPSecretLoad, _token_cache_get, _token_cache_set, get_auth_oidc, get_token_oidc, oidc_identity_string, request_token, validate_token
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountType, IdentityType
from rucio.db.sqla.session import get_session

# Sample IDP secret mock data
mock_idpsecrets = {
    "def": {
        "user_auth_client": [
            {
                "issuer": "https://issuer.example.com",
                "client_id": "client123",
                "client_secret": "secret",
                "redirect_uris": ["https://redirect.example.com"],
                "issuer_nickname": "example_issuer"
            }
        ],
        "client_credential_client": {
            "client_id": "client456",
            "client_secret": "secret456",
            "issuer": "https://issuer.example.com"
        }
    }
}

# Fixture to mock the IDPSecretLoad instance
@pytest.fixture
def mock_idp_secret_load():
    with patch("rucio.core.oidc.IDPSecretLoad") as MockIDPSecretLoad:
        mock_instance = MockIDPSecretLoad.return_value
        mock_instance._config = mock_idpsecrets  # Set the mock data
        yield mock_instance

# Test for get_vo_user_auth_config
def test_get_vo_user_auth_config(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.get_vo_user_auth_config.return_value = mock_idpsecrets["def"]["user_auth_client"][0]

    # Test the method
    result = mock_idp_secret_load.get_vo_user_auth_config(vo="def")
    # Assertions
    assert result["client_id"] == "client123"
    assert result["issuer"] == "https://issuer.example.com"
    mock_idp_secret_load.get_vo_user_auth_config.assert_called_once_with(vo="def")

# Test for get_client_credential_client
def test_get_client_credential_client(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.get_client_credential_client.return_value = mock_idpsecrets["def"]["client_credential_client"]
    # Test the method
    result = mock_idp_secret_load.get_client_credential_client(vo="def")
    # Assertions
    assert result["client_id"] == "client456"
    assert result["issuer"] == "https://issuer.example.com"
    mock_idp_secret_load.get_client_credential_client.assert_called_once_with(vo="def")

# Test for get_config_from_clientid_issuer
def test_get_config_from_clientid_issuer(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.get_config_from_clientid_issuer.return_value = mock_idpsecrets["def"]["user_auth_client"][0]
    # Test the method
    result = mock_idp_secret_load.get_config_from_clientid_issuer(client_id="client123", issuer="https://issuer.example.com")
    # Assertions
    assert result["client_id"] == "client123"
    assert result["issuer"] == "https://issuer.example.com"
    mock_idp_secret_load.get_config_from_clientid_issuer.assert_called_once_with(client_id="client123", issuer="https://issuer.example.com")

# Test for is_valid_issuer
def test_is_valid_issuer(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.is_valid_issuer.return_value = True
    # Test the method
    result = mock_idp_secret_load.is_valid_issuer(issuer_url="https://issuer.example.com", vo="def")
    # Assertions
    assert result is True
    mock_idp_secret_load.is_valid_issuer.assert_called_once_with(issuer_url="https://issuer.example.com", vo="def")


@pytest.fixture
def generate_rsa_keypair():
    """Generate an RSA keypair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_key, public_key, private_pem, public_pem

@pytest.fixture
def mock_jwks(generate_rsa_keypair):
    """Mock JWKS content using the generated RSA public key."""
    _, public_key, _, _ = generate_rsa_keypair

    public_numbers = public_key.public_numbers()
    jwk = {
        "keys": [
            {
                "kid": "test-key",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": RSAAlgorithm.to_jwk({"n": public_numbers.n, "e": public_numbers.e})["n"],
                "e": RSAAlgorithm.to_jwk({"n": public_numbers.n, "e": public_numbers.e})["e"]
            }
        ]
    }
    return jwk

@pytest.fixture
def mock_oidc_discovery():
    """Mock OIDC discovery metadata."""
    return {
        "issuer": "https://mock-oidc-provider",
        "jwks_uri": "https://mock-oidc-provider/.well-known/jwks.json",
        "token_endpoint": "https://mock-oidc-provider/token"
    }

@pytest.fixture
def encode_jwt(mock_jwks, generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key."""
    private_key, _, _, _ = generate_rsa_keypair

    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1700000000,
        "exp": 1700003600,
        "iss": "https://mock-oidc-provider",
        "aud": "mock-client-id",
        "nonce": "random-nonce",
        "scope": "openid profile email"
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
    return token


def get_jwks_content(issuer_url: str):
    """Mock function to return JWKS content."""
    return mock_jwks

def test_validate_token_success(encode_jwt):
    """Test successful token validation."""
    decoded_token = validate_token(
        token=encode_jwt,
        issuer_url="https://mock-oidc-provider",
        audience="mock-client-id",
        token_type="id_token",
        nonce="random-nonce"
    )
    assert decoded_token["sub"] == "1234567890"
    assert decoded_token["iss"] == "https://mock-oidc-provider"

def test_validate_token_invalid_nonce(encode_jwt):
    """Test failure due to incorrect nonce."""
    with pytest.raises(CannotAuthenticate, match="Invalid nonce in ID token."):
        validate_token(
            token=encode_jwt,
            issuer_url="https://mock-oidc-provider",
            audience="mock-client-id",
            token_type="id_token",
            nonce="wrong-nonce"
        )

def test_validate_token_missing_scope(encode_jwt):
    """Test failure when access token is missing required scope."""
    with pytest.raises(CannotAuthenticate, match="Access token doesn't have required scope."):
        validate_token(
            token=encode_jwt,
            issuer_url="https://mock-oidc-provider",
            audience="mock-client-id",
            token_type="access_token",
            scopes=["admin"]
        )


@pytest.fixture
def encode_jwt_with_argument(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `aud` and `scope`."""
    def _generate_jwt(aud, scope):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1700000000,
            "exp": 1700003600,
            "iss": "https://mock-oidc-provider",
            "aud": aud,  # Dynamic audience
            "scope": scope  # Dynamic scope
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt

@patch("rucio.core.oidc.get_discovery_metadata")
@patch("rucio.core.oidc.IDPSecretLoad")
@patch('requests.post')
@pytest.mark.parametrize("audience, scope", [
    ("https://mydestrse.com", "storage.modify:/mydir storage.read:/mydir"),
    ("https://mysourcerse.com", "storage.read:/mydir"),
    ("https://mydestrse.com", "storage.modify:/mydir/myfile.txt")
])
def test_request_token_success(mock_get_discovery_metadata, mock_IDPSecretLoad, encode_jwt_with_argument, mock_post, audience, scope):

    mock_token = encode_jwt_with_argument(audience, scope)
    # Prepare mock response
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": mock_token}  # Mock the response to return the token
    # Mock the requests.post to return the mock_response
    mock_post.return_value = mock_response

    mock_get_discovery_metadata.return_value = mock_oidc_discovery
    mock_IDPSecretLoad.return_value = mock_idp_secret_load
    mock_idp_secret_load.get_client_credential_client.return_value = mock_idpsecrets["def"]["client_credential_client"]

    result = request_token(scope=scope, audience=audience, vo="def", use_cache=False)
    # Assertions to ensure everything works as expected
    mock_post.assert_called_once()  # Ensure the post request was made
    mock_post.assert_called_with(
        url=mock_oidc_discovery["token_endpoint"],
        auth=(mock_idpsecrets["def"]["client_credential_client"]["client_id"], mock_idpsecrets["def"]["client_credential_client"]["client_secret"]),
        data={
            'grant_type': 'client_credentials',
            'scope': scope,
            'audience': audience
        },
        timeout=10
    )
    assert result == mock_token
    # Decode the JWT token and validate the claims
    decoded_token = jwt.decode(result, options={"verify_signature": False})
    # Validate the claims
    assert decoded_token["aud"] == audience
    assert decoded_token["scope"] == scope


def save_validated_token(token, valid_dict, extra_dict=None, session=None):
    """
    Save JWT token to the Rucio DB.

    :param token: Authentication token as a variable-length string.
    :param valid_dict: Validation Rucio dictionary as the output
                       of the __get_rucio_jwt_dict function

    :returns: DB token object if successful, raises an exception otherwise.
    """
    try:
        if not extra_dict:
            extra_dict = {}
        new_token = models.Token(account=valid_dict.get('account', None),
                                 token=token,
                                 oidc_scope=valid_dict.get('authz_scope', None),
                                 expired_at=valid_dict.get('lifetime', None),
                                 audience=valid_dict.get('audience', None),
                                 identity=valid_dict.get('identity', None),
                                 refresh=extra_dict.get('refresh', False),
                                 refresh_token=extra_dict.get('refresh_token', None),
                                 refresh_expired_at=extra_dict.get('refresh_expired_at', None),
                                 refresh_lifetime=extra_dict.get('refresh_lifetime', None),
                                 refresh_start=extra_dict.get('refresh_start', None),
                                 ip=extra_dict.get('ip', None))
        new_token.save(session=session)
        return new_token
    except Exception as error:
        raise Exception(error.args)


def get_oauth_session_row(account, state=None, session=None):
    stmt = select(
        models.OAuthRequest
    ).where(
        models.OAuthRequest.account == account
    )
    if state:
        stmt = stmt.where(
            models.OAuthRequest.state == state
        )
    return session.execute(stmt).scalars().all()


def get_token_row(access_token, account=None, session=None) -> models.Token:
    stmt = select(
        models.Token
    ).where(
        models.Token.token == access_token
    )
    token = session.execute(stmt).scalar_one_or_none()
    if account and token:
        assert token.account == account
    return token


class MockResponse:
    def __init__(self, json_data):
        self.json_data = json_data

    def json(self):
        return self.json_data



@pytest.mark.noparallel(reason='fails when run in parallel')
class TestAuthCoreAPIoidc:

    """ OIDC Core API Testing: Testing creation of authorization URL for Rucio Client,
        token request, token exchange, admin token request, finding token for an account.
        TO-DO tests for: exchange_token_oidc, get_token_for_account_operation, get_admin_token_oidc

        setUp function (below) runs first (nose does this automatically)

    """
    # pylint: disable=unused-argument

    def setup_method(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.db_session = get_session()
        self.accountstring = 'test_' + rndstr()
        self.accountstring = self.accountstring.lower()
        self.account = InternalAccount(self.accountstring, **self.vo)
        try:
            add_account(self.account, AccountType.USER, 'rucio@email.com', session=self.db_session)
        except Duplicate:
            pass

        try:
            add_account_identity('SUB=knownsub, ISS=https://test_issuer/', IdentityType.OIDC, self.account, 'rucio_test@test.com', session=self.db_session)
        except DatabaseException:
            pass

    def teardown_method(self):
        self.db_session.remove()

    def get_auth_init_and_mock_response(self, code_response, account=None, polling=False, auto=True, session=None):
        """
        OIDC creates entry in oauth_requests table

        returns: auth_query_string (state=xxx&code=yyy
                 as would be returned from the IdP
                 after a successful authentication)

        """
        if not account:
            account = self.account

        kwargs = {
            'auth_scope': 'openid profile',
            'audience': 'rucio',
            'issuer': 'dummy_admin_iss_nickname',
            'auto': auto,
            'polling': polling,
            'refresh_lifetime': 96,
            'ip': None,
            'webhome': 'https://rucio-test.cern.ch/ui',
        }
        auth_url = get_auth_oidc(account, session=session, **kwargs)
        print("[get_auth_init_and_mock_response] got auth_url:", auth_url)
        # get the state from the auth_url and add an arbitrary code value to the query string
        # to mimic a return of IdP with authz_code
        urlparsed = urlparse(auth_url)
        if ('_polling' in auth_url) or (not polling and not auto):
            auth_url = redirect_auth_oidc(urlparsed.query, session=session)
            print("[get_auth_init_and_mock_response] got redirect auth_url:", auth_url)
            urlparsed = urlparse(auth_url)
        urlparams = parse_qs(urlparsed.query)
        assert 'state' in urlparams
        state = urlparams["state"][0]
        assert 'nonce' in urlparams
        nonce = urlparams["nonce"][0]
        auth_query_string = "state=" + state + "&code=" + code_response
        return {'state': state, 'nonce': nonce, 'auth_url': auth_url, 'auth_query_string': auth_query_string}

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_auth_oidc_url(self, mock_clients, mock_oidc_client):
        """ OIDC Auth URL generation

            Runs the Test:

            - calling the respective function

            End:

            - checking the URL to be as expected
        """

        mock_oidc_client.side_effect = get_mock_oidc_client

        try:
            kwargs = {'auth_scope': 'openid profile',
                      'audience': 'rucio',
                      'issuer': 'dummy_admin_iss_nickname',
                      'auto': False,
                      'polling': False,
                      'refresh_lifetime': 96,
                      'ip': None,
                      'webhome': None}
            # testing classical CLI login init, expecting user to be
            # redirected via Rucio Auth server to the IdP issuer for login
            auth_url = get_auth_oidc(self.account, session=self.db_session, **kwargs)
            assert 'https://test_redirect_string/auth/oidc_redirect?' in auth_url and '_polling' not in auth_url

            # testing classical CLI login init, expecting user to be redirected
            # via Rucio Auth server to the IdP issuer for login and Rucio Client
            # to be polling the Rucio Auth server for token until done so
            kwargs['polling'] = True
            auth_url = get_auth_oidc(self.account, session=self.db_session, **kwargs)
            assert 'https://test_redirect_string/auth/oidc_redirect?' in auth_url and '_polling' in auth_url

            # testing classical CLI login init, with the Rucio Client being
            # trusted with IdP user credentials (auto = True). Rucio Client
            # gets directly the auth_url pointing it to the IdP
            kwargs['polling'] = False
            kwargs['auto'] = True
            auth_url = get_auth_oidc(self.account, session=self.db_session, **kwargs)
            assert 'https://test_auth_url_string' in auth_url

            # testing webui login URL (auto = True, polling = False)
            kwargs['webhome'] = 'https://back_to_rucio_ui_page'
            auth_url = get_auth_oidc(InternalAccount('webui', **self.vo), session=self.db_session, **kwargs)
            assert 'https://test_auth_url_string' in auth_url

        except:
            print(traceback.format_exc())

    def test_get_token_oidc_unknown_state(self):
        """ OIDC Token request with unknown state from IdP

            Runs the Test:

            - requesting token with parameters without corresponding
              DB entry (in oauth_Requests table)

            End:

            - checking the relevant exception to be thrown
        """
        try:
            auth_query_string = "state=" + rndstr() + "&code=" + rndstr()
            get_token_oidc(auth_query_string, session=self.db_session)
        except CannotAuthenticate:
            assert "could not keep track of responses from outstanding requests" in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_code(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown code from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        try:
            auth_init_response = self.get_auth_init_and_mock_response(code_response='wrongcode', session=self.db_session)
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
            assert oauth_session_row
            get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        except CannotAuthenticate:
            assert "Unknown AuthZ code provided" in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_nonce(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown nonce from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        try:
            auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
            assert oauth_session_row

            NEW_TOKEN_DICT['id_token']['nonce'] = 'wrongnonce'
            get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        except CannotAuthenticate:
            assert "This points to possible replay attack !" in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_account_identity(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown account identity in the token from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        try:
            auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
            assert oauth_session_row

            NEW_TOKEN_DICT['id_token'] = {'sub': 'unknownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
            get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        except CannotAuthenticate:
            assert "OIDC identity 'SUB=unknownsub, ISS=https://test_issuer/' of the '" + self.accountstring + "' account is unknown to Rucio." in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_webui_account_identity(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown webui identity in the token from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client

        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), account=InternalAccount('webui', **self.vo), session=self.db_session)
        # check if DB entry exists
        oauth_session_row = get_oauth_session_row(InternalAccount('webui', **self.vo), state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row

        NEW_TOKEN_DICT['id_token'] = {'sub': 'unknownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict['webhome'] is None
        assert token_dict['token'] is None

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_webui_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token via webui 'account' - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking if the right token is saved in the DB and if it is present
              in the return dict of the get_token_oidc function
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), account=InternalAccount('webui', **self.vo), session=self.db_session)
        oauth_session_row = get_oauth_session_row(InternalAccount('webui', **self.vo), state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        assert token_dict['webhome'] is not None
        assert token_dict['token']['token'] == access_token
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token, session=self.db_session)
        assert db_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_cli_polling_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token while client is polling - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking if the token is in the DB and no token is being returned from the core function
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), polling=True, auto=False, session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        assert token_dict['polling'] is True
        assert 'token' not in token_dict
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token, session=self.db_session)
        assert db_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_cli_fetchcode_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token, client receives fetchcode - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking if the token is in the DB and a fetchcode is being returned from the core function
            - fetching the token
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), polling=False, auto=False, session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        assert 'fetchcode' in token_dict
        assert 'token' not in token_dict
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token, session=self.db_session)
        assert db_token
        token = redirect_auth_oidc(token_dict['fetchcode'], fetchtoken=True, session=self.db_session)
        assert token == access_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_and_refresh_tokens_oidc_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access and refresh tokens - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        refresh_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['refresh_token'] = refresh_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token
        assert db_token.token == access_token
        assert db_token.refresh_token == refresh_token

    @patch('rucio.core.oidc.JWS')
    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_CLIENTS')
    def test_validate_and_save_external_token_success(self, mock_oidc_clients, mock_jwt_dict, mock_jws):
        """ OIDC validate externally provided token with correct audience, scope and issuer - success

            Runs the Test:

            - mocking the OIDC client, and token validation dictionary pretending
              the externally passed token is valid (time, issuer, audience, scope all as expected)
            - calling the validate_auth_token core function (which is being called
              e.g. when trying to validate tokens passed to rucio in the header of a request

            End:

            - checking if the external token has been saved in the DB

        """

        mock_oidc_clients.return_value = {'https://test_issuer/': MockClientOIDC()}
        token_validate_dict = {'account': self.account,
                               'identity': 'SUB=knownsub, ISS=https://test_issuer/',
                               'lifetime': datetime.utcfromtimestamp(time.time() + 60),
                               'audience': 'rucio',
                               'authz_scope': 'openid profile'}
        mock_jwt_dict.return_value = token_validate_dict

        # mocking the token response
        access_token = rndstr() + '.' + rndstr() + '.' + rndstr()
        # trying to validate a token that does not exist in the Rucio DB
        value = validate_auth_token(access_token, session=self.db_session)
        # checking if validation went OK (we bypassed it with the dictionary above)
        assert value == token_validate_dict
        # most importantly, check that the token was saved in Rucio DB
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token
        assert db_token.token == access_token

    @patch('rucio.core.oidc.JWS')
    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_CLIENTS')
    def test_validate_and_save_external_token_fail(self, mock_oidc_clients, mock_jwt_dict, mock_jws):
        """ OIDC validate externally provided token with correct audience, scope and issuer - failure

            Runs the Test:

            - mocking the OIDC client, and token validation dictionary pretending
              the externally passed token has invalid audience
            - calling the validate_auth_token core function (which is being called
              e.g. when trying to validate tokens passed to rucio in the header of a request

            End:

            - checking if the external token was not saved in the DB

        """

        mock_oidc_clients.return_value = {'https://test_issuer/': MockClientOIDC()}
        token_validate_dict = {'account': self.account,
                               'identity': 'SUB=knownsub, ISS=https://test_issuer/',
                               'lifetime': datetime.utcfromtimestamp(time.time() + 60),
                               'audience': 'unknown_audience',
                               'authz_scope': 'openid profile'}
        mock_jwt_dict.return_value = token_validate_dict

        # mocking the token response
        access_token = rndstr() + '.' + rndstr() + '.' + rndstr()
        # trying to validate a token that does not exist in the Rucio DB
        with pytest.raises(CannotAuthenticate):
            validate_auth_token(access_token, session=self.db_session)
        # most importantly, check that the token was saved in Rucio DB
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert not db_token
