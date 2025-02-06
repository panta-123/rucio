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
from rucio.tests.common import account_name_generator

# Sample IDP secret mock data
mock_idpsecrets = {
    "def": {
        "user_auth_client": [
            {
                "issuer": "https://mock-oidc-provider",
                "client_id": "mock-client-id",
                "client_secret": "secret",
                "redirect_uris": "https://redirect.example.com",
                "issuer_nickname": "example_issuer"
            }
        ],
        "client_credential_client": {
            "client_id": "client456",
            "client_secret": "secret456",
            "issuer": "https://mock-oidc-provider"
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
    assert result["client_id"] == "mock-client-id"
    assert result["issuer"] == "https://mock-oidc-provider"
    mock_idp_secret_load.get_vo_user_auth_config.assert_called_once_with(vo="def")

# Test for get_client_credential_client
def test_get_client_credential_client(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.get_client_credential_client.return_value = mock_idpsecrets["def"]["client_credential_client"]
    # Test the method
    result = mock_idp_secret_load.get_client_credential_client(vo="def")
    # Assertions
    assert result["client_id"] == "client456"
    assert result["issuer"] == "https://mock-oidc-provider"
    mock_idp_secret_load.get_client_credential_client.assert_called_once_with(vo="def")

# Test for get_config_from_clientid_issuer
def test_get_config_from_clientid_issuer(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.get_config_from_clientid_issuer.return_value = mock_idpsecrets["def"]["user_auth_client"][0]
    # Test the method
    result = mock_idp_secret_load.get_config_from_clientid_issuer(client_id="mock-client-id", issuer="https://mock-oidc-provider")
    # Assertions
    assert result["client_id"] == "mock-client-id"
    assert result["issuer"] == "https://mock-oidc-provider"
    mock_idp_secret_load.get_config_from_clientid_issuer.assert_called_once_with(client_id="mock-client-id", issuer="https://mock-oidc-provider")

# Test for is_valid_issuer
def test_is_valid_issuer(mock_idp_secret_load):
    # Mock the method behavior
    mock_idp_secret_load.is_valid_issuer.return_value = True
    # Test the method
    result = mock_idp_secret_load.is_valid_issuer(issuer_url="https://mock-oidc-provider", vo="def")
    # Assertions
    assert result is True
    mock_idp_secret_load.is_valid_issuer.assert_called_once_with(issuer_url="https://mock-oidc-provider", vo="def")


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
def get_jwks_content(generate_rsa_keypair):
    """Mock JWKS content using the generated RSA public key."""
    _, public_key, _, _ = generate_rsa_keypair

    jwk = {"keys": [
        {
            "kid": "test-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            **RSAAlgorithm.to_jwk(public_key, as_dict=True)
        }
        ]
    }
    return jwk
  

@pytest.fixture
def get_discovery_metadata():
    """Mock OIDC discovery metadata."""
    return {
        "issuer": "https://mock-oidc-provider",
        "jwks_uri": "https://mock-oidc-provider/.well-known/jwks.json",
        "token_endpoint": "https://mock-oidc-provider/token",
        "authorization_endpoint": "https://mock-oidc-provider/authorize",
    }

@pytest.fixture
def encode_jwt_id_token(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key."""
    private_key, _, _, _ = generate_rsa_keypair

    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "nbf": datetime.utcnow(),
        "iss": "https://mock-oidc-provider",
        "aud": "mock-client-id",
        "nonce": "random-nonce",
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
    return token

@pytest.fixture
def encode_jwt_id_token_with_argument(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `aud` and `scope`."""
    def _generate_jwt(nonce):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": "knownsub",
            "name": "John Doe",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "nbf": datetime.utcnow(),
            "iss": "https://mock-oidc-provider",
            "aud": "mock-client-id",
            "nonce": nonce,
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt

@pytest.fixture
def encode_jwt_access_token(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key."""
    private_key, _, _, _ = generate_rsa_keypair

    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "nbf": datetime.utcnow(),
        "iss": "https://mock-oidc-provider",
        "aud": "rucio",
        "scope": "test"
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
    return token

@pytest.fixture
def encode_jwt_with_argument(generate_rsa_keypair):
    """Generate a JWT using the mock JWKS private key with dynamic `aud` and `scope`."""
    def _generate_jwt(aud, scope):
        private_key, _, _, _ = generate_rsa_keypair

        payload = {
            "sub": "knownsub",
            "name": "John Doe",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "nbf": datetime.utcnow(),
            "iss": "https://mock-oidc-provider",
            "aud": aud,  # Dynamic audience
            "scope": scope  # Dynamic scope
        }

        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
        return token
    return _generate_jwt

@pytest.fixture
def encode_jwt_refresh_token(generate_rsa_keypair):
    """Generate a refresh JWT using the mock JWKS private key."""
    private_key, _, _, _ = generate_rsa_keypair

    payload = {
        "sub": "1234567890",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=30),  # Longer validity for refresh tokens
        "nbf": datetime.utcnow(),
        "iss": "https://mock-oidc-provider",
        "aud": "rucio"
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
    return token


def test_validate_token_success(encode_jwt_id_token, get_discovery_metadata, get_jwks_content):
    """Test successful token validation."""
    # Patching get_discovery_metadata and get_jwks_content using unittest.mock.patch
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        # Call the function being tested
        decoded_token = validate_token(
            token=encode_jwt_id_token,
            issuer_url=get_discovery_metadata["issuer"],
            audience="mock-client-id",
            token_type="id_token",
            nonce="random-nonce"
        )
        
        # Assertions based on expected decoded values
        assert decoded_token["sub"] == "1234567890"
        assert decoded_token["iss"] == get_discovery_metadata["issuer"]
        
        # Verify that get_discovery_metadata and get_jwks_content were called
        mock_get_jwks_content.assert_called_once()

def test_validate_token_invalid_nonce(encode_jwt_id_token, get_jwks_content):
    """Test failure due to incorrect nonce."""

    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate, match="Invalid nonce in ID token."):
            validate_token(
                token=encode_jwt_id_token,
                issuer_url="https://mock-oidc-provider",
                audience="mock-client-id",
                token_type="id_token",
                nonce="wrong-nonce"
            )

from rucio.core.config import remove_option as config_remove
from rucio.core.config import set as config_set


def test_validate_token_extra_acess_token_scope(encode_jwt_access_token, get_jwks_content):
    """Test failure due to incorrect nonce."""
    config_set('oidc', 'extra_access_token_scope', 'test')

    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        decoded_token = validate_token(
            token=encode_jwt_access_token,
            issuer_url="https://mock-oidc-provider",
            audience="rucio",
            token_type="access_token",
            scopes=["test"]
        )        
        # Verify that get_discovery_metadata and get_jwks_content were called
        mock_get_jwks_content.assert_called_once()
    config_remove('oidc', 'extra_access_token_scope')

"""
def test_validate_token_extra_invalid_acess_token_scope(encode_jwt_access_token, get_jwks_content):
    config_set('oidc', 'extra_access_token_scope', 'test')
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate):
            decoded_token = validate_token(
                token=encode_jwt_access_token,
                issuer_url="https://mock-oidc-provider",
                audience="mock-client-id",
                token_type="access_token",
                scopes= ["wrongscope"]
            )
    config_remove('oidc', 'extra_access_token_scope')
"""

@pytest.fixture
def mock_idp_secret_load():
    with patch("rucio.core.oidc.IDPSecretLoad") as MockIDPSecretLoad:
        mock_instance = Mock()  # Create a Mock instance directly
        mock_instance._config = mock_idpsecrets
        mock_instance.get_client_credential_client.return_value = mock_idpsecrets["def"]["client_credential_client"]
        mock_instance.get_vo_user_auth_config.return_value = mock_idpsecrets["def"]["user_auth_client"][0]
        mock_instance.get_config_from_clientid_issuer.return_value = mock_idpsecrets["def"]["user_auth_client"][0]
        MockIDPSecretLoad.return_value = mock_instance  # Make the class instantiation return the mock instance
        yield mock_instance

@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
@pytest.mark.parametrize("audience, scope", [
    ("https://mysourcerse.com", "storage.read:/mydir"),
    ("https://mydestrse.com", "storage.modify:/mydir storage.read:/mydir"),
    ("https://mysourcerse.com", "storage.read:/mydir/myfile.txt")
])
def test_request_token_success(mock_post, mock_get_discovery_metadata, mock_idp_secret_load, encode_jwt_with_argument, audience, scope, get_discovery_metadata):
    mock_token = encode_jwt_with_argument(audience, scope)
    # Prepare mock response
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": mock_token}  # Mock the response to return the token
    # Mock the requests.post to return the mock_response
    mock_post.return_value = mock_response

    mock_get_discovery_metadata.return_value = get_discovery_metadata
    

    result = request_token(scope=scope, audience=audience, vo="def", use_cache=False)
    # Assertions to ensure everything works as expected
    mock_post.assert_called_once()  # Ensure the post request was made
    mock_post.assert_called_with(
        url=get_discovery_metadata["token_endpoint"],
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

def setup_test_account():
    usr = account_name_generator()
    account = InternalAccount(usr)
    db_session = get_session()
    
    add_account(account, AccountType.USER, 'rucio@email.com', session=db_session)
    add_account_identity('SUB=knownsub, ISS=https://mock-oidc-provider', IdentityType.OIDC, account, 'rucio@email.com', session=db_session)

    return account, db_session

def get_idp_auth_params(auth_url, session):
    urlparsed = urlparse(auth_url)
    idp_auth_url = redirect_auth_oidc(urlparsed.query, session=session)
    idp_urlparsed = urlparse(idp_auth_url)
    return parse_qs(idp_urlparsed.query)

@patch("rucio.core.oidc.get_discovery_metadata")
def test_get_auth_oidc(mock_get_discovery_metadata, mock_idp_secret_load, get_discovery_metadata):
    account, db_session = setup_test_account()
    
    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',    
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }
    
    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)
    
    redirect_url = mock_idpsecrets["def"]["user_auth_client"][0]["redirect_uris"]
    assert f"{redirect_url}/auth/oidc_redirect?" in auth_url and '_polling' not in auth_url
    
    idp_params = get_idp_auth_params(auth_url, db_session)
    
    assert 'state' in idp_params
    assert 'nonce' in idp_params
    assert idp_params["audience"][0] in kwargs["audience"]
    assert idp_params["client_id"][0] in mock_idpsecrets["def"]["user_auth_client"][0]["client_id"]
    assert 'code' in idp_params["response_type"][0]

    # Test polling mode
    kwargs["polling"] = True
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)
    assert f"{redirect_url}/auth/oidc_redirect?" in auth_url and '_polling' in auth_url

    # Test modified auth_scope
    kwargs["polling"] = False
    kwargs["auth_scope"] = "openid profile extra_scope"
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)
    
    idp_params = get_idp_auth_params(auth_url, db_session)
    assert kwargs["auth_scope"] in idp_params["scope"][0]

    # Test unknown identity
    new_account, _ = setup_test_account()
    auth_url = get_auth_oidc(new_account, session=db_session, **kwargs)
    assert auth_url is None

    
@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
def test_get_token_oidc_success(mock_post, mock_get_discovery_metadata, mock_idp_secret_load, encode_jwt_id_token_with_argument, encode_jwt_access_token, get_discovery_metadata, get_jwks_content):
    account, db_session = setup_test_account()

    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',    
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }
    
    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, nonce = idp_params["state"][0], idp_params["nonce"][0]
    # created id_token with same nonce
    id_token = encode_jwt_id_token_with_argument(nonce)
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": encode_jwt_access_token, "id_token": id_token, "expires_in": 3600, "scope": "test"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=test_code&state={state}"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        result = get_token_oidc(auth_query_string, session=db_session)
        assert 'fetchcode' in result
        db_token = get_token_row(encode_jwt_access_token, account=account, session=db_session)
        assert db_token
        assert db_token.token == encode_jwt_access_token
        assert db_token.refresh is False
        assert db_token.account == account
        assert db_token.identity == 'SUB=knownsub, ISS=https://mock-oidc-provider'
        assert db_token.audience == 'rucio'


    # wrong state validation
    auth_query_string = f"code=test_code&state=wrongstate"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(CannotAuthenticate):
            get_token_oidc(auth_query_string, session=db_session)
    
    
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("400 Client Error: Bad Request for url")
    mock_response.json.return_value = {"error": "invalid_grant", "error_description": "Invalid authorization code"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=wrongcode&state={state}"
    
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        with pytest.raises(requests.exceptions.HTTPError, match="400 Client Error: Bad Request for url"):
            get_token_oidc(auth_query_string, session=db_session)
    

@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
def test_get_token_oidc_polling_success(mock_post, mock_get_discovery_metadata, mock_idp_secret_load, encode_jwt_id_token_with_argument, encode_jwt_access_token, get_discovery_metadata, get_jwks_content):
    account, db_session = setup_test_account()

    kwargs = {
        'auth_scope': 'openid profile',
        'audience': 'rucio',    
        'issuer': 'https://mock-oidc-provider',
        'polling': True,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }
    
    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, nonce = idp_params["state"][0], idp_params["nonce"][0]
    # created id_token with same nonce
    id_token = encode_jwt_id_token_with_argument(nonce)
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"access_token": encode_jwt_access_token, "id_token": id_token, "expires_in": 3600, "scope": "test"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=test_code&state={state}"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        result = get_token_oidc(auth_query_string, session=db_session)
        assert 'polling' in result
        assert result['polling']


@patch("rucio.core.oidc.get_discovery_metadata")
@patch('requests.post')
def test_get_token_oidc_with_refresh_token(mock_post, mock_get_discovery_metadata, mock_idp_secret_load, encode_jwt_id_token_with_argument, encode_jwt_access_token, encode_jwt_refresh_token, get_discovery_metadata, get_jwks_content):
    account, db_session = setup_test_account()

    kwargs = {
        'auth_scope': 'openid profile offline_access',
        'audience': 'rucio',    
        'issuer': 'https://mock-oidc-provider',
        'polling': False,
        'refresh_lifetime': 96,
        'ip': None,
        'webhome': None,
    }
    
    mock_get_discovery_metadata.return_value = get_discovery_metadata
    auth_url = get_auth_oidc(account, session=db_session, **kwargs)

    idp_params = get_idp_auth_params(auth_url, db_session)
    state, nonce = idp_params["state"][0], idp_params["nonce"][0]
    # created id_token with same nonce
    id_token = encode_jwt_id_token_with_argument(nonce)
    mock_response = Mock()
    mock_response.raise_for_status = Mock()  # No exception for a successful response
    mock_response.json.return_value = {"refresh_token": encode_jwt_refresh_token, "access_token": encode_jwt_access_token, "id_token": id_token, "expires_in": 3600, "scope": "test"}
    mock_post.return_value = mock_response
    auth_query_string = f"code=test_code&state={state}"
    with patch('rucio.core.oidc.get_jwks_content', return_value=get_jwks_content) as mock_get_jwks_content:
        result = get_token_oidc(auth_query_string, session=db_session)
        db_token = get_token_row(encode_jwt_access_token, account=account, session=db_session)
        assert db_token
        assert db_token.refresh_token == encode_jwt_refresh_token



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
