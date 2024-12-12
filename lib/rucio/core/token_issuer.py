""" token_issuer """
import base64
import datetime
import os
import uuid
from typing import Any, Optional, Union

import jwt
from cryptography.hazmat.primitives import serialization

from rucio.common.exception import InvalidGrantError, InvalidOIDCRequestError, UnauthorizedOIDCClientError, UnsupportedGrantTypeError
from rucio.common.types import (
    RefreshTokenRequest,
    RefreshTokenResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from rucio.core.oidc_client import validate_client
from rucio.db.sqla import constants
from rucio.db.sqla.session import read_session

ISSUER = "myruciohome"
SECRET_KEY = "your_secret_key"
SUPPORTED_ALGORITHMS = ["HS256", "RS256"]

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH")

if not PRIVATE_KEY_PATH:
    raise ValueError("Environment variable 'PRIVATE_KEY_PATH' is not set or empty.")

if not PUBLIC_KEY_PATH:
    raise ValueError("Environment variable 'PUBLIC_KEY_PATH' is not set or empty.")

# RSA Keys (Load from files or environment variables)
with open(PRIVATE_KEY_PATH, "r") as private_key_file:
    PRIVATE_KEY_RS256 = private_key_file.read()

with open(PUBLIC_KEY_PATH, "r") as public_key_file:
    PUBLIC_KEY_RS256 = public_key_file.read()

ACCESS_TOKEN_LIFETIME = 21600
REFRESH_TOKEN_LIFETIME = 864000
DEFAULT_AUDIENCE = "https://rucio.jlab.org"
SUBJECT_TOKEN_TYPE_SUPPORTED = ["urn:ietf:params:oauth:token-type:access_token"]
REQUESTED_TOKEN_TYPE_SUPPORTED = ["urn:ietf:params:oauth:token-type:refresh_token", "urn:ietf:params:oauth:token-type:access_token"]
SUB = "rucio-service"

def validate_scopes(requested_scope: str) -> None:
    """ Check allowed scopes. """
    # Split the requested scope into action and path
    action, _ = requested_scope.split(':', 1) if ':' in requested_scope else (requested_scope, '')
    # Check if the action part of the requested scope matches any allowed scope in the enum
    res = any(action == scope.name.lower() for scope in constants.AllowedScope)
    if not res:
        raise ValueError("One or more requested scopes were not originally granted")

def validate_expiration(decoded_token: dict[str, Any]) -> None:
    """
    Raises an error if the token has expired.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = datetime.datetime.fromtimestamp(decoded_token.get("exp"), datetime.timezone.utc)
    if exp <= now:
        raise jwt.ExpiredSignatureError("Token has expired")

def decode_token(token: str, algorithm: str = "RS256", verify_aud=False) -> dict[str, Any]:
    """
    Decodes a JWT token using the specified algorithm.
    """
    if algorithm == "HS256":
        return jwt.decode(token, SECRET_KEY, algorithms=[algorithm])
    else:
        return jwt.decode(token, PUBLIC_KEY_RS256, algorithms=[algorithm], options={"verify_aud": verify_aud})


def create_jwt_token(sub: str,
                     scope: str,
                     audience: Optional[str] = DEFAULT_AUDIENCE,
                     algorithm: str = "RS256"
) -> str:
    """
    Creates a JWT token with the specified parameters and optional expiration offset.
    The function combines the payload creation and token encoding steps into one.

    Parameters:
    - sub (str): Subject (usually the user identifier).
    - scope (str): Scope of the token.
    - audience (Optional[str]): Audience for the token. Defaults to the system's default if not provided.
    - exp_offset (int): Expiration offset in seconds (default is the access token lifetime).
    - algorithm (str): The algorithm to use for signing the token (default is "RS256").
    
    Returns:
    - str: The generated JWT token.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": sub,
        "iss": ISSUER,
        "exp": now + datetime.timedelta(seconds=int(ACCESS_TOKEN_LIFETIME)),
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "wlcg.ver": "1.0",
        "scope": scope,
        "aud": audience,
    }
    
    if algorithm == "HS256":
        return jwt.encode(payload, SECRET_KEY, algorithm=algorithm)
    else:
        return jwt.encode(payload, PRIVATE_KEY_RS256, algorithm=algorithm)


def issue_access_token(
    scope: str,
    audience: Optional[str]= DEFAULT_AUDIENCE,
    algorithm: str = "RS256"
):
    """
    Issues an access token and optionally a refresh token.
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

    :param sub: Subject (user ID or client ID).
    :param scope: Scopes requested for the token.
    :param audience: Audience for which the token is intended.
    :param include_refresh_token: Whether to include a refresh token in the response.
    :param algorithm: The algorithm to use for token signing. Default is RS256.
    :return: A dictionary containing the access token response.
    """
    sub = SUB
    scopes = scope.split()
    scope_base_list = []
    for sc in scopes:
        scope_base = sc.split(":")[0]
        scope_base_list.append(scope_base)
    required_scopes_enum = [constants.AllowedScope(sc) for sc in scope_base_list]

    # Validate and create the access token
    access_token = create_jwt_token(sub, scope, audience, algorithm)

    response = {
        "access_token": access_token,
        "token_type": "Bearer",  # Token type as per RFC 6749 Section 7.1
        "expires_in": ACCESS_TOKEN_LIFETIME,
    }

    return response

def create_refresh_token(sub: str, scope: str, audience: Optional[str]= DEFAULT_AUDIENCE, algorithm: str = "RS256"):
    payload = {
        "sub": sub,
        "jti": str(uuid.uuid4()),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=REFRESH_TOKEN_LIFETIME),
        "scope": scope,
        "aud": audience
    }
    if algorithm == "HS256":
        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    else:
        return jwt.encode(payload, PRIVATE_KEY_RS256, algorithm=algorithm)

@read_session
def handle_token_exchange(data: TokenExchangeRequest, client_id: str, client_secret: str, algorithm: str = "RS256", *, session = "Session") -> TokenExchangeResponse:
    """
    Handle token exchange according to https://datatracker.ietf.org/doc/html/rfc8693#name-token-exchange-request-and-

    # Step 1: Validate the algorithm
    # Step 2: check grant_type, subject_token_type, requested_token_type
    # Step 4: Decode the subject token
    # Step 5: Validate token expiration
    # Step 6: Ensure requested scopes are within the granted scopes.
    # Step 7: Generate and return the refresh token along with access token details
    """

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithm '{algorithm}' is not supported")

    grant_type = data.get("grant_type")
    if grant_type != constants.GrantType.TOKEN_EXCHANGE.value:
        raise UnsupportedGrantTypeError(f"grant_type must be {constants.GrantType.TOKEN_EXCHANGE.value}")
    subject_token = data.get("subject_token")
    subject_token_type = data.get("subject_token_type")
    if subject_token_type not in SUBJECT_TOKEN_TYPE_SUPPORTED:
        raise InvalidOIDCRequestError("subject_token_type requested is not allowed")
    
    requested_token_type = data.get("requested_token_type", None)
    if requested_token_type:
        if str(requested_token_type) not in REQUESTED_TOKEN_TYPE_SUPPORTED:
             raise InvalidOIDCRequestError("requested_token_type is not allowed")
    else:
        requested_token_type = "urn:ietf:params:oauth:token-type:access_token"
    requested_scopes = data.get("scope", "")
    check_client_allowed_scopes = requested_scopes.split()
    if not validate_client(client_id, client_secret, required_scopes=check_client_allowed_scopes, required_grant_types=[grant_type], session=session):
        #raise UnauthorizedOIDCClientError
        #raise InvalidOIDCRequestError
        raise UnsupportedGrantTypeError("Invalid client credentials or insufficient scope/grant type for the client")

    try:
        decoded_token = decode_token(subject_token, algorithm)
    except jwt.InvalidTokenError:
        raise InvalidGrantError("Invalid subject token")

    validate_expiration(decoded_token)
    response = {}
    # Ensure requested scopes is subset of the scopes in subject_token
    granted_scopes = str(decoded_token.get("scope", ""))
    granted_scopes_list = granted_scopes.split()
    if check_client_allowed_scopes:
        if granted_scopes_list.issubset(check_client_allowed_scopes):
            raise InvalidOIDCRequestError("One or more requested scopes is beyond what your subject_token have.")

    if requested_token_type == "urn:ietf:params:oauth:token-type:refresh_token":
        if not "offline_access" in granted_scopes_list:
            raise InvalidOIDCRequestError("subjetc_token doesn't have offline_access scope to request urn:ietf:params:oauth:token-type:referesh_token")
        refresh_token = create_refresh_token(decoded_token["sub"], granted_scopes)
        response["refresh_token"] = refresh_token

    # Generate new access token
    new_access_token = issue_access_token(
                        scope=granted_scopes,
                        audience=data.get("audience"),
                        algorithm=algorithm,
    )

    response["access_token"] = new_access_token["access_token"]
    response["issued_token_type"] = requested_token_type
    response["token_type"] =  "Bearer"
    response["expires_in"] = ACCESS_TOKEN_LIFETIME

    return response

@read_session
def handle_refresh_token(data: RefreshTokenRequest, client_id: str, client_secret: str, algorithm: str = "RS256", *, session = "Session") -> RefreshTokenResponse:
    """
    Handle the refresh token flow to generate a new access token.
    https://datatracker.ietf.org/doc/html/rfc6749#section-6
    :param data: Dictionary containing the refresh token request parameters.
    :param algorithm: The JWT algorithm used to sign/verify the tokens. Default is RS256.
    :return: A dictionary containing the new access token and other response parameters.
    """

    grant_type = data.get("grant_type")
    if grant_type != constants.GrantType.REFRESH_TOKEN.value:
        raise UnsupportedGrantTypeError(f"grant_type must be {constants.GrantType.REFRESH_TOKEN.value}")

    requested_scopes = data.get("scope", "")
    check_client_allowed_scopes = requested_scopes.split()
    if not validate_client(client_id, client_secret, required_scopes=check_client_allowed_scopes, required_grant_types=[grant_type], session=session):
        raise UnsupportedGrantTypeError("Invalid client credentials or insufficient scope/grant type for the client")

    refresh_token = data.get("refresh_token")
    try:
        decoded_refresh_token = decode_token(refresh_token, algorithm)
    except jwt.InvalidTokenError:
        raise InvalidOIDCRequestError("Invalid refresh token")
    except jwt.ExpiredSignatureError:
        raise InvalidOIDCRequestError("Refresh token has expired")

    validate_expiration(decoded_refresh_token)
    granted_scopes_list = str(decoded_refresh_token.get("scope", "")).split()
    if check_client_allowed_scopes:
        if granted_scopes_list.issubset(check_client_allowed_scopes):
            raise InvalidOIDCRequestError("One or more requested scopes is beyond what your subject_token have.")

    # Create a new access token with the validated scopes
    new_access_token = issue_access_token(
                        scope=requested_scopes,
                        audience=data.get("audience"),
                        algorithm=algorithm,
                        )

    return {
        "access_token": new_access_token["access_token"],
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFETIME,
    }

@read_session
def handle_token(
    data: Union[TokenExchangeRequest, RefreshTokenRequest], 
    client_id: str, 
    client_secret: str, 
    algorithm: str = "RS256", 
    *, 
    session="Session"
) -> Union[TokenExchangeResponse, RefreshTokenResponse]:
    """
    Handle token requests for both token exchange and refresh token flows.
    """
    grant_type = data.get("grant_type")

    if grant_type == constants.GrantType.TOKEN_EXCHANGE.value:
        # Handle token exchange
        return handle_token_exchange(
            data=data,
            client_id=client_id,
            client_secret=client_secret,
            algorithm=algorithm,
            session=session
        )
    elif grant_type == constants.GrantType.REFRESH_TOKEN.value:
        # Handle refresh token
        return handle_refresh_token(
            data=data,
            client_id=client_id,
            client_secret=client_secret,
            algorithm=algorithm,
            session=session
        )
    else:
        raise UnsupportedGrantTypeError(f"Unsupported grant_type: {grant_type}")



def openid_config_resource():
    """ OpenID discovery """
    res = {
            "issuer": ISSUER,
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "scopes_supported": ["storage.read", "storage.write", "storage.modify", "storage.stage", "offline_access"],
            "response_types_supported": ["token"],
            "grant_types_supported": [constants.GrantType.TOKEN_EXCHANGE.value ,constants.GrantType.REFRESH_TOKEN.value],
            "claims_supported": ["sub", "iss", "exp", "iat", "nbf", "jti", "wlcg.ver", "wlcg.groups", "scope"],
        }
    return res

def jwks():
    """Return JWKS configuration for public key discovery."""

    def load_public_key(key_path):
        with open(key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key

    public_key = load_public_key(PUBLIC_KEY_PATH)
    numbers = public_key.public_numbers()
    return {
        "keys": [
            {
                "alg": "RS256",
                "kid": "RS256-1",
                "use": "sig",
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
                "e": "AQAB", #base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
            },
        ]
    }

