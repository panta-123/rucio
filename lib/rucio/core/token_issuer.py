import datetime
import uuid
from typing import Any, Optional, TypedDict

import jwt

from rucio.common.exception import CannotAuthenticate, CannotAuthorize, RucioException

SUPPORTED_ALGORITHMS = ["HS256"]

ISSUER = "myruciohome"
SECRET_KEY = "your_secret_key"
SUPPORTED_ALGORITHMS = ["HS256", "RS256"]

# RSA Keys (Load from files or environment variables)
with open("private.key", "r") as private_key_file:
    PRIVATE_KEY_RS256 = private_key_file.read()

with open("public.key", "r") as public_key_file:
    PUBLIC_KEY_RS256 = public_key_file.read()

ACCESS_TOKEN_LIFETIME = 21600
REFRESH_TOKEN_LIFETIME = 864000
DEFAULT_AUDIENCE = "https://rucio.jlab.org"

class SupportedScopes(TypedDict):
    storage_read: str
    storage_modify: str
    storage_create: str
    storage_stage: str
    offline_access: str

class GrantTypes(TypedDict):
    token_exchange: str
    token_refresh: str

class WLCGPayload(TypedDict):
    sub: str
    exp: 'datetime'
    iss: str
    wlcg_ver: str
    #wlcggroups: Optional[str]
    aud: str
    iat: 'datetime'
    nbf: 'datetime'
    jti: str
    scope: str  

SUPPORTED_SCOPES: SupportedScopes = {
    "storage_read": "storage.read",
    "storage_modify": "storage.modify",
    "storage_create": "storage.create",
    "storage_stage": "storage.stage",
    "offline_access": "offline_access"
}

GRANT_TYPES_SUPPORTED: GrantTypes = {
    "token_exchange": "urn:ietf:params:oauth:grant-type:token-exchange",
    "token_refresh": "refresh_token"
}

def is_scope_allowed(requested_scope: str) -> bool:
    """ Check allowed scopes
    """
    # Split the requested scope into action and path
    action, _ = requested_scope.split(':', 1) if ':' in requested_scope else (requested_scope, '')
    # Check if the action part of the requested scope matches any allowed scope
    return any(action == allowed_scope for allowed_scope in SUPPORTED_SCOPES.values())

def create_access_token(sub: str, scope: str, audience: Optional[str] = DEFAULT_AUDIENCE, algorithm: str = "RS256"):
    if not is_scope_allowed(scope):
        raise ValueError(f"Requested scope '{scope}' is not allowed")
    payload = {
        "sub": sub,
        "iss": ISSUER,
        "exp": datetime.datetime.now(datetime.timezone.utc)  + datetime.timedelta(seconds=ACCESS_TOKEN_LIFETIME),
        "iat": datetime.datetime.now(datetime.timezone.utc) ,
        "nbf": datetime.datetime.now(datetime.timezone.utc) ,
        "jti": str(uuid.uuid4()),
        "wlcg.ver": "1.0",
        "scope": scope,
        "aud": audience if audience else DEFAULT_AUDIENCE
    }
    if algorithm == "HS256":
        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    else:
        return jwt.encode(payload, PRIVATE_KEY_RS256, algorithm=algorithm)


def issue_access_token(
    sub: str,
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

    scopes = scope.split()
    if not all(is_scope_allowed(s) for s in scopes):
        raise ValueError(f"One or more requested scopes are not allowed")

    # Validate and create the access token
    access_token = create_access_token(sub, scope, audience, algorithm)

    response = {
        "access_token": access_token,
        "token_type": "Bearer",  # Token type as per RFC 6749 Section 7.1
        "expires_in": ACCESS_TOKEN_LIFETIME,
    }
    # Include refresh token if required
    if "offline_access" in scopes:
        refresh_token = create_access_token(sub, scope, audience, algorithm)
        response["refresh_token"] = refresh_token

    # Include the scope if it differs from the requested scope
    granted_scope = scope
    if granted_scope != scope:
        response["scope"] = granted_scope

    # Add HTTP headers to prevent caching
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }

    return response, 200, headers

def create_refresh_token(sub: str, scope: str, audience: Optional[str]= DEFAULT_AUDIENCE, algorithm: str = "RS256"):
    scopes = scope.split()
    if not all(is_scope_allowed(s) for s in scopes):
        raise ValueError(f"One or more requested scopes are not allowed")

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

def handle_token_exchange(data: dict[str, Any], algorithm: str = "RS256") -> dict[str, Any]:
    """
    Handle token exchange according to https://datatracker.ietf.org/doc/html/rfc8693#name-token-exchange-request-and-

    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithm '{algorithm}' is not supported")

    # Extract required fields
    subject_token = data.get("subject_token")
    subject_token_type = data.get("subject_token_type")
    grant_type = data.get("grant_type")
    if not subject_token or not subject_token_type or not grant_type:
        raise ValueError("Required fields 'subject_token', 'subject_token_type', and 'grant_type' are missing")

    if grant_type != GRANT_TYPES_SUPPORTED["token_exchange"]:
        raise ValueError("Invalid grant type")


    requested_token_type = data.get("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")

    # Decode the subject token
    try:
        if algorithm == "HS256":
            decoded_token = jwt.decode(subject_token, SECRET_KEY, algorithms=[algorithm])
        else:
            decoded_token = jwt.decode(subject_token, PUBLIC_KEY_RS256, algorithms=[algorithm], options={"verify_aud": False})
    except jwt.InvalidTokenError:
        return {"error": "Invalid subject token"}, 401

    # Ensure requested scopes are within the granted scopes
    granted_scopes = str(decoded_token.get("scope", ""))
    granted_scopes_list = granted_scopes.split()

    if not all(is_scope_allowed(s) for s in granted_scopes_list):
        raise ValueError("One or more requested scopes are not allowed")
    if "offline_access" not in granted_scopes_list:
        raise ValueError("The 'offline_access' scope is required for token exchange")

    # Generate refresh token
    refresh_token = create_refresh_token(decoded_token["sub"], granted_scopes)
    print(jwt.get_unverified_header(subject_token))
    return {
        "access_token": subject_token,
        "issued_token_type": requested_token_type,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFETIME,
        "refresh_token": refresh_token,
    }

def handle_refresh_token(data: dict[str, str], algorithm: str = "RS256"):
    """
    Handle the refresh token flow to generate a new access token.
    https://datatracker.ietf.org/doc/html/rfc6749#section-6
    :param data: Dictionary containing the refresh token request parameters.
    :param algorithm: The JWT algorithm used to sign/verify the tokens. Default is RS256.
    :return: A dictionary containing the new access token and other response parameters.
    """
    if data.get("grant_type") != GRANT_TYPES_SUPPORTED["token_refresh"]:
        raise CannotAuthenticate("error :Invalid grant type. Expected 'refresh_token'")

    refresh_token = data.get("refresh_token")
    requested_scopes = data.get("scope", "")  # Scope is optional in refresh requests
    requested_scopes_list = requested_scopes.split()
    try:
        if algorithm == "HS256":
            decoded_refresh_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=[algorithm])
        else:
            decoded_refresh_token = jwt.decode(refresh_token, PUBLIC_KEY_RS256, algorithms=[algorithm],  options={"verify_aud": False})
    except jwt.ExpiredSignatureError:
        return {"error": "Refresh token has expired"}, 401
    except jwt.InvalidTokenError:
        return {"error": "Invalid refresh token"}, 401

    # Extract granted scopes from the refresh token
    granted_scopes = str(decoded_refresh_token.get("scope"))
    granted_scopes_list = granted_scopes.split()
    # Validate requested scopes
    if requested_scopes_list:
        if not set(requested_scopes_list).issubset(set(granted_scopes_list)):
            return {"error": "One or more requested scopes were not originally granted"}, 400
    else:
        # If no scope is requested, use the originally granted scope
        requested_scopes= granted_scopes
    # Create a new access token with the validated scopes
    new_access_token = create_access_token(
                        sub=decoded_refresh_token["sub"],
                        scope=requested_scopes,
                        audience=data.get("audience"),
                        algorithm=algorithm,
                        )

    return {
        "access_token": new_access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFETIME,
    }


def openid_config_resource():
    res = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
            "scopes_supported": ["offline_access"],
            "response_types_supported": ["token"],
            "grant_types_supported": list(GRANT_TYPES_SUPPORTED.values()),
            "claims_supported": ["sub", "iss", "exp", "iat", "nbf", "jti", "wlcg.ver", "wlcg.groups", "scope"],
        }
    return res

def jwks():
    """Return JWKS configuration for public key discovery."""
    return {
        "keys": [
            {
                "alg": "RS256",
                "kid": "RS256-1",
                "use": "sig",
                "kty": "RSA",
                "n": jwt.algorithms.RSAAlgorithm.from_jwk(PUBLIC_KEY_RS256).public_numbers().n,
                "e": jwt.algorithms.RSAAlgorithm.from_jwk(PUBLIC_KEY_RS256).public_numbers().e
            },
        ]
    }


res = create_access_token("12345", scope= "storage.read:/myfile/myfile.txt offline_access")

data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token": str(res),
    }
result = handle_token_exchange(data=data)
print(result)


data = {
        "grant_type": "refresh_token",
        "refresh_token": result["refresh_token"],
    }

refresh_res = handle_refresh_token(data=data)
