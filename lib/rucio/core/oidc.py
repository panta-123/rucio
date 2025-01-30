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

import hashlib
import json
import logging
import traceback
import uuid
from datetime import datetime, timedelta
from math import floor
from typing import TYPE_CHECKING, Any, Final, Literal, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import requests
from dogpile.cache.api import NoValue
from sqlalchemy import delete, null, or_, select, update
from sqlalchemy.sql.expression import true

from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get, config_get_int
from rucio.common.exception import CannotAuthenticate, CannotAuthorize, RucioException
from rucio.common.utils import all_oidc_req_claims_present, chunks, val_to_space_sep_str
from rucio.core.account import account_exists
from rucio.core.identity import exist_identity_account
from rucio.core.monitor import MetricManager
from rucio.db.sqla import models
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount

# The WLCG Common JWT Profile dictates that the lifetime of access and ID tokens
# should range from five minutes to six hours.
TOKEN_MIN_LIFETIME: Final = config_get_int('oidc', 'token_min_lifetime', default=300)
TOKEN_MAX_LIFETIME: Final = config_get_int('oidc', 'token_max_lifetime', default=21600)

REGION: Final = MemcacheRegion(expiration_time=TOKEN_MAX_LIFETIME)
METRICS = MetricManager(module=__name__)
CACHE_REGION: Final = MemcacheRegion(expiration_time=86400)
# private/protected file containing Rucio Client secrets known to the Identity Provider as well
IDPSECRETS = config_get('oidc', 'idpsecrets', False)
EXPECTED_OIDC_AUDIENCE = config_get('oidc', 'expected_audience', False, 'rucio')
# The 'openid' scope is always required for an ID token to be issued.
# 'profile' is added as required for extra scope
DEFAULT_ID_TOKEN_SCOPES = 'openid profile'
# Extra scopes for id token.
ID_TOKEN_EXTRA_SCOPES = config_get('oidc', 'id_token_extra_scopes', False, '')
# Corresponding claim that needs to there for above scopes
ID_TOKEN_EXTRA_CLAIMS = config_get('oidc', 'id_token_extra_claims', False, '')
EXPECTED_OIDC_ACCESS_TOKEN_SCOPE = config_get('oidc', 'expected_access_token_scope', False, 'rucio')
REFRESH_LIFETIME_H = config_get_int('oidc', 'default_jwt_refresh_lifetime', False, 96)

# Allow 2 mins of leeway in case Rucio and IdP server clocks are not perfectly synchronized
# this affects the token issued time (a token could be issued in the future if IdP clock is ahead)
LEEWAY_SECS = 120

class LazyConfigLoad:
    def __init__(self, config_file: str = IDPSECRETS):
        """Initialize with a JSON configuration file."""
        self.config_file = config_file
        self._config = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load and validate the configuration file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self._config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise ValueError(f"Error loading '{self.config_file}': {exc}")

        self._validate_config()

    def get_vo_user_auth_config(self, vo: str = "def") -> dict:
        """Retrieve the issuer configuration for a VO."""
        config = self._config.get(vo)
        if not config:
            raise ValueError(f"VO '{vo}' not found in the configuration.")

        # Exclude 'client_credential_client' from issuer list
        vo_user_auth_config = {"issuer": config["issuer"]}
        vo_user_auth_config.update(config["user_auth_client"])

        return vo_user_auth_config

    def get_client_credential_client(self, vo: str = "def") -> dict:
        """Retrieve client credentials for the specified VO."""
        config = self._config.get(vo)
        if not config:
            raise ValueError(f"VO '{vo}' not found in the configuration.")

        vo_client_credential_config = {"issuer": config["issuer"]}
        vo_client_credential_config.update(config["client_credential_client"])

        return vo_client_credential_config

    def is_valid_issuer(self, issuer_url: str, vo: str = "def") -> bool:
        """Check if the given issuer URL matches the VO's configured issuer."""
        return self.get_vo_user_auth_config(vo).get("issuer") == issuer_url

    def _validate_config(self) -> None:
        """Validate the configuration format."""
        if not self._config:
            raise ValueError("Configuration is empty or invalid.")

        for vo, details in self._config.items():
            if not isinstance(details, dict):
                raise ValueError(f"VO '{vo}' must have a dictionary configuration.")
            if not details.get("issuer", None):
                ValueError(f"No issuer key in VO '{vo}' config")

            user_auth_client = details.get("user_auth_client")
            if not user_auth_client or not all(k in user_auth_client for k in ["client_id", "client_secret"]):
                raise ValueError(f"VO '{vo}' must have 'client_id' and 'client_secret'.")
            if not isinstance(user_auth_client.get("redirect_uris", []), list):
                raise ValueError(f" VO '{vo}' user_auth_client must have a list of 'redirect_uris'.")

            client_credential_client = details.get("client_credential_client")
            if not client_credential_client or not all(k in client_credential_client for k in ["client_id", "client_secret"]):
                raise ValueError(f"VO '{vo}' client_credential_client must have 'client_id' and 'client_secret'.")



@METRICS.time_it
def _token_cache_get(
    key: str,
    min_lifetime: int = TOKEN_MIN_LIFETIME,
) -> Optional[str]:
    """Retrieve a token from the cache.

    Return ``None`` if the cache backend did not return a value, the value is
    not a valid JWT, or the token has a remaining lifetime less than
    ``min_lifetime`` seconds.
    """
    value = REGION.get(key)
    if isinstance(value, NoValue):
        METRICS.counter('token_cache.miss').inc()
        return None

    if isinstance(value, str):
        try:
            payload = jwt.decode(value, options={"verify_signature": False})
        except Exception:
            METRICS.counter('token_cache.invalid').inc()
            return None
    else:
        METRICS.counter('token_cache.invalid').inc()
        return None

    now = datetime.utcnow().timestamp()
    expiration = payload.get('exp', 0)    # type: ignore
    if now + min_lifetime > expiration:
        METRICS.counter('token_cache.expired').inc()
        return None

    METRICS.counter('token_cache.hit').inc()
    return value


def get_discovery_metadata(issuer_url: str) -> dict[str, Any]:
    """_summary_

    :param str issuer_url: _description_
    :return dict[str, Any]: _description_
    """
    # Check if the JWKS content is already cached
    cache_key = f"discovery_metadata_{issuer_url}"
    cached_discovery = CACHE_REGION.get(cache_key)
    if cached_discovery:
        return json.loads(cached_discovery)
    discovery_url = f"{issuer_url}/.well-known/openid-configuration"
    response = requests.get(discovery_url, timeout=10)
    response.raise_for_status()
    metadata = response.json()
    CACHE_REGION.set(cache_key, json.dumps(metadata))
    return metadata


def get_jwks_content(issuer_url: str) -> dict[str, Any]:
    """
    Discover the JWKS content from the issuer's metadata and cache the response.

    :param issuer_url: The issuer's base URL (e.g., https://example.com).
    :return: The JWKS content (JSON with public keys).
    """
    # Check if the JWKS content is already cached
    cache_key = f"jwks_content_{issuer_url}"
    cached_jwks = CACHE_REGION.get(cache_key)

    if cached_jwks:
        return json.loads(cached_jwks)  # Return the cached JWKS content

    metadata = get_discovery_metadata(issuer_url=issuer_url)

    # Get the jwks_uri from the metadata
    jwks_url = metadata.get("jwks_uri")
    if not jwks_url:
        raise ValueError("No 'jwks_uri' found in the metadata.")

    # Fetch the JWKS content
    jwks_response = requests.get(jwks_url, timeout=10)
    jwks_response.raise_for_status()
    jwks_content = jwks_response.json()

    # Cache the JWKS content
    CACHE_REGION.set(cache_key, json.dumps(jwks_content))
    return jwks_content


def validate_token(
        token: str,
        issuer_url: str,
        audience:str,
        token_type: Literal["id_token", "access_token"],
        nonce:Optional[str] = None,
) -> dict[str, Any]:
    """
    Validate an ID token or access token.

    :param token: The token to validate (ID token or access token).
    :param issuer_url: The issuer URL for the token.
    :param audience: The expected audience (client ID or resource server).
    :param nonce: The nonce from the original request (for ID token validation).
    :param token_type: The type of token ("id_token" or "access_token").

    :return: The decoded token if valid.
    """
    jwks_content = get_jwks_content(issuer_url=issuer_url)
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid", None)
    alg = headers.get("alg")
    if not alg:
        raise ValueError("Token header is missing the 'alg' (algorithm) claim.")
    if not kid:
        # in this case use the first key
        keys = jwks_content.get("keys", [])
        if not keys:
            raise ValueError("No keys found in JWKS.")
        key = keys[0]
    else:
        # Find the key in the JWKS matching the 'kid'
        key = next((jwk for jwk in jwks_content.get("keys", []) if jwk.get("kid") == kid), None)
        if not key:
            raise ValueError(f"No matching key found in JWKS for kid: {kid}")

    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    except Exception as e:
        raise ValueError(f"Failed to convert JWK to PEM-format public key: {e}") from e

    # Decode and validate the token
    try:
        decoded_token = jwt.decode(
            token,
            key=public_key,
            audience=audience,
            issuer=issuer_url,
            algorithms=[alg],
            options={"verify_signature": True}
        )
    except Exception as e:
        raise CannotAuthenticate(f"Invalid {token_type}: {e}")

    # Additional validation for ID tokens
    if token_type == "id_token" and nonce:
        # openid in scope means sub has to be present in id_token
        if "sub" not in decoded_token:
            raise CannotAuthenticate("Failed to get sub from ID token. 'openid' scope is needed for oidc client")
        if "profile" in ID_TOKEN_EXTRA_SCOPES:
            # according to https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
            profile_claims = ["profile","name", "given_name", "family_name"]
            has_profile_scope = any(claim in decoded_token for claim in profile_claims)
            if not has_profile_scope:
                raise CannotAuthenticate("Failed to get name from ID token")
        if "email" in ID_TOKEN_EXTRA_SCOPES:
            if not "email" in decoded_token:
                raise CannotAuthenticate("failed to get email from ID token")
        # security for replay attack
        if decoded_token.get("nonce") != nonce:
            raise CannotAuthenticate("Invalid nonce in ID token.")
        if ID_TOKEN_EXTRA_CLAIMS:
            for _claim in ID_TOKEN_EXTRA_CLAIMS:
                if _claim not in ID_TOKEN_EXTRA_CLAIMS:
                    raise CannotAuthenticate(f"failed to get {_claim} from ID token")

    return decoded_token


def request_token(
    scope: str,
    audience: Optional[str] = None,
    resource: Optional[str] = None,
    vo: str = 'def',
    use_cache: bool = True,
) -> Optional[str]:
    """
    Request a token from the provider.

    Return ``None`` if the configuration was not loaded properly or the request
    was unsuccessful.

    :param scope: Scope of the token.
    :param audience: (Optional) Audience for the token.
    :param vo: Virtual Organization (default: 'def').
    :param use_cache: Whether to use caching for tokens (default: True).
    :param resource: (Optional) Resource for the token as per RFC8707.
    :return: The access token or None if the request fails.
    :raises ValueError: If neither 'audience' nor 'resource' is provided.
    """
    # Validate input: Either 'audience' or 'resource' must be provided
    if not audience and not resource:
        raise ValueError("Either 'audience' or 'resource' (RFC8707) must be provided.")

    # Load configuration
    config_loader = LazyConfigLoad()
    client_config = config_loader.get_client_credential_client(vo)

    if client_config is None:
        raise ValueError(f"Configuration for VO '{vo}' not found.")

    # Access IDP configurations within the VO
    issuer = client_config.get("issuer")
    issuer_token_endpoint = get_discovery_metadata(issuer_url=issuer)["token_endpoint"]
    client_id = client_config.get("client_id")
    client_secret = client_config.get("client_secret")

    # Create a cache key based on parameters
    cache_key_base = f"scope={scope};vo={vo}"
    if audience:
        cache_key_base += f";audience={audience}"
    elif resource:
        cache_key_base += f";resource={resource}"
    key = hashlib.md5(cache_key_base.encode()).hexdigest()

    # Check cache
    if use_cache and (token := _token_cache_get(key)):
        return token

    # Prepare token request payload
    data = {
        'grant_type': 'client_credentials',
        'scope': scope,
    }
    if audience:
        data['audience'] = audience
    elif resource:
        data['resource'] = resource

    # Request the token
    try:
        response = requests.post(
            url=issuer_token_endpoint,
            auth=(client_id, client_secret), # type: ignore
            data=data,
            timeout=10  # Add a timeout of 10 seconds
        )
        response.raise_for_status()
        payload = response.json()
        token = payload['access_token']
    except Exception:
        logging.debug('Failed to procure a token', exc_info=True)
        return None

    # Cache the token if caching is enabled
    if use_cache:
        REGION.set(key, token)
    return token


@transactional_session
def get_auth_oidc(
    account: str,
    vo: str = 'def',
    *,
    session: "Session",
    **kwargs
) -> Optional[str]:
    """
    Assembles the authorization request of the Rucio Client tailored to the Rucio user
    & Identity Provider. Saves authentication session parameters in the oauth_requests
    DB table (for later use-cases). This information is saved for the token lifetime
    of a token to allow token exchange and refresh.
    Returns authorization URL as a string or a redirection url to
    be used in user's browser for authentication.

    :param account: Rucio Account identifier as a string.
    :param auth_scope: space separated list of scope names. Scope parameter
                       defines which user's info the user allows to provide
                       to the Rucio Client.
    :param audience: audience for which tokens are requested (EXPECTED_OIDC_AUDIENCE is the default)
    :param polling: If True, '_polling' string will be appended to the access_msg
                    in the DB oauth_requests table to inform the authorization stage
                    that the Rucio Client is polling the server for a token
    :param refresh_lifetime: specifies how long the OAuth daemon should
                             be refreshing this token. Default is 96 hours.
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns: User & Rucio OIDC Client specific Authorization or Redirection URL as a string
              OR a redirection url to be used in user's browser for authentication.
    """
    # TO-DO - implement a check if that account already has a valid
    # token with the required scope and audience and return such token !
    if not account_exists(account, session=session):
        logging.debug("Account %s does not exist.", account)
        return None

    auth_scope = kwargs.get('auth_scope', None)
    if not auth_scope:
        auth_scope = DEFAULT_ID_TOKEN_SCOPES + ID_TOKEN_EXTRA_SCOPES

    audience = kwargs.get('audience', EXPECTED_OIDC_AUDIENCE)
    resource = None

    config_loader = LazyConfigLoad()
    idp_config_vo = config_loader.get_vo_user_auth_config(vo)
    redirect_url = idp_config_vo["redirect_url"]
    client_id = idp_config_vo["client_id"]
    issuer = idp_config_vo["issuer"]
    authorization_endpoint = get_discovery_metadata(issuer_url=issuer)["authorization_endpoint"]

    polling = kwargs.get('polling', False)
    refresh_lifetime = kwargs.get('refresh_lifetime', REFRESH_LIFETIME_H)
    ip = kwargs.get('ip', None)

    try:
        # uuid4 string in order to keep track of responses to outstanding requests (state)
        # and to associate a client session with an ID Token and to mitigate replay attacks (nonce).
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        auth_url = authorization_endpoint
        # redirect code is put in access_msg and returned to the user
        access_msg =str(uuid.uuid4())
        if polling:
            access_msg += '_polling'
        # Making sure refresh_lifetime is an integer or None.
        if refresh_lifetime:
            refresh_lifetime = int(refresh_lifetime)
        # Specifying temporarily 5 min lifetime for the authentication session.
        expired_at = datetime.utcnow() + timedelta(seconds=300)
        # saving session parameters into the Rucio DB
        oauth_session_params = models.OAuthRequest(account=account,
                                                   state=state,
                                                   nonce=nonce,
                                                   access_msg=access_msg,
                                                   redirect_msg=auth_url,
                                                   expired_at=expired_at,
                                                   refresh_lifetime=refresh_lifetime,
                                                   ip=ip)
        oauth_session_params.save(session=session)
        _delete_oauth_request_by_account_and_expiration(account, session=session)
        auth_server = urlparse(authorization_endpoint)

        # Build the query parameters
        query_params = {
            "client_id": client_id,
            "response_type": "code",
            "state": state,
            "nonce": nonce,
            "redirect_uri": redirect_url,
            "scope": auth_scope,
        }
        if audience:
            query_params['audience'] = audience
        else:
            query_params['resource'] = resource

        auth_server = urlparse(authorization_endpoint)
        auth_url = f"{auth_server.geturl()}?{urlencode(query_params)}"
        return auth_url

    except Exception as error:
        raise CannotAuthenticate(traceback.format_exc()) from error


@transactional_session
def get_token_oidc(
    auth_query_string: str,
    ip: Optional[str] = None,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[dict[str, Optional[Union[str, bool]]]]:
    """
    After Rucio User got redirected to Rucio /auth/oidc_token (or /auth/oidc_code)
    REST endpoints with authz code and session state encoded within the URL.
    These parameters are used to eventually gets user's info and tokens from IdP.

    :param auth_query_string: IdP redirection URL query string (AuthZ code & user session state).
    :param ip: IP address of the client as a string.
    :param session: The database session in use.

    :returns:
    """
    # parse auth_query_string
    parsed_authquery = parse_qs(auth_query_string)
    state = parsed_authquery["state"][0]
    code = parsed_authquery["code"][0]

    # getting oauth request params from the oauth_requests DB Table
    query = select(
        models.OAuthRequest
    ).where(
        models.OAuthRequest.state == state
    )
    oauth_req_params = session.execute(query).scalar()
    if oauth_req_params is None:
        raise CannotAuthenticate("User related Rucio OIDC session could not keep "
                                    + "track of responses from outstanding requests.")  # NOQA: W503
    nonce = oauth_req_params.nonce
    account = oauth_req_params.account
    req_url = urlparse(oauth_req_params.redirect_msg or '')
    issuer_url = req_url.scheme + "://" + req_url.netloc

    # get info from config
    config_loader = LazyConfigLoad()
    idp_config_vo =config_loader.get_vo_user_auth_config(vo)
    issuer_token_endpoint = get_discovery_metadata(issuer_url=issuer_url)["token_endpoint"]
    config_loader = LazyConfigLoad()
    redirect_url = idp_config_vo["redirect_url"]
    client_id = idp_config_vo["client_id"]
    client_secret = idp_config_vo["client_secret"]

    req_params = parse_qs(req_url.query)
    client_params = {}
    for key in list(req_params):
        client_params[key] = val_to_space_sep_str(req_params[key])

    response = requests.post(issuer_token_endpoint, data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_url,
        'client_id': client_id,
        'client_secret': client_secret,
    }, timeout=10)
    tokens = response.json()
    if "access_token" not in tokens or "id_token" not in tokens:
        raise CannotAuthenticate("ID token or access token missing in the response.")

    # Decode the ID token and validate the nonce
    token_type = "id_token"
    id_token_decoded = validate_token(token=tokens['id_token'], issuer_url=issuer_url, nonce=nonce, audience=client_id, token_type=token_type)
    # Extract the issuer from the ID token
    issuer_from_id_token = id_token_decoded.get("iss")
    sub_from_id_token = id_token_decoded.get("sub")
    identity = oidc_identity_string(issuer_from_id_token, sub_from_id_token)
    # check if given account has the identity registered
    if not exist_identity_account(identity, IdentityType.OIDC, account, session=session):
        raise CannotAuthenticate("OIDC identity '%s' of the '%s' account is unknown to Rucio."
                                    % (identity, account))
    # extract scope, audience, lifetime from access token
    token_type = "access_token"
    access_token_decoded = validate_token(token=tokens['access_token'], issuer_url=issuer_url, audience=EXPECTED_OIDC_AUDIENCE, token_type=token_type)
    scopes =  access_token_decoded['scopes']
    exp_at = access_token_decoded['exp']
    lifetime = datetime.utcnow() + timedelta(seconds=exp_at)

    # assemble OIDC table value
    jwt_row_dict = {
        'authz_scope': scopes,
        'audience': EXPECTED_OIDC_AUDIENCE,
        'lifetime': lifetime,
        'account': account,
        'identity': identity
    }
    extra_dict: dict[str, Any] = {'state': state}
    if ip:
        extra_dict['ip'] = ip
    if 'refresh_token' in tokens:
        extra_dict['refresh_token'] = tokens['refresh_token']
        extra_dict['refresh'] = True
        extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
        extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)
    new_token = __save_validated_token(tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
    __delete_expired_tokens_account(account=account, session=session)
    if oauth_req_params.access_msg:
        if 'http' not in oauth_req_params.access_msg:
            if '_polling' not in oauth_req_params.access_msg:
                fetchcode = str(uuid.uuid4())
                query = update(
                    models.OAuthRequest
                ).where(
                    models.OAuthRequest.state == state
                ).values({
                    models.OAuthRequest.access_msg: fetchcode,
                    models.OAuthRequest.redirect_msg: new_token['token']
                })
                # If Rucio Client was requested to poll the Rucio Auth server
                # for a token automatically, we save the token under a access_msg.
            else:
                query = update(
                    models.OAuthRequest
                ).where(
                    models.OAuthRequest.state == state
                ).values({
                    models.OAuthRequest.access_msg: oauth_req_params.access_msg,
                    models.OAuthRequest.redirect_msg: new_token['token']
                })
            session.execute(query)
            session.commit()
            if '_polling' in oauth_req_params.access_msg:
                return {'polling': True}
            elif 'http' in oauth_req_params.access_msg:
                return {'webhome': oauth_req_params.access_msg, 'token': new_token}
            else:
                return {'fetchcode': fetchcode}

    return {'token': new_token}


@transactional_session
def refresh_cli_auth_token(
    token_string: str,
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> Optional[tuple[str, int]]:
    """
    Checks if there is active refresh token and if so returns
    either active token with expiration timestamp or requests a new
    refresh and returns new access token.
    :param token_string: token string
    :param account: Rucio account for which token refresh should be considered

    :return: tuple of (access token, expiration epoch), None otherwise
    """
    # only validated tokens are in the DB, check presence of token_string
    query = select(
        models.Token
    ).where(
        models.Token.token == token_string,
        models.Token.account == account,
        models.Token.expired_at > datetime.utcnow()
    ).with_for_update(
        skip_locked=True
    )
    account_token = session.execute(query).scalar()

    # if token does not exist in the DB, return None
    if account_token is None:
        logging.debug("No valid token exists for account %s.", account)
        return None

    # protection (!) no further action should be made
    # for token_string without refresh_token in the DB !
    if account_token.refresh_token is None:
        logging.debug("No refresh token exists for account %s.", account)
        return None

    # if the token exists, check if it was refreshed already, if not, refresh it
    if account_token.refresh:
        # protection (!) returning the same token if the token_string
        # is a result of a refresh which happened in the last 5 min
        datetime_min_ago = datetime.utcnow() - timedelta(seconds=300)
        if account_token.updated_at > datetime_min_ago:
            epoch_exp = int(floor((account_token.expired_at - datetime(1970, 1, 1)).total_seconds()))
            new_token_string = account_token.token
            return new_token_string, epoch_exp

        # asking for a refresh of this token
        new_token = __refresh_token_oidc(account_token, vo=vo, session=session)
        new_token_string = new_token['token']
        epoch_exp = int(floor((new_token['expires_at'] - datetime(1970, 1, 1)).total_seconds()))
        return new_token_string, epoch_exp

    else:
        # find account token with the same scope,
        # audience and has a valid refresh token
        query = select(
            models.Token
        ).where(
            models.Token.refresh == true(),
            models.Token.refresh_expired_at > datetime.utcnow(),
            models.Token.account == account,
            models.Token.expired_at > datetime.utcnow()
        ).with_for_update(
            skip_locked=True
        )
        new_token = session.execute(query).scalar()
        if new_token is None:
            return None

        # if the new_token has same audience and scopes as the original
        # account_token --> return this token and exp timestamp to the user
        if all_oidc_req_claims_present(new_token.oidc_scope, new_token.audience,
                                       account_token.oidc_scope, account_token.audience):
            epoch_exp = int(floor((new_token.expired_at - datetime(1970, 1, 1)).total_seconds()))
            new_token_string = new_token.token
            return new_token_string, epoch_exp
        # if scopes and audience are not the same, return None
        logging.debug("No token could be returned for refresh operation for account %s.", account)
        return None


@transactional_session
def _delete_oauth_request_by_account_and_expiration(
    account: str,
    *,
    session: "Session"
) -> None:
    """
    Delete an OAuth request by its account, and expiration time.

    :param account: The account associated with the OAuth request.
    :param expired_at: The expiration time of the OAuth request.
    :param session: Database session in use.

    :returns: Number of deleted rows.
    :raises RucioException: If an error occurs during deletion.
    """
    query = select(
    models.OAuthRequest.state
    ).where(
        models.OAuthRequest.expired_at <= datetime.utcnow(),
        models.OAuthRequest.account == account
    ).with_for_update(
        skip_locked=True
    )

    # Execute the query and fetch all matching states
    oauth_requests = session.execute(query).scalars().all()

    # Process deletion in chunks
    for chunk in chunks(oauth_requests, 100):
        delete_query = delete(
            models.OAuthRequest
        ).where(
            models.OAuthRequest.state.in_(chunk)
        )
        session.execute(delete_query)

    # Commit the transaction
    session.commit()

@transactional_session
def __delete_expired_tokens_account(
    account: "InternalAccount",
    *,
    session: "Session"
) -> None:
    """"
    Deletes expired tokens from the database.

    :param account: Account to delete expired tokens.
    :param session: The database session in use.
    """
    query = select(
            models.Token.token
        ).where(
            models.Token.expired_at <= datetime.utcnow(),
            models.Token.account == account,
            or_(
                models.Token.refresh_expired_at == null(),
                models.Token.refresh_expired_at <= datetime.utcnow()
            )
        ).with_for_update(
        skip_locked=True
    )
    tokens = session.execute(query).scalars().all()

    for chunk in chunks(tokens, 100):
        delete_query = delete(
            models.Token
        ).prefix_with(
            "/*+ INDEX(TOKENS_ACCOUNT_EXPIRED_AT_IDX) */"
        ).where(
            models.Token.token.in_(chunk)
        )
        session.execute(delete_query)

@transactional_session
def __save_validated_token(
    token: str,
    valid_dict: dict[str, Any],
    extra_dict: Optional[dict[str, Any]] = None,
    *,
    session: "Session"
) -> dict[str, Any]:
    """
    Save JWT token to the Rucio DB.

    :param token: Authentication token as a variable-length string.
    :param valid_dict: Validation Rucio dictionary as the output
                       of the __get_rucio_jwt_dict function
    :raises RucioException: on any error
    :returns: A dict with token and expires_at entries.
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

        return token_dictionary(new_token)

    except Exception as error:
        raise RucioException(error.args) from error

@transactional_session
def __change_refresh_state(
    token: str,
    refresh: bool = False,
    *,
    session: "Session"
):
    """
    Changes token refresh state to True/False.

    :param token:      the access token for which the refresh value should be changed.
    """
    try:
        query = update(
            models.Token
        ).where(
            models.Token.token == token
        )
        if refresh:
            # update refresh column for a token to True
            query = query.values({
                models.Token.refresh: True
            })
        else:
            query = query.values({
                models.Token.refresh: False,
                models.Token.refresh_expired_at: datetime.utcnow()
            })
        session.execute(query)
    except Exception as error:
        raise RucioException(error.args) from error


@METRICS.time_it
@transactional_session
def __refresh_token_oidc(
    token_object: models.Token,
    vo: str = 'def',
    *,
    session: "Session"
):
    """
    Requests new access and refresh tokens from the Identity Provider.
    Assumption: The Identity Provider issues refresh tokens for one time use only and
    with a limited lifetime. The refresh tokens are invalidated no matter which of these
    situations happens first.

    :param token_object: Rucio models.Token DB row object

    :returns: A dict with token and expires_at entries if all went OK, None if
        refresh was not possible due to token invalidity or refresh lifetime
        constraints. Otherwise, throws an an Exception.
    """
    jwt_row_dict, extra_dict = {}, {}
    jwt_row_dict['account'] = token_object.account
    jwt_row_dict['identity'] = token_object.identity
    extra_dict['refresh_start'] = datetime.utcnow()
    # check if refresh token started in the past already
    if hasattr(token_object, 'refresh_start'):
        if token_object.refresh_start:
            extra_dict['refresh_start'] = token_object.refresh_start
    # check if refresh lifetime is set for the token
    extra_dict['refresh_lifetime'] = REFRESH_LIFETIME_H
    if token_object.refresh_lifetime:
        extra_dict['refresh_lifetime'] = token_object.refresh_lifetime
    # if the token has been refreshed for time exceeding
    # the refresh_lifetime, the attempt will be aborted and refresh stopped
    if datetime.utcnow() - extra_dict['refresh_start'] > timedelta(hours=extra_dict['refresh_lifetime']):
        __change_refresh_state(token_object.token, refresh=False, session=session)
        return None

    refresh_token = token_object.refresh_token
    decoded_refresh_token = jwt.decode(refresh_token, options={"verify_signature": False})
    issuer_url = decoded_refresh_token.get('iss')
    config_loader = LazyConfigLoad()
    idp_config_vo =config_loader.get_vo_user_auth_config(vo)
    issuer_token_endpoint = get_discovery_metadata(issuer_url=issuer_url)["token_endpoint"]
    client_id = idp_config_vo["client_id"]
    client_secret = idp_config_vo["client_secret"]
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret
    }

    # Send the token refresh request
    response = requests.post(issuer_token_endpoint, headers=headers, data=data, timeout=10)
    if response.status_code != 200:
        raise CannotAuthorize(f"Failed to refresh token: {response.text}")

    oidc_tokens = response.json()

    # Handle the response
    if 'error' in oidc_tokens:
        raise CannotAuthorize(oidc_tokens['error'])
    # save new access and refresh tokens in the DB
    if 'refresh_token' in oidc_tokens and 'access_token' in oidc_tokens:
        token_type = "access_token"
        validate_token(token=oidc_tokens['access_token'],issuer_url=issuer_url, audience=EXPECTED_OIDC_AUDIENCE, token_type=token_type)
        # aborting refresh of the original token
        # (keeping it in place until it expires)
        __change_refresh_state(token_object.token, refresh=False, session=session)

        # get access token expiry timestamp
        jwt_row_dict['lifetime'] = datetime.utcnow() + timedelta(seconds=oidc_tokens['expires_in'])
        extra_dict['refresh'] = True
        extra_dict['refresh_token'] = oidc_tokens['refresh_token']
        try:
            values = decoded_refresh_token['exp']
            extra_dict['refresh_expired_at'] = datetime.utcfromtimestamp(float(values['exp']))
        except Exception:
            # 4 day expiry period by default
            extra_dict['refresh_expired_at'] = datetime.utcnow() + timedelta(hours=REFRESH_LIFETIME_H)
        new_token = __save_validated_token(oidc_tokens['access_token'], jwt_row_dict, extra_dict=extra_dict, session=session)
        METRICS.counter(name='IdP_authorization.access_token.saved').inc()
        METRICS.counter(name='IdP_authorization.refresh_token.saved').inc()
    else:
        raise CannotAuthorize(f"OIDC identity {token_object.identity} of the {token_object.account} account is did not succeed requesting a new access and refresh tokens.")  # NOQA: W503
    return new_token


def validate_jwt_and_save_token(
    token: str,
    account: Optional[str],
    vo: str = 'def',
    *,
    session: "Session"
) -> dict[str, Any]:
    """_summary_

    :raises CannotAuthenticate: _description_
    :return _type_: _description_
    """
    unverified_claims = jwt.get_unverified_claims(token)
    issuer_url = unverified_claims["iss"]
    config_loader = LazyConfigLoad()
    is_valid_issuer = config_loader.is_valid_issuer(issuer_url=issuer_url, vo=vo)
    if not is_valid_issuer:
        raise CannotAuthenticate(f"token with issuer {issuer_url} is not from valid issuer")
    token_type = "access_token"
    access_token_decoded = validate_token(token=token, issuer_url=issuer_url, audience=EXPECTED_OIDC_AUDIENCE, token_type=token_type)
    token_dict = {}
    token_dict["audience"] = access_token_decoded["aud"]
    token_dict['authz_scope'] = access_token_decoded['scope']
    token_dict["account"] = account
    __save_validated_token(token, token_dict, session=session)
    return token_dict


def oidc_identity_string(sub: str, iss: str) -> str:
    """
    Transform IdP sub claim and issuers url into users identity string.
    :param sub: users SUB claim from the Identity Provider
    :param iss: issuer (IdP) https url

    :returns: OIDC identity string "SUB=<usersid>, ISS=https://iam-test.ch/"
    """
    return f"SUB={sub}, ISS={iss}"


def token_dictionary(token: models.Token) -> dict[str, Any]:
    """_summary_

    :param models.Token token: token as Token model
    :return _type_: _description_
    """
    return {'token': token.token, 'expires_at': token.expired_at}
