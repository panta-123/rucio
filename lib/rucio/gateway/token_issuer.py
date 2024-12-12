from typing import TYPE_CHECKING, Any, Iterator, Optional, Union

from rucio.common import exception
from rucio.common.types import (
    RefreshTokenRequest,
    RefreshTokenResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from rucio.common.utils import gateway_update_return_dict
from rucio.core import token_issuer
from rucio.db.sqla.session import read_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

@read_session
def handle_token(
    data: Union[TokenExchangeRequest, RefreshTokenRequest],
    client_id: str, 
    client_secret: str, 
    *,
    session="Session"
) -> Union[TokenExchangeResponse, RefreshTokenResponse]:
    """ handle token endpoint"""
    return token_issuer.handle_token(data, client_id=client_id, client_secret=client_secret, session=session)

def jwks() -> dict:
    """
    jwks url
    """
    res = token_issuer.jwks()
    return res

def openid_config_resource():
    """
    openID discovery
    """
    return token_issuer.openid_config_resource()
