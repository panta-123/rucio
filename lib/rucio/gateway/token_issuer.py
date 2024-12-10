from typing import TYPE_CHECKING, Any, Iterator, Optional, Union

from rucio.common import exception
from rucio.common.types import InternalAccount, TokenDict
from rucio.common.utils import gateway_update_return_dict
from rucio.core import token_issuer
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import transactional_session
from rucio.gateway import permission


def token(
    data: dict[str, str],
) -> 'Iterator[dict[str, Any]]':
    """
    :param data: 

    :returns: result of the query (authorization URL or a
              token if a user asks with the correct code) or None.
              Exception thrown in case of an unexpected crash.
    """
    return True

def jwks() -> dict:
    """
    """
    return token_issuer.jwks()

def openid_config_resource():
    """
    """
    return token_issuer.openid_config_resource()