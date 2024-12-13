from typing import TYPE_CHECKING, Any, Union

import rucio.common.exception
import rucio.gateway.permission
from rucio.core import oidc_client
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_oidc_client(allowed_scopes: list, grant_types: list, issuer: str, vo: str = 'def', *, session: "Session"):
    """ add oidc client"""
    kwargs = {}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_scope', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits. %s' % (issuer, auth_result.message))
    oidc_client.create_client(allowed_scopes=allowed_scopes, grant_types= grant_types, session=session)

@read_session
def list_oidc_client(issuer: str, vo: str = 'def', *, session: "Session"):
    """ add oidc client"""
    kwargs = {}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_scope', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits. %s' % (issuer, auth_result.message))
    oidc_client.list_all_oidc_clients(session=session)

@transactional_session
def delete_oidc_client(client_id: str, issuer: str, vo: str = 'def', *, session: "Session"):
    """ add oidc client"""
    kwargs = {}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_scope', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits. %s' % (issuer, auth_result.message))
    oidc_client.delete_client(client_id=client_id, session=session)

@transactional_session
def update_oidc_client(client_id: str, allowed_scopes: list, grant_types: list, issuer: str, vo: str = 'def', *, session: "Session"):
    """ add oidc client"""
    kwargs = {}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_scope', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits. %s' % (issuer, auth_result.message))
    oidc_client.update_client(client_id=client_id, allowed_scopes=allowed_scopes, grant_types= grant_types, session=session)
