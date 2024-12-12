from typing import TYPE_CHECKING, Union

import rucio.gateway.permission
from rucio.core import oidc_client
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_oidc_client(allowed_scopes: list, grant_types: list, *, session: "Session"):
    """ add oidc client"""
    oidc_client.create_client(allowed_scopes=allowed_scopes, grant_types= grant_types, session=session)

@read_session
def list_oidc_client(*, session: "Session"):
    """ list oidc client"""
    oidc_client.list_all_oidc_clients(session=session)

@transactional_session
def delete_oidc_client(client_id: str, *, session: "Session"):
    """ delete oidc client"""
    oidc_client.delete_client(client_id=client_id, session=session)

@transactional_session
def update_oidc_client(client_id: str, allowed_scopes: list, grant_types: list, *, session: "Session"):
    """ update oidc client"""
    oidc_client.update_client(client_id=client_id, allowed_scopes=allowed_scopes, grant_types= grant_types, session=session)
