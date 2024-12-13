""" oidc client for token exchange and refresh"""
import hashlib
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, delete, select
from sqlalchemy.exc import (
    IntegrityError,
)

from rucio.common import exception
from rucio.db.sqla import constants, models
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from sqlalchemy.orm import Session



def generate_client_credentials():
    """ Generate client credentials"""
    client_id = str(uuid.uuid4())
    client_secret = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()  # Simple secret generation
    return client_id, client_secret

@transactional_session
def create_client(allowed_scopes: list, grant_types: list, *, session: "Session") -> None:
    """
    Creates a new OIDC client with a generated client_id and client_secret.
    """
    client_id, client_secret = generate_client_credentials()
    try:
        allowed_scopes_enum = [constants.AllowedScope(scope) if isinstance(scope, str) else scope for scope in allowed_scopes]
    except ValueError as e:
        raise ValueError("scope in in allowed scope") from e
    try:
        grant_types_enum = [constants.GrantType(grant) if isinstance(grant, str) else grant for grant in grant_types]
    except ValueError as e:
        raise ValueError("scope in in allowed scope") from e

    new_client = models.OIDCClient(
        client_id=client_id,
        client_secret=client_secret
    )

    # Set the allowed_scopes_list and grant_types_list properties to invoke the setters
    new_client.allowed_scopes_list = allowed_scopes_enum
    new_client.grant_types_list = grant_types_enum
    try:
        new_client.save(session=session)
    except IntegrityError:
        raise exception.Duplicate('Client ID \'%s\' already exists!' % client_id)

@read_session
def validate_client(client_id: str, client_secret: str, required_scopes: list, required_grant_types: list, *, session: "Session") -> bool:
    """
    Checks if the client exists and validates that the client_secret is correct.
    Also verifies if the client's allowed_scopes and grant_types match or are a subset of the required ones.
    """

    query = select(models.OIDCClient).where(models.OIDCClient.client_id == client_id)
    client = session.execute(query).scalars().first()

    if client and client.client_secret == client_secret:
        # Convert the required_scopes and required_grant_types to their enum values
        scope_base_list = []
        for scope in required_scopes:
            scope_base = scope.split(":")[0]
            scope_base_list.append(scope_base)
        required_scopes_enum = [constants.AllowedScope(scope) for scope in scope_base_list]
        required_grant_types_enum = [constants.GrantType(grant) for grant in required_grant_types]

        # Check if required scopes and grant types are valid
        valid_scopes = set(required_scopes_enum).issubset(set(client.allowed_scopes_list))
        valid_grant_types = set(required_grant_types_enum).issubset(set(client.grant_types_list))

        if not valid_scopes:
            raise exception.InvalidOIDCRequestError(f"Client does not have the required scopes: {required_scopes}")
        if not valid_grant_types:
            raise exception.UnsupportedGrantTypeError(f"Client does not support the required grant types: {required_grant_types}")

        return True

    raise exception.UnauthorizedOIDCClientError(f"Client is not authorized")

@read_session
def list_all_oidc_clients(*, session: "Session") -> list[dict[str, Any]]:
    """
    Lists all the clients from the OIDCClient table.
    """
    query = select(models.OIDCClient)
    clients = session.execute(query).scalars().all()

    clients_list = []
    for client in clients:
        client_dict = {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "allowed_scopes": [scope.name for scope in client.allowed_scopes_list],  # Convert enum values to names
            "grant_types": [grant.name for grant in client.grant_types_list],  # Convert enum values to names
        }
        clients_list.append(client_dict)

    # Return the list of dictionaries
    return clients_list

@transactional_session
def delete_client(client_id: str, *, session: "Session") -> bool:
    """
    Deletes an OIDC client by its client_id.
    """
    query = delete(
        models.OIDCClient
    ).where(
            and_(models.OIDCClient.client_id == client_id)
    )
    result = session.execute(query)
    if result.rowcount > 0:
        return True
    return False

@transactional_session
def update_client(client_id: str, allowed_scopes: list, grant_types: list, *, session: "Session") -> bool:
    """
    Updates the allowed_scopes and grant_types for an existing client.
    """
    query = select(
        models.OIDCClient
    ).where(
        models.OIDCClient.client_id == client_id
    )
    result = session.execute(query).scalars().first()

    if result:
        # Update the fields
        result.allowed_scopes = allowed_scopes
        result.grant_types = grant_types
        return True
    return False
