# ==================================================================================================
#  Tests helpers
# ==================================================================================================
from typing import Any

import httpx

import utils
from database import db, DbCredentials


# --------------------------------------------------------------------------------------------------
#   Database
# --------------------------------------------------------------------------------------------------
def access_database(
    access_function,
    url_parts: list | None = None,
    headers: dict | None = None,
    body: dict | None = None,
    credentials: DbCredentials = db.app_credentials,
) -> Any:
    """Generic database access function."""
    url_parts = url_parts or []
    headers = headers or dict()
    url_complement = '/'.join(url_parts)
    url_complement = f'/{url_complement}' if url_complement else url_complement
    command_url = f'{db.url}{url_complement}'
    params = utils.clear_nulls(
        {'url': command_url, 'auth': credentials, 'headers': headers, 'json': body}
    )
    response = access_function(**params)
    return response.json()

class Db:
    """Database access helper class to be used by `TestDb` fixture factory."""
    def __init__(self, database_name: str):
        self.database_name = database_name

    def create(self) -> None:
        """Create the database."""
        access_database(
            access_function=httpx.put,
            url_parts=[self.database_name],
            credentials=db.admin_credentials,
        )

    def add_permissions(self) -> None:
        """Add user permissions on database"""
        BODY = {
            "members": {
                "roles": ["_admin"]
            },
            "admins": {
                "roles": ["_admin", "app"]
            }
        }
        access_database(
            access_function=httpx.put,
            url_parts=[self.database_name, '_security'],
            credentials=db.admin_credentials,
            body=BODY,
        )

    def create_document(self, document_id: str, body: dict[str, Any] | None = None) -> Any:
        """Create a document on the database."""
        body = body or dict()
        response = access_database(
            access_function=httpx.put,
            url_parts=[self.database_name, document_id],
            credentials=db.app_credentials,
            body=body,
        )
        return response

    def check_document(self, document_id: str) -> bool:
        """Check if document exists on database."""
        command_url = f'{self.database_name}/{document_id}'
        response = httpx.head(url=command_url, auth=db.app_credentials)
        return bool(response.headers.get('etag'))

    def get_document_by_id(self, document_id: str, fields: list[str] | None = None) -> Any:
        """Get a document from the database by it's `id`."""
        match fields:
            case None | []:
                fields = ['_id']
            case ['_id', *_]:
                ...
            case _:
                fields.append('_id')

        body = {
            "selector": {
                "_id": {"$eq": document_id}
            },
            "fields": fields
        }

        response = access_database(
            access_function=httpx.post,
            url_parts=[self.database_name, '_find'],
            credentials=db.app_credentials,
            body=body,
        )
        return response

    def delete(self) -> None:
        """Delete the database."""
        access_database(
            access_function=httpx.delete,
            url_parts=[self.database_name],
            credentials=db.admin_credentials,
        )
