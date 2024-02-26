# ==================================================================================================
#  Tests helpers
# ==================================================================================================
from collections.abc import Sequence
from typing import Any

import httpx

import utils
from database import db, DbCredentials, Index


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
    """Database access helper class to be used by `test_db` fixture."""
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

    def create_document(self, document_id: str, body: dict | None = None) -> Any:
        """Create a document on the database."""
        body = body or dict()
        response = access_database(
            access_function=httpx.put,
            url_parts=[self.database_name, document_id],
            credentials=db.app_credentials,
            body=body,
        )
        return response

    def create_indexes(self, indexes: Sequence[Index]) -> None:
        """Create database indexes."""
        for index in indexes:
            body = {
                "index": {
                    "fields": index.fields
                },
                "ddoc": index.name,
                "type": "json"
            }
            access_database(
                access_function=httpx.post,
                url_parts=[self.database_name, '_index'],
                credentials=db.app_credentials,
                body=body,
            )

    def check_document(self, document_id: str) -> bool:
        """Check if document exists on database."""
        command_url = f'{db.url}/{self.database_name}/{document_id}'
        response = httpx.head(url=command_url, auth=db.app_credentials)
        return bool(response.headers.get('etag'))

    def get_document_by_id(self, document_id: str) -> Any:
        """Get a document from the database by `id`."""
        response = access_database(
            access_function=httpx.get,
            url_parts=[self.database_name, document_id],
            credentials=db.app_credentials,
        )
        return response

    def update_document(self, document_id: str, update_fields: dict) -> str:
        """Update document fields."""

        document_data = self.get_document_by_id(document_id=document_id)
        current_revision = utils.deep_traversal(document_data, '_rev')

        new_fields = {
            key: value for key, value in (document_data | update_fields).items()
            if key not in ['_id', '_rev']
        }

        new_revision = access_database(
            access_function=httpx.put,
            url_parts=[self.database_name, document_id],
            credentials=db.app_credentials,
            body=new_fields,
            headers={'if-match': current_revision}
        )
        return new_revision

    def delete(self) -> None:
        """Delete the database."""
        access_database(
            access_function=httpx.delete,
            url_parts=[self.database_name],
            credentials=db.admin_credentials,
        )
