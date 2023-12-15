# ==================================================================================================
#   CouchDB database
# ==================================================================================================

import os
from typing import Any, NamedTuple

import httpx
from fastapi import status

import config
import schemas as sch
import utils
from exceptions import InvalidCouchDBCredentialError


class DbCredentials(NamedTuple):
    user: str
    password: str


class Index(NamedTuple):
    """Databse index structure."""
    name: str
    fields: list[str]


class DatabaseInfo(NamedTuple):
    """Database information structure."""
    name: str
    indexes: list[Index]


class CouchDb:
    """Class representing CouchDb."""

    def __init__(self) -> None:
        self.url = config.DB_URL
        self.admin_credentials = self._get_credentials(
            user_env_var='COUCHDB_USER',
            pwd_env_var='COUCHDB_PASSWORD'
        )
        self.app_credentials = self._get_credentials(
            user_env_var='COUCHDB_APP_USER',
            pwd_env_var='COUCHDB_APP_PASSWORD'
        )

    def _get_credentials(self, user_env_var: str, pwd_env_var: str) -> DbCredentials:
        """Get CouchDB admin credentials."""
        user = os.environ.get(user_env_var)
        password = os.environ.get(pwd_env_var)
        if (not user) or (not password):
            raise InvalidCouchDBCredentialError
        return DbCredentials(user=user, password=password)

    def create_database(self, database_name: str) -> None:
        """Create a new database."""
        command_url = f'{self.url}/{database_name}'
        response = httpx.put(url=command_url, auth=self.admin_credentials)
        # If a database already exists it'll generate a `status_code` of 412, but that isn't
        # significative here because we'll ignore existing databases.
        if response.status_code != status.HTTP_412_PRECONDITION_FAILED:
            response.raise_for_status()

    def set_app_permissions_on_database(self, database_name: str) -> None:
        """Set administration permissions to the `app` role on a database."""
        BODY = {
            "members": {
                "roles": ["_admin"]
            },
            "admins": {
                "roles": ["_admin", "app"]
            }
        }
        command_url = f'{self.url}/{database_name}/_security'
        httpx.put(
            url=command_url,
            auth=self.admin_credentials,
            json=BODY,
        ).raise_for_status()

    def init_databases(self, database_names: list[str]) -> None:
        """Create databases if not created."""
        for database_name in database_names:
            self.create_database(database_name=database_name)
            self.set_app_permissions_on_database(database_name=database_name)

    def create_database_indexes(self, database_info: DatabaseInfo) -> None:
        """Create indexes for a database."""
        database_name = database_info.name
        for index in database_info.indexes:
            body = {
                "index": {
                    "fields": index.fields
                },
                "ddoc": index.name,
                "type": "json"
            }
            httpx.post(
                url=f'{self.url}/{database_name}/_index',
                auth=self.app_credentials,
                json=body,
            ).raise_for_status()

    def check_document_available(self, database_name: str, document_id: str) -> str | None:
        """Checks if document exists on database."""
        command_url = f'{self.url}/{database_name}/{document_id}'
        try:
            response = httpx.head(url=command_url, auth=self.app_credentials).raise_for_status()
            version = response.headers.get('etag')
            if version:
                version = version.strip('"')
            return version
        except httpx.HTTPStatusError as err:
            if err.response.status_code == status.HTTP_404_NOT_FOUND:
                # Oh, mypy! Why can't you see that a `return` without argument returns `None`?
                return None
            raise

    def get_document_by_id(
        self,
        database_name: str,
        document_id: str,
    ) -> dict[str, Any]:
        """Get information about a document by `id`."""
        response = httpx.get(
            url=f'{self.url}/{database_name}/{document_id}',
            auth=self.app_credentials,
        ).raise_for_status()

        return response.json()

    def get_document_fields_by_id(
        self,
        database_name: str,
        document_id: str,
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Get information about a document by `id` choosing it's `fields`."""
        fields = fields or []
        body = {
            "selector": {
                "_id": {
                    "$eq": document_id
                }
            },
            "fields": fields,
        }

        response = httpx.post(
            url=f'{self.url}/{database_name}/_find',
            auth=self.app_credentials,
            json=body,
        ).raise_for_status()

        document_info = utils.deep_traversal(response.json(), 'docs', 0)
        return document_info or {}

    def update_document_fields(self, original_fields: dict, updated_fields: dict) -> dict:
        """Update document fields with new values, excluding special fields."""
        SPECIAL_FIELDS = ['_id', '_rev']
        return {
            key: value for key, value in (original_fields | updated_fields).items()
            if key not in SPECIAL_FIELDS
        }

    def update_document(
        self,
        database_name: str,
        document_id: str,
        fields_to_change: dict
    ) -> str:
        """Update the fields of an existing document."""
        document_fields = self.get_document_by_id(
            database_name=database_name,
            document_id=document_id
        )
        revision = utils.deep_traversal(document_fields, '_rev')
        updated_fields = self.update_document_fields(
            original_fields=document_fields,
            updated_fields=fields_to_change
        )
        response = httpx.put(
            url=f'{self.url}/{database_name}/{document_id}',
            auth=self.app_credentials,
            json=updated_fields,
            headers={'if-match': revision}
        ).raise_for_status()
        return utils.deep_traversal(response.json(), 'rev')

    def sign_in_user(
        self,
        id: str,
        hash_: str,
        user_info: sch.UserInfo,
    ) -> None:
        """Sign in the user."""
        command_url = f'{self.url}/{config.USER_CREDENTIALS_DB_NAME}/{id}'
        body = {'hash': hash_}
        httpx.put(url=command_url, json=body, auth=self.app_credentials).raise_for_status()
        command_url = f'{self.url}/{config.USER_INFO_DB_NAME}/{id}'
        body = utils.clear_nulls(user_info.model_dump(exclude={'id'}))
        httpx.put(url=command_url, json=body, auth=self.app_credentials).raise_for_status()

db = CouchDb()
