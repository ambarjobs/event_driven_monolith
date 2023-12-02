# ==================================================================================================
#   CouchDB database
# ==================================================================================================

import os
from typing import NamedTuple

import httpx

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
        self.url = config.db_url
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
        if response.status_code != 412:
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

    def init_tables(self, database_names: list[str]) -> None:
        """Create database tables if not created."""
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

    def check_document_available(self, database_name: str, docuement_id: str) -> str:
        """Checks if document exists on database."""
        command_url = f'{self.url}/{database_name}/{docuement_id}'
        response = httpx.head(url=command_url, auth=self.app_credentials).raise_for_status()
        version = response.headers.get('etag')
        if version:
            version = version.strip('"')
        return version

    def sign_in_user(self, id: str, hash_: str, user_info: sch.UserInfo) -> None:
        """Sign in the user."""
        command_url = f'{self.url}/user-credentials/{id}'
        body = {'hash': hash_}
        httpx.put(url=command_url, json=body, auth=self.app_credentials).raise_for_status()
        command_url = f'{self.url}/user-info/{id}'
        body = utils.clear_nulls(user_info.model_dump(exclude={'id'}))
        httpx.put(url=command_url, json=body, auth=self.app_credentials).raise_for_status()

db = CouchDb()
