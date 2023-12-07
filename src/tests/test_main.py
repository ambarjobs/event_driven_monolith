# ==================================================================================================
#  Main module tests
# ==================================================================================================
from typing import Type

import bcrypt
import pytest
from fastapi import status
from fastapi.testclient import TestClient

import config
import schemas as sch
import utils
from tests.helpers import Db
from main import app

config.USER_CREDENTIALS_DB_NAME = f'{config.TEST_PREFIX}-{config.USER_CREDENTIALS_DB_NAME}'
config.USER_INFO_DB_NAME = f'{config.TEST_PREFIX}-{config.USER_INFO_DB_NAME}'

client = TestClient(app=app)


class TestMain:
    def test_signin__general_case(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        known_hash: str,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        info_db = TestDb(database_name=config.USER_INFO_DB_NAME)

        body = {
            "credentials": {
                "id": user_credentials.id,
                "password": user_credentials.password.get_secret_value()
            },
            "user_info": utils.clear_nulls(user_info.model_dump())
        }

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        try:
            credentials_db.create()
            info_db.create()
            credentials_db.add_permissions()
            info_db.add_permissions()

            response = client.post('/signin', json=body)

            assert response.status_code == status.HTTP_201_CREATED
            assert response.json() == {'status': 'signed_in'}

            credentials_response = credentials_db.get_document_by_id(
                document_id=user_credentials.id,
                fields=['_id', '_rev', 'hash'],
            )

            credentials_doc =  utils.deep_traversal(credentials_response, 'docs', 0)

            assert credentials_doc is not None
            assert credentials_doc.get('_id') == user_credentials.id
            assert credentials_doc.get('hash') == known_hash

            info_response = info_db.get_document_by_id(
                document_id=user_info.id,
                fields=['_id', '_rev', 'name', 'phone_number', 'address'],
            )

            info_doc =  utils.deep_traversal(info_response, 'docs', 0)

            assert info_doc is not None
            assert info_doc.get('_id') == user_info.id
            assert info_doc.get('name') == user_info.name
            assert info_doc.get('address') == user_info.address
            assert 'phone_number' not in info_doc

        finally:
            credentials_db.delete()
            info_db.delete()

    def test_signin__already_exists(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        info_db = TestDb(database_name=config.USER_INFO_DB_NAME)

        body = {
            "credentials": {
                "id": user_credentials.id,
                "password": user_credentials.password.get_secret_value()
            },
            "user_info": utils.clear_nulls(user_info.model_dump())
        }

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        try:
            credentials_db.create()
            info_db.create()
            credentials_db.add_permissions()
            info_db.add_permissions()

            client.post('/signin', json=body)

            # Try to sign in a pre existent user.
            response = client.post('/signin', json=body)

            credentials_response = credentials_db.get_document_by_id(
                document_id=user_credentials.id,
                fields=['_id', '_rev', 'hash'],
            )
            credentials_doc =  utils.deep_traversal(credentials_response, 'docs', 0)

            expected_result = {
                'status': 'already_signed_in',
                'version': credentials_doc['_rev']
            }

            assert response.status_code == status.HTTP_409_CONFLICT
            assert response.json() == expected_result
        finally:
            credentials_db.delete()
            info_db.delete()
