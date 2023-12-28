# ==================================================================================================
#  Main module tests
# ==================================================================================================
from datetime import datetime, timedelta, UTC
from unittest import mock

import bcrypt
import pytest
from fastapi import status
from fastapi.testclient import TestClient

import config
import schemas as sch
import utils
from main import app
from tests.helpers import Db


TEST_EXECUTION_LIMIT = 15

client = TestClient(app=app)


class TestMain:
    # ==============================================================================================
    #   /signin endpoint test
    # ==============================================================================================
    def test_signin__general_case(
        self,
        test_db: Db,
        another_test_db: Db,
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        known_hash: str,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        info_db = another_test_db
        info_db.database_name = config.USER_INFO_DB_NAME

        body = {
            "credentials": {
                "id": user_credentials.id,
                "password": user_credentials.password.get_secret_value()
            },
            "user_info": utils.clear_nulls(user_info.model_dump())
        }

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        # Blocks `user-signed-in` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post('/signin', json=body)

            assert response.status_code == status.HTTP_201_CREATED
            assert response.json() == {
                'status': 'successful_sign_in',
                'error': False,
                'details': {
                    'description': 'User signed in successfully.'
                }
            }

        credentials_doc = credentials_db.get_document_by_id(
            document_id=user_credentials.id,
        )

        assert credentials_doc is not None
        assert credentials_doc.get('_id') == user_credentials.id
        assert credentials_doc.get('hash') == known_hash

        info_doc = info_db.get_document_by_id(
            document_id=user_info.id,
        )

        assert info_doc is not None
        assert info_doc.get('_id') == user_info.id
        assert info_doc.get('name') == user_info.name
        assert info_doc.get('address') == user_info.address
        assert 'phone_number' not in info_doc

    def test_signin__already_exists(
        self,
        test_db: Db,
        another_test_db: Db,
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        info_db = another_test_db
        info_db.database_name = config.USER_INFO_DB_NAME
        body = {
            "credentials": {
                "id": user_credentials.id,
                "password": user_credentials.password.get_secret_value()
            },
            "user_info": utils.clear_nulls(user_info.model_dump())
        }

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        # Blocks `user-signed-in` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            client.post('/signin', json=body)

            # Try to sign in a pre existent user.
            response = client.post('/signin', json=body)

            credentials_doc = credentials_db.get_document_by_id(
                document_id=user_credentials.id,
            )

            expected_result = {
                'status': 'user_already_signed_in',
                'error': True,
                'details': {
                    'description': 'User already signed in.',
                    'data': {
                        'version': credentials_doc['_rev']
                    }
                }
            }

            assert response.status_code == status.HTTP_409_CONFLICT
            assert response.json() == expected_result

    # ==============================================================================================
    #   /login endpoint test
    # ==============================================================================================
    def test_login__general_case(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_hash = utils.calc_hash(password=user_credentials.password)
        sign_in_body = {
            'hash': sign_in_hash,
            'validated': True
        }
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_200_OK

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'successfully_logged_in'
        assert login_status.error is False
        assert login_status.details.description == 'User has successfully logged in.'
        assert 'token' in login_status.details.data
        assert len(login_status.details.data['token']) > 0

        db_user_credentials = credentials_db.get_document_by_id(
            document_id=user_credentials.id,
        )

        assert db_user_credentials.get('_id') == user_credentials.id

        last_login_iso = db_user_credentials.get('last_login')
        assert last_login_iso is not None
        assert (
            this_moment - datetime.fromisoformat(last_login_iso) <
            timedelta(seconds=TEST_EXECUTION_LIMIT)
        )

    def test_login__inexistent_user(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_hash = utils.calc_hash(password=user_credentials.password)
        sign_in_body = {
            'hash': sign_in_hash,
            'validated': True
        }
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': 'inexistent@user.id',
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'incorrect_login_credentials'
        assert login_status.error is True
        assert login_status.details.description == (
            'Invalid user or password. Check if user has signed in.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data is None

    def test_login__incorrect_password(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_hash = utils.calc_hash(password=user_credentials.password)
        sign_in_body = {
            'hash': sign_in_hash,
            'validated': True
        }
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': user_credentials.id,
            'password': 'incorrect_password'
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'incorrect_login_credentials'
        assert login_status.error is True
        assert login_status.details.description == (
            'Invalid user or password. Check if user has signed in.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data is None

    def test_login__user_has_no_hash(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_body = {}
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'incorrect_login_credentials'
        assert login_status.error is True
        assert login_status.details.description == (
            'Invalid user or password. Check if user has signed in.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data is None

    def test_login__no_email_validation(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_hash = utils.calc_hash(password=user_credentials.password)
        sign_in_body = {
            'hash': sign_in_hash,
        }
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'email_not_validated'
        assert login_status.error is True
        assert login_status.details.description == (
            'User email is not validated.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data is None

    def test_login__user_already_logged_in__last_login_not_expired(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_hash = utils.calc_hash(password=user_credentials.password)
        sign_in_body = {
            'hash': sign_in_hash,
            'validated': True,
            # Logged in more than TEST_EXECUTION_LIMIT seconds ago.
            'last_login': datetime.isoformat(
                this_moment -
                timedelta(seconds=TEST_EXECUTION_LIMIT)
            )
        }
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'user_already_signed_in'
        assert login_status.error is True
        assert login_status.details.description == (
            'User was already logged in.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data is None

    def test_login__user_already_logged_in__last_login_expired(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_in_hash = utils.calc_hash(password=user_credentials.password)
        sign_in_body = {
            'hash': sign_in_hash,
            'validated': True,
            # `last_login` expired one hour ago.
            'last_login': datetime.isoformat(
                this_moment -
                timedelta(hours=config.TOKEN_DEFAULT_EXPIRATION_HOURS + 1.0)
            )
        }
        # Minimal sign in.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_in_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_200_OK

        login_status = sch.ServiceStatus(**response.json())

        assert login_status.status == 'successfully_logged_in'
        assert login_status.error is False
        assert login_status.details.description == 'User has successfully logged in.'
        assert 'token' in login_status.details.data
        assert len(login_status.details.data['token']) > 0

        db_user_credentials = credentials_db.get_document_by_id(
            document_id=user_credentials.id,
        )

        assert db_user_credentials.get('_id') == user_credentials.id

        this_moment = datetime.now(tz=UTC)
        last_login_iso = db_user_credentials.get('last_login')
        assert last_login_iso is not None
        assert (
            this_moment - datetime.fromisoformat(last_login_iso) <
            timedelta(seconds=TEST_EXECUTION_LIMIT)
        )
