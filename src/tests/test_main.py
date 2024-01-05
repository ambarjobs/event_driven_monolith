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

        response = client.post(url='/login', data=login_body)
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
        # Logged in on this test
        assert (
            this_moment - datetime.fromisoformat(last_login_iso) <
            timedelta(seconds=config.TEST_EXECUTION_LIMIT)
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
            # Logged in before this test.
            'last_login': datetime.isoformat(
                this_moment -
                timedelta(seconds=config.TEST_EXECUTION_LIMIT)
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
        # Logged in on this test.
        assert (
            this_moment - datetime.fromisoformat(last_login_iso) <
            timedelta(seconds=config.TEST_EXECUTION_LIMIT)
        )

    # ==============================================================================================
    #   /confirm-email-api endpoint test
    # ==============================================================================================
    def test_confirm_email_api__general_case(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        email_confimation_db.create_document(
            document_id=token_confirmation_info.user_id,
            body={'email_confirmation_token': test_token}
        )

        email_confirmation_data = email_confimation_db.get_document_by_id(
            document_id=token_confirmation_info.user_id
        )
        assert utils.deep_traversal(email_confirmation_data, 'confirmed_datetime') is None

        token_data = sch.EmailConfirmationToken(token=test_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_200_OK

        content = sch.ServiceStatus.model_validate_json(response.content)
        assert content.status == 'confirmed'
        assert content.error is False
        assert content.details.description == 'Email confirmed.'
        assert content.details.data['email'] == token_confirmation_info.user_id
        assert content.details.data['name'] == token_confirmation_info.user_name

    def test_confirm_email_api__invalid_token(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())
        invalid_token = test_token
        while invalid_token == test_token:
            invalid_token = test_token[:-1]

        token_data = sch.EmailConfirmationToken(token=invalid_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        content = sch.ServiceStatus.model_validate_json(response.content)
        assert content.status == 'invalid_token'
        assert content.error is True
        assert content.details.description == 'Invalid token.'
        assert content.details.data['token'] == invalid_token
        assert content.details.data['errors'] in (
            'Not enough segments',
            'Signature verification failed.'
        )

    def test_confirm_email_api__invalid_token__invalid_payload(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        token_confirmation_info.user_id = 'invalid id(email)'
        invalid_token = utils.create_token(payload=token_confirmation_info.model_dump())

        token_data = sch.EmailConfirmationToken(token=invalid_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        content = sch.ServiceStatus.model_validate_json(response.content)
        assert content.status == 'invalid_token'
        assert content.error is True
        assert content.details.description == 'Invalid token.'
        assert content.details.data['token'] == invalid_token
        assert content.details.data['errors'][0]['type'] == 'value_error'
        assert content.details.data['errors'][0]['loc'] == ['user_id']

    def test_confirm_email_api__inexistent_token(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        email_confimation_db.create_document(
            document_id=token_confirmation_info.user_id,
        )

        token_data = sch.EmailConfirmationToken(token=test_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_404_NOT_FOUND

        content = sch.ServiceStatus.model_validate_json(response.content)
        assert content.status == 'inexistent_token'
        assert content.error is True
        assert content.details.description == 'Inexistent token for the user id.'
        assert content.details.data['token'] == test_token
        assert content.details.data['email'] == token_confirmation_info.user_id

    def test_confirm_email_api__previously_confirmed(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        previous_confirmation_datetime = datetime.now(tz=UTC) - timedelta(hours=-1)
        previous_confirmation_datetime_iso = previous_confirmation_datetime.isoformat()
        email_confimation_db.create_document(
            document_id=token_confirmation_info.user_id,
            body={
                'email_confirmation_token': test_token,
                'confirmed_datetime': previous_confirmation_datetime_iso
            }
        )

        token_data = sch.EmailConfirmationToken(token=test_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_409_CONFLICT

        content = sch.ServiceStatus.model_validate_json(response.content)
        assert content.status == 'previously_confirmed'
        assert content.error is True
        assert content.details.description == 'The email was already confirmed.'
        assert content.details.data['confirmation_datetime'] == previous_confirmation_datetime_iso
        assert content.details.data['email'] == token_confirmation_info.user_id

    # ==============================================================================================
    #   /confirm-email endpoint test
    # ==============================================================================================
    def test_confirm_email__general_case(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        email_confimation_db.create_document(
            document_id=token_confirmation_info.user_id,
            body={'email_confirmation_token': test_token}
        )

        email_confirmation_data = email_confimation_db.get_document_by_id(
            document_id=token_confirmation_info.user_id
        )
        assert utils.deep_traversal(email_confirmation_data, 'confirmed_datetime') is None

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.get(url='/confirm-email', params={'token': test_token})
        assert response.status_code == status.HTTP_200_OK

        content = response.content.decode(config.APP_ENCODING_FORMAT)
        message_parts = (
            'Thank you for confirm your email.',
            'Now you can log in on:',
            'to access our platform.'
        )
        for message_part in message_parts:
            assert message_part in content

    def test_confirm_email__invalid_token(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())
        invalid_token = test_token
        while invalid_token == test_token:
            invalid_token = test_token[:-1]

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.get(url='/confirm-email', params={'token': invalid_token})
        assert response.status_code == status.HTTP_200_OK

        content = response.content.decode(config.APP_ENCODING_FORMAT)
        message_parts = (
            'Unfortunately an error occurred:',
            'The confirmation link is corrupted or expired.'
        )
        for message_part in message_parts:
            assert message_part in content

    def test_confirm_email__inexistent_token(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        email_confimation_db.create_document(
            document_id=token_confirmation_info.user_id,
        )

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.get(url='/confirm-email', params={'token': test_token})
        assert response.status_code == status.HTTP_200_OK

        content = response.content.decode(config.APP_ENCODING_FORMAT)
        message_parts = (
            'Unfortunately an error occurred:',
            'There is no sign in corresponding to the confirmation link.'
        )
        for message_part in message_parts:
            assert message_part in content

    def test_confirm_email__previously_confirmed(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        previous_confirmation_datetime = datetime.now(tz=UTC) - timedelta(hours=-1)
        previous_confirmation_datetime_iso = previous_confirmation_datetime.isoformat()
        email_confimation_db.create_document(
            document_id=token_confirmation_info.user_id,
            body={
                'email_confirmation_token': test_token,
                'confirmed_datetime': previous_confirmation_datetime_iso
            }
        )

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.get(url='/confirm-email', params={'token': test_token})
        assert response.status_code == status.HTTP_200_OK

        content = response.content.decode(config.APP_ENCODING_FORMAT)
        message_parts = (
            'Your email address was confirmed previously.',
            'You can just log in on:',
            'to access our platform.',
        )
        for message_part in message_parts:
            assert message_part in content
