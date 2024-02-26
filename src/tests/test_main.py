# ==================================================================================================
#  Main module tests
# ==================================================================================================
import asyncio
import io
import json
from copy import deepcopy
from datetime import datetime, timedelta, UTC
from unittest import mock

import bcrypt
import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sse_starlette.sse import ServerSentEvent

import config
import output_status as ost
import services as srv
import schemas as sch
import utils
from database import DbCredentials
from main import app
from tests.helpers import Db


client = TestClient(app=app)


# ==================================================================================================
#   Authentication functionality
# ==================================================================================================
class TestAuthenticationApi:
    # ----------------------------------------------------------------------------------------------
    #   `/signup` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_signup__general_case(
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

        # Blocks `user-signed-up` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post('/signup', json=body)

            assert response.status_code == status.HTTP_201_CREATED
            assert response.json() == {
                'status': 'successful_sign_up',
                'error': False,
                'details': {
                    'description': 'User signed up successfully.'
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

    def test_signup__already_exists(
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

        # Blocks `user-signed-up` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            client.post('/signup', json=body)

            # Try to sign up a pre existent user.
            response = client.post('/signup', json=body)

            credentials_doc = credentials_db.get_document_by_id(
                document_id=user_credentials.id,
            )

            expected_result = {
                'status': 'user_already_signed_up',
                'error': True,
                'details': {
                    'description': 'User already signed up.',
                    'data': {
                        'version': credentials_doc['_rev']
                    }
                }
            }

            assert response.status_code == status.HTTP_409_CONFLICT
            assert response.json() == expected_result

    # ----------------------------------------------------------------------------------------------
    #   `/login` endpoint test
    # ----------------------------------------------------------------------------------------------
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

        sign_up_hash = utils.calc_hash(password=user_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post(url='/login', data=login_body)
        assert response.status_code == status.HTTP_200_OK

        login_status = sch.OutputStatus(**response.json())

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

        sign_up_hash = utils.calc_hash(password=user_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': 'inexistent@user.id',
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.OutputStatus(**response.json())

        assert login_status.status == 'incorrect_login_credentials'
        assert login_status.error is True
        assert login_status.details.description == (
            'Invalid user or password. Check if user has signed up.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data == {}

    def test_login__incorrect_password(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_up_hash = utils.calc_hash(password=user_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': user_credentials.id,
            'password': 'incorrect_password'
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.OutputStatus(**response.json())

        assert login_status.status == 'incorrect_login_credentials'
        assert login_status.error is True
        assert login_status.details.description == (
            'Invalid user or password. Check if user has signed up.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data == {}

    def test_login__user_has_no_hash(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_up_body = {}
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.OutputStatus(**response.json())

        assert login_status.status == 'incorrect_login_credentials'
        assert login_status.error is True
        assert login_status.details.description == (
            'Invalid user or password. Check if user has signed up.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data == {}

    def test_login__no_email_validation(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        sign_up_hash = utils.calc_hash(password=user_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        login_status = sch.OutputStatus(**response.json())

        assert login_status.status == 'email_not_validated'
        assert login_status.error is True
        assert login_status.details.description == (
            'User email is not validated.'
        )
        # No token sent (`token` would come inside `data`).
        assert login_status.details.data == {}

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

        sign_up_hash = utils.calc_hash(password=user_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True,
            # Logged in before this test.
            'last_login': datetime.isoformat(
                this_moment -
                timedelta(seconds=config.TEST_EXECUTION_LIMIT)
            )
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_200_OK

        login_status = sch.OutputStatus(**response.json())

        assert login_status.status == 'user_already_logged_in'
        assert login_status.error is False
        assert login_status.details.description == (
            'User was already logged in and last token is still valid.'
        )

        assert 'new_token' in login_status.details.data
        assert len(login_status.details.data['new_token']) > 0

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

        sign_up_hash = utils.calc_hash(password=user_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True,
            # `last_login` expired one hour ago.
            'last_login': datetime.isoformat(
                this_moment -
                timedelta(hours=config.TOKEN_DEFAULT_EXPIRATION_HOURS + 1.0)
            )
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=user_credentials.id, body=sign_up_body)

        login_body = {
            'username': user_credentials.id,
            'password': user_credentials.password.get_secret_value()
        }

        response = client.post('/login', data=login_body)
        assert response.status_code == status.HTTP_200_OK

        login_status = sch.OutputStatus(**response.json())

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

# ==================================================================================================
#   Email confirmation functionality
# ==================================================================================================
class TestEmailConfirmationApi:
    # ----------------------------------------------------------------------------------------------
    #   `/confirm-email-api` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_confirm_email_api__general_case(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        email_confirmation_db.create_document(
            document_id=token_confirmation_info.user_id,
            body={'email_confirmation_token': test_token}
        )

        email_confirmation_data = email_confirmation_db.get_document_by_id(
            document_id=token_confirmation_info.user_id
        )
        assert utils.deep_traversal(email_confirmation_data, 'confirmed_datetime') is None

        token_data = sch.EmailConfirmationToken(token=test_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_200_OK

        content = sch.OutputStatus.model_validate_json(response.content)
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

        content = sch.OutputStatus.model_validate_json(response.content)
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

        content = sch.OutputStatus.model_validate_json(response.content)
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

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        email_confirmation_db.create_document(
            document_id=token_confirmation_info.user_id,
        )

        token_data = sch.EmailConfirmationToken(token=test_token).model_dump()
        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.post(url='/confirm-email-api', json=token_data)
        assert response.status_code == status.HTTP_404_NOT_FOUND

        content = sch.OutputStatus.model_validate_json(response.content)
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

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        previous_confirmation_datetime = datetime.now(tz=UTC) - timedelta(hours=-1)
        previous_confirmation_datetime_iso = previous_confirmation_datetime.isoformat()
        email_confirmation_db.create_document(
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

        content = sch.OutputStatus.model_validate_json(response.content)
        assert content.status == 'previously_confirmed'
        assert content.error is True
        assert content.details.description == 'The email was already confirmed.'
        assert content.details.data['confirmation_datetime'] == previous_confirmation_datetime_iso
        assert content.details.data['email'] == token_confirmation_info.user_id

    # ----------------------------------------------------------------------------------------------
    #   `/confirm-email` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_confirm_email__general_case(
        self,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        email_confirmation_db.create_document(
            document_id=token_confirmation_info.user_id,
            body={'email_confirmation_token': test_token}
        )

        email_confirmation_data = email_confirmation_db.get_document_by_id(
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

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        email_confirmation_db.create_document(
            document_id=token_confirmation_info.user_id,
        )

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            response = client.get(url='/confirm-email', params={'token': test_token})
        assert response.status_code == status.HTTP_200_OK

        content = response.content.decode(config.APP_ENCODING_FORMAT)
        message_parts = (
            'Unfortunately an error occurred:',
            'There is no sign up corresponding to the confirmation link.'
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

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        previous_confirmation_datetime = datetime.now(tz=UTC) - timedelta(hours=-1)
        previous_confirmation_datetime_iso = previous_confirmation_datetime.isoformat()
        email_confirmation_db.create_document(
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

# ==================================================================================================
#   Recipes functionality
# ==================================================================================================
class TestRecipesApi:
    # ----------------------------------------------------------------------------------------------
    #   `/load-recipes` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_load_recipes__general_case(
        self,
        test_db: Db,
        another_test_db: Db,
        admin_credentials: sch.UserCredentials,
        recipe_csv_file: io.BytesIO,
        another_recipe: sch.Recipe,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        recipes_db = another_test_db
        recipes_db.database_name = config.RECIPES_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        recipes_db.create()
        recipes_db.add_permissions()

        sign_up_hash = utils.calc_hash(password=admin_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=admin_credentials.id, body=sign_up_body)

        payload = {'sub': admin_credentials.id}
        token = utils.create_token(payload=payload)

        with mock.patch(target='services.store_recipe') as mock_store_recipe:
            response = client.post(
                url='/load-recipes',
                files={'recipes_csv': recipe_csv_file},
                headers={'Authorization': f'Bearer {token}'}
            )
            mock_store_recipe.assert_called_with(another_recipe)
        assert response.status_code == status.HTTP_201_CREATED

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'api_recipes_loaded'
        assert utils.deep_traversal(response_data, 'error') is False
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Recipes loaded successfully.'

    def test_load_recipes__invalid_token(
        self,
        admin_credentials: sch.UserCredentials,
        recipe_csv_file: io.BytesIO,
    ) -> None:
        payload = {'sub': admin_credentials.id}
        token = utils.create_token(payload=payload)
        invalid_token = token[:-1]

        response = client.post(
            url='/load-recipes',
            files={'recipes_csv': recipe_csv_file},
            headers={'Authorization': f'Bearer {invalid_token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'invalid_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Invalid token: Signature verification failed.'

    def test_load_recipes__expired_token(
        self,
        admin_credentials: sch.UserCredentials,
        recipe_csv_file: io.BytesIO,
    ) -> None:
        payload = {'sub': admin_credentials.id}
        token = utils.create_token(payload=payload, expiration_hours=-1.0)

        response = client.post(
            url='/load-recipes',
            files={'recipes_csv': recipe_csv_file},
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'expired_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'The token has expired, log in again: Signature has expired.'

    def test_load_recipes__invalid_user(
        self,
        user_credentials: sch.UserCredentials,
        recipe_csv_file: io.BytesIO,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        response = client.post(
            url='/load-recipes',
            files={'recipes_csv': recipe_csv_file},
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'invalid_user'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Only application admin can load recipes.'

    def test_load_recipes__error_storing_recipe(
        self,
        test_db: Db,
        another_test_db: Db,
        admin_credentials: sch.UserCredentials,
        recipe_csv_file: io.BytesIO,
        invalid_db_credentials: DbCredentials,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        recipes_db = another_test_db
        recipes_db.database_name = config.RECIPES_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        recipes_db.create()
        recipes_db.add_permissions()

        sign_up_hash = utils.calc_hash(password=admin_credentials.password)
        sign_up_body = {
            'hash': sign_up_hash,
            'validated': True
        }
        # Minimal sign up.
        credentials_db.create_document(document_id=admin_credentials.id, body=sign_up_body)

        payload = {'sub': admin_credentials.id}
        token = utils.create_token(payload=payload)

        with mock.patch.object(target=srv.db, attribute='app_credentials', new=invalid_db_credentials):
            response = client.post(
                url='/load-recipes',
                files={'recipes_csv': recipe_csv_file},
                headers={'Authorization': f'Bearer {token}'}
            )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'api_error_loading_recipes'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'An error ocurred trying to load the recipes.'
        assert list(
            utils.deep_traversal(response_data, 'details', 'data')
        ) == ['lemon-cake', 'baked-potatoes']

    # ----------------------------------------------------------------------------------------------
    #   Databases setup function
    # ----------------------------------------------------------------------------------------------
    def recipe_databases_setup(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
    ) -> None:
        recipes_db = test_db
        recipes_db.database_name = config.RECIPES_DB_NAME

        user_recipes_db = another_test_db
        user_recipes_db.database_name = config.USER_RECIPES_DB_NAME

        recipes_db.create()
        recipes_db.add_permissions()

        user_recipes_db.create()
        user_recipes_db.add_permissions()

        self.all_recipes = (recipe, another_recipe, one_more_recipe)
        for all_recipes_item in self.all_recipes:
            srv.store_recipe(recipe=all_recipes_item)

        self.available_user_recipe = deepcopy(recipe)
        self.purchased_user_recipe = deepcopy(another_recipe)
        self.purchased_user_recipe.status = sch.RecipeStatus.PURCHASED
        self.requested_user_recipe = deepcopy(one_more_recipe)
        self.requested_user_recipe.status = sch.RecipeStatus.REQUESTED

        self.user_recipes = (self.purchased_user_recipe, self.requested_user_recipe)
        self.user_recipes_mapping = {recipe.id: recipe.to_json(exclude={'price', 'recipe'}) for recipe in self.user_recipes}

        user_recipes_data = {
            'recipes': [
                {'recipe_id': recipe.id, 'status': recipe.status}
                for recipe in self.user_recipes
            ]
        }
        user_recipes_db.create_document(document_id=user_credentials.id, body=user_recipes_data)

    # ----------------------------------------------------------------------------------------------
    #   `/get-all-recipes` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_get_all_recipes_endpoint__general_case(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
    ) -> None:
        self.recipe_databases_setup(
            test_db=test_db,
            another_test_db=another_test_db,
            recipe=recipe,
            another_recipe=another_recipe,
            one_more_recipe=one_more_recipe,
            user_credentials=user_credentials,
        )

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        response = client.get(
            url='/get-all-recipes',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == status.HTTP_200_OK

        all_recipe_status = response.json()
        assert utils.deep_traversal(all_recipe_status, 'status') == 'api_all_recipes_retrieved'
        assert utils.deep_traversal(all_recipe_status, 'error') is False
        assert utils.deep_traversal(
            all_recipe_status,
            'details',
            'description'
        ) == 'All recipes retrieved successfully.'

        api_recipes = utils.deep_traversal(all_recipe_status, 'details', 'data', 'all_recipes')
        api_recipes_mapping = {recipe['id']: recipe for recipe in api_recipes}

        assert len(api_recipes) == len(self.all_recipes)
        for api_recipe in api_recipes:
            api_recipe_id = api_recipe['id']
            if api_recipe_id in self.user_recipes_mapping:
                assert api_recipe == self.user_recipes_mapping[api_recipe_id]
            else:
                assert api_recipe == api_recipes_mapping[api_recipe_id]

    def test_get_all_recipes_endpoint__recipe_reading_error(
        self,
        test_db: Db,
        another_test_db: Db,
        user_credentials: sch.UserCredentials,
        invalid_db_credentials: DbCredentials,
    ) -> None:
        # ----------------------------------------------------------------------
        #   Databases setup
        # ----------------------------------------------------------------------
        recipes_db = test_db
        recipes_db.database_name = config.RECIPES_DB_NAME

        user_recipes_db = another_test_db
        user_recipes_db.database_name = config.USER_RECIPES_DB_NAME

        recipes_db.create()
        recipes_db.add_permissions()

        user_recipes_db.create()
        user_recipes_db.add_permissions()
        # ----------------------------------------------------------------------

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        with mock.patch.object(
            target=srv.db,
            attribute='app_credentials',
            new=invalid_db_credentials,
        ):
            response = client.get(
                url='/get-all-recipes',
                headers={'Authorization': f'Bearer {token}'}
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        all_recipe_status = response.json()
        assert utils.deep_traversal(all_recipe_status, 'status') == 'api_error_getting_all_recipes'
        assert utils.deep_traversal(all_recipe_status, 'error') is True
        assert utils.deep_traversal(
            all_recipe_status,
            'details',
            'description'
        ) == 'An error ocurred trying to get all recipes.'


    def test_get_all_recipes_endpoint__invalid_token(
        self,
        user_credentials: sch.UserCredentials,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)
        invalid_token = token[:-1]

        response = client.get(
            url='/get-all-recipes',
            headers={'Authorization': f'Bearer {invalid_token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'invalid_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Invalid token: Signature verification failed.'

    def test_get_all_recipes_endpoint__expired_token(
        self,
        user_credentials: sch.UserCredentials,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload, expiration_hours=-1.0)

        response = client.get(
            url='/get-all-recipes',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'expired_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'The token has expired, log in again: Signature has expired.'

    # ----------------------------------------------------------------------------------------------
    #   `/get-recipe-details` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_get_recipe_details__general_case__available_recipe(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
    ) -> None:
        self.recipe_databases_setup(
            test_db=test_db,
            another_test_db=another_test_db,
            recipe=recipe,
            another_recipe=another_recipe,
            one_more_recipe=one_more_recipe,
            user_credentials=user_credentials,
        )

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        response = client.get(
            url=f'/get-recipe-details/{self.available_user_recipe.id}',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == status.HTTP_200_OK

        recipe_details_status = response.json()
        assert (
            utils.deep_traversal(recipe_details_status, 'status') == 'api_recipe_details_retrieved'
        )
        assert utils.deep_traversal(recipe_details_status, 'error') is False
        assert utils.deep_traversal(
            recipe_details_status,
            'details',
            'description'
        ) == 'Recipe details retrieved successfully.'

        api_recipe = utils.deep_traversal(recipe_details_status, 'details', 'data', 'recipe')

        assert 'recipe' in api_recipe
        assert 'price' in api_recipe
        assert api_recipe == recipe.to_json()

    def test_get_recipe_details__general_case__purchased_recipe(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
    ) -> None:
        self.recipe_databases_setup(
            test_db=test_db,
            another_test_db=another_test_db,
            recipe=recipe,
            another_recipe=another_recipe,
            one_more_recipe=one_more_recipe,
            user_credentials=user_credentials,
        )

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        response = client.get(
            url=f'/get-recipe-details/{self.purchased_user_recipe.id}',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == status.HTTP_200_OK

        recipe_details_status = response.json()
        assert (
            utils.deep_traversal(recipe_details_status, 'status') == 'api_recipe_details_retrieved'
        )
        assert utils.deep_traversal(recipe_details_status, 'error') is False
        assert utils.deep_traversal(
            recipe_details_status,
            'details',
            'description'
        ) == 'Recipe details retrieved successfully.'

        expected_recipe = deepcopy(self.purchased_user_recipe)
        expected_recipe.status = 'purchased'
        del(expected_recipe.price)

        api_recipe = utils.deep_traversal(recipe_details_status, 'details', 'data', 'recipe')

        assert api_recipe == expected_recipe.to_json()

    def test_get_recipe_details__general_case__requested_recipe(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
    ) -> None:
        self.recipe_databases_setup(
            test_db=test_db,
            another_test_db=another_test_db,
            recipe=recipe,
            another_recipe=another_recipe,
            one_more_recipe=one_more_recipe,
            user_credentials=user_credentials,
        )

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        response = client.get(
            url=f'/get-recipe-details/{self.requested_user_recipe.id}',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == status.HTTP_200_OK

        recipe_details_status = response.json()
        assert (
            utils.deep_traversal(recipe_details_status, 'status') == 'api_recipe_details_retrieved'
        )
        assert utils.deep_traversal(recipe_details_status, 'error') is False
        assert utils.deep_traversal(
            recipe_details_status,
            'details',
            'description'
        ) == 'Recipe details retrieved successfully.'

        expected_recipe = deepcopy(self.requested_user_recipe)
        expected_recipe.status = 'requested'
        del(expected_recipe.recipe)
        del(expected_recipe.price)

        api_recipe = utils.deep_traversal(recipe_details_status, 'details', 'data', 'recipe')

        assert api_recipe == expected_recipe.to_json()

    def test_get_recipe_details__recipe_reading_error(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
        invalid_db_credentials: DbCredentials,
    ) -> None:
        # ----------------------------------------------------------------------
        #   Databases setup
        # ----------------------------------------------------------------------
        recipes_db = test_db
        recipes_db.database_name = config.RECIPES_DB_NAME

        user_recipes_db = another_test_db
        user_recipes_db.database_name = config.USER_RECIPES_DB_NAME

        recipes_db.create()
        recipes_db.add_permissions()

        user_recipes_db.create()
        user_recipes_db.add_permissions()
        # ----------------------------------------------------------------------

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        with mock.patch.object(
            target=srv.db,
            attribute='app_credentials',
            new=invalid_db_credentials,
        ):
            response = client.get(
                url=f'/get-recipe-details/{recipe.id}',
                headers={'Authorization': f'Bearer {token}'}
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        all_recipe_status = response.json()
        assert (
            utils.deep_traversal(all_recipe_status, 'status') == 'api_error_getting_recipe_details'
            )
        assert utils.deep_traversal(all_recipe_status, 'error') is True
        assert utils.deep_traversal(
            all_recipe_status,
            'details',
            'description'
        ) == 'An error ocurred trying to get recipe details.'


    def test_get_recipe_details__invalid_token(
        self,
        user_credentials: sch.UserCredentials,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)
        invalid_token = token[:-1]

        response = client.get(
            url='/get-recipe-details/some-recipe',
            headers={'Authorization': f'Bearer {invalid_token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'invalid_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Invalid token: Signature verification failed.'

    def test_get_recipe_details__expired_token(
        self,
        user_credentials: sch.UserCredentials,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload, expiration_hours=-1.0)

        response = client.get(
            url='/get-recipe-details/some-recipe',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'expired_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'The token has expired, log in again: Signature has expired.'


# ==================================================================================================
#   Purchasing functionality
# ==================================================================================================
class TestPurchasingApi:
    # ----------------------------------------------------------------------------------------------
    #   `/buy-recipe` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_buy_recipe__general_case(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        encr_payment_info = cc_payment_info.encrypt().decode(encoding=config.APP_ENCODING_FORMAT)

        with mock.patch(target='services.start_checkout', autospec=True) as mock_start_checkout:
            mock_start_checkout.return_value = ost.start_checkout_status()
            buy_recipe_response = client.post(
                url=f'/buy-recipe/{recipe.id}',
                json={
                    'encr_info': encr_payment_info
                },
                headers={'Authorization': f'Bearer {token}'}
            )

        assert buy_recipe_response.status_code == status.HTTP_201_CREATED
        mock_start_checkout.assert_called_with(
            user_id=user_credentials.id,
            recipe_id=recipe.id,
            payment_encr_info=encr_payment_info,
        )

    def test_buy_recipe__create_checkout_error(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        encr_payment_info = cc_payment_info.encrypt()

        create_checkout_status = 'create_checkout_error'
        create_checkout_description = 'Some error from `create-checkout` endpoint.'
        create_checkout_error_status = sch.OutputStatus(
            status=create_checkout_status,
            error=True,
            details=sch.StatusDetails(
                description=create_checkout_description
            ),
        )

        with mock.patch(target='services.start_checkout', autospec=True) as mock_start_checkout:
            mock_start_checkout.return_value = create_checkout_error_status
            buy_recipe_response = client.post(
                url=f'/buy-recipe/{recipe.id}',
                json={
                    'encr_info': encr_payment_info.decode(encoding=config.APP_ENCODING_FORMAT)
                },
                headers={'Authorization': f'Bearer {token}'}
            )

        assert buy_recipe_response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        buy_recipe_response_json = buy_recipe_response.json()

        assert utils.deep_traversal(buy_recipe_response_json, 'status') == create_checkout_status
        assert (
            utils.deep_traversal(buy_recipe_response_json, 'details', 'description') ==
            create_checkout_description
        )

    def test_buy_recipe__create_checkout__http_error(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        encr_payment_info = cc_payment_info.encrypt()

        create_checkout_status = 'http_error'
        create_checkout_description = 'Some HTTP error from `create-checkout` endpoint.'
        create_checkout_status_code = status.HTTP_502_BAD_GATEWAY
        create_checkout_error_data = {'errors': ['Some HTTP error.']}
        create_checkout_error_status = sch.OutputStatus(
            status=create_checkout_status,
            error=True,
            details=sch.StatusDetails(
                description=create_checkout_description,
                error_code=create_checkout_status_code,
                data=create_checkout_error_data,
            ),
        )

        with mock.patch(target='services.start_checkout', autospec=True) as mock_start_checkout:
            mock_start_checkout.return_value = create_checkout_error_status
            buy_recipe_response = client.post(
                url=f'/buy-recipe/{recipe.id}',
                json={
                    'encr_info': encr_payment_info.decode(encoding=config.APP_ENCODING_FORMAT)
                },
                headers={'Authorization': f'Bearer {token}'}
            )

        assert buy_recipe_response.status_code == create_checkout_status_code

        buy_recipe_response_json = buy_recipe_response.json()

        assert utils.deep_traversal(buy_recipe_response_json, 'status') == create_checkout_status
        assert (
            utils.deep_traversal(buy_recipe_response_json, 'details', 'description') ==
            create_checkout_description
        )
        assert (
            utils.deep_traversal(buy_recipe_response_json, 'details', 'error_code') ==
            create_checkout_status_code
        )
        assert (
            utils.deep_traversal(buy_recipe_response_json, 'details', 'data') ==
            create_checkout_error_data
        )

    def test_buy_recipe__invalid_token(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)
        invalid_token = token[:-1]

        encr_payment_info = cc_payment_info.encrypt()

        response = client.post(
            url=f'/buy-recipe/{recipe.id}',
            json={
                'encr_info': encr_payment_info.decode(encoding=config.APP_ENCODING_FORMAT)
            },
            headers={'Authorization': f'Bearer {invalid_token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'invalid_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Invalid token: Signature verification failed.'

    def test_buy_recipe__expired_token(
        self,
        recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload, expiration_hours=-1.0)

        encr_payment_info = cc_payment_info.encrypt()

        response = client.post(
            url=f'/buy-recipe/{recipe.id}',
            json={
                'encr_info': encr_payment_info.decode(encoding=config.APP_ENCODING_FORMAT)
            },
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response_data = response.json()
        assert utils.deep_traversal(response_data, 'status') == 'expired_token'
        assert utils.deep_traversal(response_data, 'error') is True
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'The token has expired, log in again: Signature has expired.'

    # ----------------------------------------------------------------------------------------------
    #   `/payment-webhook` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_payment_webhook__general_case(
        self,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        with mock.patch(
            target='services.update_payment_status',
            autospec=True
        ) as mock_update_payment_status:
            mock_update_payment_status.return_value = ost.update_payment_status_status()

            body = {
                'recipe_id': recipe.id,
                'payment_id': payment_id,
                'payment_status': payment_status,
            }
            payment_webhook_response = client.post(
                url=f'/payment-webhook/{checkout_id}',
                json=body
            )

            assert payment_webhook_response.status_code == status.HTTP_202_ACCEPTED

            payment_webhook_response_json = payment_webhook_response.json()

            expected_status = ost.api_payment_webhook_status()

            assert payment_webhook_response_json == expected_status.model_dump()

    def test_payment_webhook__update_payment_status_error(
        self,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        with mock.patch(
            target='services.update_payment_status',
            autospec=True
        ) as mock_update_payment_status:
            mock_update_payment_status.return_value = ost.update_payment_status_checkout_not_found_status()

            body = {
                'recipe_id': recipe.id,
                'payment_id': payment_id,
                'payment_status': payment_status,
            }
            payment_webhook_response = client.post(
                url=f'/payment-webhook/{checkout_id}',
                json=body
            )

            assert payment_webhook_response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            payment_webhook_response_json = payment_webhook_response.json()

            expected_status = ost.update_payment_status_checkout_not_found_status()

            assert payment_webhook_response_json == expected_status.model_dump()

# ==================================================================================================
#   Payment Provider Simulator functionality
# ==================================================================================================
class TestPaymentProviderSimulatorApi:
    # ----------------------------------------------------------------------------------------------
    #   `/create-checkout` endpoint test
    # ----------------------------------------------------------------------------------------------
    def test_create_checkout__general_case(
        self,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
        checkout_id: str,
    ) -> None:
        with mock.patch(
            target='services.payment_processing',
            autospec=True
        ) as mock_payment_processing:
            with mock.patch(target='main.uuid4') as mock_uuid4:
                mock_uuid4.return_value = checkout_id

                mock_payment_processing.return_value = ost.start_checkout_status()

                body = {
                    'payment_encr_info': {
                        'encr_info': cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
                    },
                    'api_key': config.PAYMENT_PROVIDER_API_KEY
                }
                create_checkout_response = client.post(
                    url=f'/create-checkout/{recipe.id}',
                    json=body
                )

                assert create_checkout_response.status_code == status.HTTP_201_CREATED

                create_checkout_response_json = create_checkout_response.json()


                expected_status = ost.pprovider_create_checkout_status()
                expected_status.details.data = {'checkout_id': checkout_id}

                assert create_checkout_response_json == expected_status.model_dump()

    def test_create_checkout__payment_processing_error(
        self,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
        checkout_id: str,
    ) -> None:
        with mock.patch(
            target='services.trigger_payment_processing',
            autospec=True
        ) as mock_trigger_payment_processing:
            with mock.patch(target='main.uuid4') as mock_uuid4:
                mock_uuid4.return_value = checkout_id

                mock_trigger_payment_processing.return_value = (
                    ost.trigger_payment_processing_executor_error_status()
                )

                body = {
                    'payment_encr_info': {
                        'encr_info': cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
                    },
                    'api_key': config.PAYMENT_PROVIDER_API_KEY
                }
                create_checkout_response = client.post(
                    url=f'/create-checkout/{recipe.id}',
                    json=body
                )

                assert create_checkout_response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
                mock_trigger_payment_processing.assert_called_with(
                    checkout_id=checkout_id,
                    recipe_id=recipe.id
                )

                create_checkout_response_json = create_checkout_response.json()
                expected_status = ost.trigger_payment_processing_executor_error_status()

                assert create_checkout_response_json == expected_status.model_dump()

    def test_create_checkout__invalid_encrypted_payment_info(
        self,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
        checkout_id: str,
    ) -> None:
        with mock.patch(
            target='services.payment_processing',
            autospec=True
        ) as mock_payment_processing:
            with mock.patch(target='main.uuid4') as mock_uuid4:
                mock_uuid4.return_value = checkout_id

                mock_payment_processing.return_value = ost.start_checkout_status()

                body = {
                    'payment_encr_info': {
                        'encr_info': cc_payment_info.encrypt().decode(
                            config.APP_ENCODING_FORMAT
                        )[:-1]
                    },
                    'api_key': config.PAYMENT_PROVIDER_API_KEY
                }
                create_checkout_response = client.post(
                    url=f'/create-checkout/{recipe.id}',
                    json=body
                )

                assert create_checkout_response.status_code == status.HTTP_400_BAD_REQUEST

                create_checkout_response_json = create_checkout_response.json()
                expected_status = ost.pprovider_payment_info_error_status()

                assert create_checkout_response_json == expected_status.model_dump()

    def test_create_checkout__invalid_api_key(
        self,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
        checkout_id: str,
    ) -> None:
        with mock.patch(
            target='services.payment_processing',
            autospec=True
        ) as mock_payment_processing:
            with mock.patch(target='main.uuid4') as mock_uuid4:
                mock_uuid4.return_value = checkout_id

                mock_payment_processing.return_value = ost.start_checkout_status()

                body = {
                    'payment_encr_info': {
                        'encr_info': cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
                    },
                    # If `api_key` don't have 64 bytes the error will be on payload validation.
                    'api_key': 'invalid!invalid!invalid!invalid!invalid!invalid!invalid!invalid!'
                }
                create_checkout_response = client.post(
                    url=f'/create-checkout/{recipe.id}',
                    json=body
                )

                assert create_checkout_response.status_code == status.HTTP_401_UNAUTHORIZED

                create_checkout_response_json = create_checkout_response.json()


                expected_status = ost.pprovider_api_key_error_status()

                assert create_checkout_response_json == expected_status.model_dump()


# ==================================================================================================
#   Purchase events handling functionality
# ==================================================================================================
class TestPurchaseEventsHandlingApi:
    # ----------------------------------------------------------------------------------------------
    #   `/notifications` endpoint test
    # ----------------------------------------------------------------------------------------------
    @pytest.mark.asyncio
    async def __test_notifications__general_case(
        self,
        user_id: str,
        general_data: dict,
        notifications_manager: srv.NotificationEventsManager,
    ) -> None:
        payload = {'sub': user_id}
        token = utils.create_token(payload=payload)

        with mock.patch(target='services.notifications_manager', new=notifications_manager):
            notifications_manager.put(user_id=user_id, data=general_data)
            async with httpx.AsyncClient(base_url='http://localhost', timeout=20) as client:
                async with client.stream(
                    method='GET',
                    url='/notifications',
                    headers={'Authorization': f'Bearer {token}'}
                ) as response:
                    content_iterator = response.aiter_lines()
                    content = await anext(content_iterator)
                    prefix = 'data: '
                    data = json.loads(content[len(prefix):])

                    assert data == general_data

    @pytest.mark.asyncio
    async def _test_notifications__general_case(
        self,
        user_id: str,
        general_data: dict,
    ) -> None:
        async def test_generator(user_id: str = ''):
            while True:
                yield ServerSentEvent(data=general_data)
                await asyncio.sleep(1)

        payload = {'sub': user_id}
        token = utils.create_token(payload=payload)

        with mock.patch(target='services.notifications_manager.generate') as mock_generate:
            mock_generate.return_value = test_generator()
            async with httpx.AsyncClient(base_url='http://localhost', timeout=20) as client:
                async with client.stream(
                    method='GET',
                    url='/notifications',
                    headers={'Authorization': f'Bearer {token}'}
                ) as response:
                    content_iterator = response.aiter_lines()
                    content = await anext(content_iterator)
                    prefix = 'data: '
                    data = json.loads(content[len(prefix):])

                    assert data == general_data

    @pytest.mark.asyncio
    async def test_notifications__invalid_token(
        self,
        user_id: str,
    ) -> None:
        payload = {'sub': user_id}
        token = utils.create_token(payload=payload)[:-1]

        async with httpx.AsyncClient(base_url='http://localhost', timeout=20) as client:
            async with client.stream(
                method='GET',
                url='/notifications',
                headers={'Authorization': f'Bearer {token}'}
            ) as response:
                assert response.status_code == status.HTTP_400_BAD_REQUEST

                content_iterator = response.aiter_text()
                content = await anext(content_iterator)
                prefix = 'data: '
                data = json.loads(content[len(prefix):])

                assert data['status'] == 'invalid_token'
                assert data['error'] is True
                assert utils.deep_traversal(data, 'details', 'description') == 'Invalid token: Signature verification failed.'
