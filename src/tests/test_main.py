# ==================================================================================================
#  Main module tests
# ==================================================================================================
import io
from datetime import datetime, timedelta, UTC
from unittest import mock

import bcrypt
import pytest
from fastapi import status
from fastapi.testclient import TestClient

import config
import services as srv
import schemas as sch
import utils
from main import app
from tests.helpers import Db


client = TestClient(app=app)


class TestMain:
    # ==============================================================================================
    #   /signup endpoint test
    # ==============================================================================================
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

        login_status = sch.ServiceStatus(**response.json())

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

        login_status = sch.ServiceStatus(**response.json())

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

        login_status = sch.ServiceStatus(**response.json())

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

        login_status = sch.ServiceStatus(**response.json())

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

        login_status = sch.ServiceStatus(**response.json())

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

    # ==============================================================================================
    #   /load-recipes endpoint test
    # ==============================================================================================
    def test_load_recipe__general_case(
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
        assert utils.deep_traversal(response_data, 'status') == 'recipes_loaded'
        assert utils.deep_traversal(response_data, 'error') is False
        assert utils.deep_traversal(
            response_data,
            'details',
            'description'
        ) == 'Recipes loaded with success.'

    def test_load_recipe__invalid_token(
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

    def test_load_recipe__expired_token(
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

    def test_load_recipe__invalid_user(
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

    # ==============================================================================================
    #   /get-all-recipes endpoint test
    # ==============================================================================================
    def test_get_all_recipes_endpoint__general_case(
        self,
        test_db: Db,
        another_test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_credentials: sch.UserCredentials,
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

        all_recipes = (recipe, another_recipe, one_more_recipe)
        for all_recipes_item in all_recipes:
            srv.store_recipe(recipe=all_recipes_item)

        another_recipe.status = sch.RecipeStatus.purchased
        one_more_recipe.status = sch.RecipeStatus.requested

        user_recipes = (another_recipe, one_more_recipe)
        for user_recipes_item in user_recipes:
            del(user_recipes_item.price)
            del(user_recipes_item.recipe)
        user_recipes_mapping = {recipe.id: recipe.to_json() for recipe in user_recipes}

        user_recipes_data = {
            'recipes': [
                {'recipe_id': recipe.id, 'status': recipe.status}
                for recipe in user_recipes
            ]
        }
        user_recipes_db.create_document(document_id=user_credentials.id, body=user_recipes_data)
        # ----------------------------------------------------------------------

        payload = {'sub': user_credentials.id}
        token = utils.create_token(payload=payload)

        response = client.get(
            url='/get-all-recipes',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == status.HTTP_200_OK

        response_data = response.json()
        api_recipes = utils.deep_traversal(response_data, 'recipes')
        api_recipes_mapping = {recipe['id']: recipe for recipe in api_recipes}

        assert len(api_recipes) == len(all_recipes)
        for api_recipe in api_recipes:
            api_recipe_id = api_recipe['id']
            if api_recipe_id in user_recipes_mapping:
                assert api_recipe == user_recipes_mapping[api_recipe_id]
            else:
                assert api_recipe == api_recipes_mapping[api_recipe_id]

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
