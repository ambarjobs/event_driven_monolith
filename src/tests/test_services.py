# ==================================================================================================
#  Services module tests
# ==================================================================================================
import io
import json
import queue
from datetime import datetime, timedelta, UTC
from typing import Any
from unittest import mock

import bcrypt
import httpx
import pytest
from fastapi import status
from pydantic import SecretStr, ValidationError

import config
import output_status as ost
import schemas as sch
import services as srv
import utils
from database import DbCredentials
from exceptions import InvalidCsvFormatError
from tests.helpers import Db


# ==================================================================================================
#   Authentication functionality
# ==================================================================================================
class TestAuthenticationServices:
    # ----------------------------------------------------------------------------------------------
    #   `user_sign_up` service
    # ----------------------------------------------------------------------------------------------
    def test_user_sign_up__general_case(
        self,
        test_db: Db,
        another_test_db: Db,
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        known_hash: str,
        monkeypatch: pytest.MonkeyPatch,
        base_url: str,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        info_db = another_test_db
        info_db.database_name = config.USER_INFO_DB_NAME

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        with mock.patch(target='pubsub.PubSub.publish') as mock_publish:
            sign_up_status = srv.user_sign_up(
                credentials=user_credentials,
                user_info=user_info,
                base_url=base_url,
            )
            expected_event = {
                'user_id': user_info.id,
                'user_name': user_info.name,
                'base_url': base_url
            }
            # Avoiding spaces on the serialized data
            expected_event_message = json.dumps(expected_event, separators=(',', ':'))
            mock_publish.assert_called_with(
                topic='user-signed-up',
                message=expected_event_message,
            )

            expected_status = sch.OutputStatus(
                status='successful_sign_up',
                error=False,
                details = sch.StatusDetails(description='User signed up successfully.')
            )
            assert sign_up_status == expected_status

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

    def test_user_sign_up__already_signed_up(
        self,
        test_db: Db,
        another_test_db: Db,
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        monkeypatch: pytest.MonkeyPatch,
        base_url: str,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        info_db = another_test_db
        info_db.database_name = config.USER_INFO_DB_NAME

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        # Blocks `user-signed-up` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            srv.user_sign_up(credentials=user_credentials, user_info=user_info, base_url=base_url)

            # Try to sign up again an user already signed up.
            sign_up_status = srv.user_sign_up(
                credentials=user_credentials,
                user_info=user_info,
                base_url=base_url
            )
            credentials_doc = credentials_db.get_document_by_id(
                document_id=user_credentials.id,
            )
            expected_status = sch.OutputStatus(
                status='user_already_signed_up',
                error=True,
                details = sch.StatusDetails(
                    description='User already signed up.',
                    data={'version': credentials_doc['_rev']}
                )
            )
            assert sign_up_status == expected_status

    # ----------------------------------------------------------------------------------------------
    #   `authentication` service
    # ----------------------------------------------------------------------------------------------
    def test_authentication__general_case(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        test_hash = utils.calc_hash(user_credentials.password)

        before_login = datetime.now(tz=UTC)

        credentials_db.create()
        credentials_db.add_permissions()
        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'hash': test_hash,
                'validated': True,
            }
        )

        auth_status = srv.authentication(credentials=user_credentials)

        assert auth_status.status == 'successfully_logged_in'
        assert auth_status.details.description =='User has successfully logged in.'
        assert auth_status.error is False

        token = auth_status.details.data['token']
        token_payload = utils.get_token_payload(token=token)
        assert utils.deep_traversal(token_payload, 'sub') == user_credentials.id

        credentials_data = credentials_db.get_document_by_id(user_credentials.id)

        assert (
            datetime.fromisoformat(
                utils.deep_traversal(credentials_data, 'last_login')
            ) - before_login > timedelta(seconds=0)
        )

    def test_authentication__inexistent_user(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        test_hash = utils.calc_hash(user_credentials.password)

        credentials_db.create()
        credentials_db.add_permissions()

        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'hash': test_hash,
                'validated': True,
            }
        )

        user_credentials.id = 'inexistent@user.id'
        auth_status = srv.authentication(credentials=user_credentials)
        assert auth_status.status == 'incorrect_login_credentials'
        assert auth_status.details.description == (
            'Invalid user or password. Check if user has signed up.'
        )
        assert auth_status.error is True

        # token would be in `auth_status.details.data`, but `data` is empty, so there is no `token`.
        assert auth_status.details.data == {}

    def test_authentication__incorrect_password(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        test_hash = utils.calc_hash(user_credentials.password)

        credentials_db.create()
        credentials_db.add_permissions()

        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'hash': test_hash,
                'validated': True,
            }
        )

        user_credentials.password = SecretStr('incorrect')
        auth_status = srv.authentication(credentials=user_credentials)
        assert auth_status.status == 'incorrect_login_credentials'
        assert auth_status.details.description == (
            'Invalid user or password. Check if user has signed up.'
        )
        assert auth_status.error is True

        # token would be in `auth_status.details.data`, but `data` is empty, so there is no `token`.
        assert auth_status.details.data == {}

        credentials_data = credentials_db.get_document_by_id(user_credentials.id)

        last_login_iso = utils.deep_traversal(credentials_data, 'last_login')
        assert last_login_iso is None

    def test_authentication__no_hash(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        credentials_db.create()
        credentials_db.add_permissions()

        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'validated': True,
            }
        )

        auth_status = srv.authentication(credentials=user_credentials)
        assert auth_status.status == 'incorrect_login_credentials'
        assert auth_status.details.description == (
            'Invalid user or password. Check if user has signed up.'
        )
        assert auth_status.error is True

        # token would be in `auth_status.details.data`, but `data` is empty, so there is no `token`.
        assert auth_status.details.data == {}

        credentials_data = credentials_db.get_document_by_id(user_credentials.id)

        last_login_iso = utils.deep_traversal(credentials_data, 'last_login')
        assert last_login_iso is None

    def test_authentication__not_validated(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        test_hash = utils.calc_hash(user_credentials.password)

        credentials_db.create()
        credentials_db.add_permissions()

        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'hash': test_hash,
            }
        )

        auth_status = srv.authentication(credentials=user_credentials)
        assert auth_status.status == 'email_not_validated'
        assert auth_status.details.description == 'User email is not validated.'
        assert auth_status.error is True

        # token would be in `auth_status.details.data`, but `data` is empty, so there is no `token`.
        assert auth_status.details.data == {}

        credentials_data = credentials_db.get_document_by_id(user_credentials.id)

        last_login_iso = utils.deep_traversal(credentials_data, 'last_login')
        assert last_login_iso is None

    def test_authentication__already_logged_in(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        test_hash = utils.calc_hash(user_credentials.password)

        before_login = datetime.now(tz=UTC)

        credentials_db.create()
        credentials_db.add_permissions()

        # Logged in one hour ago
        last_login_iso = datetime.isoformat(this_moment - timedelta(hours=1.0))
        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'hash': test_hash,
                'validated': True,
                'last_login': last_login_iso
            }
        )

        auth_status = srv.authentication(credentials=user_credentials)
        assert auth_status.status == 'user_already_logged_in'
        assert (
            auth_status.details.description ==
            'User was already logged in and last token is still valid.'
        )
        assert auth_status.error is False

        token = auth_status.details.data['new_token']
        token_payload = utils.get_token_payload(token=token)
        assert utils.deep_traversal(token_payload, 'sub') == user_credentials.id

        credentials_data = credentials_db.get_document_by_id(user_credentials.id)

        assert (
            datetime.fromisoformat(
                utils.deep_traversal(credentials_data, 'last_login')
            ) - before_login > timedelta(seconds=0)
        )

    def test_authentication__expired_last_login(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        test_hash = utils.calc_hash(user_credentials.password)

        before_login = datetime.now(tz=UTC)

        credentials_db.create()
        credentials_db.add_permissions()

        # `last_login` expired one hour ago.
        last_login_iso = datetime.isoformat(
            this_moment -
            timedelta(hours=config.TOKEN_DEFAULT_EXPIRATION_HOURS + 1.0)
        )
        credentials_db.create_document(
            document_id=user_credentials.id,
            body={
                'hash': test_hash,
                'validated': True,
                'last_login': last_login_iso
            }
        )

        auth_status = srv.authentication(credentials=user_credentials)
        assert auth_status.status == 'successfully_logged_in'
        assert auth_status.details.description == 'User has successfully logged in.'
        assert auth_status.error is False

        token = auth_status.details.data['token']
        token_payload = utils.get_token_payload(token=token)
        assert utils.deep_traversal(token_payload, 'sub') == user_credentials.id

        credentials_data = credentials_db.get_document_by_id(user_credentials.id)

        assert (
            datetime.fromisoformat(
                utils.deep_traversal(credentials_data, 'last_login')
            ) - before_login > timedelta(seconds=0)
        )

    # ----------------------------------------------------------------------------------------------
    #   `get_user_info` service
    # ----------------------------------------------------------------------------------------------
    def test_get_user_info__general_case(
        self,
        test_db: Db,
        user_info: sch.UserInfo,
    ) -> None:
        user_info_db = test_db
        user_info_db.database_name = config.USER_INFO_DB_NAME

        user_info_db.create()
        user_info_db.add_permissions()

        body = utils.clear_nulls(user_info.model_dump(exclude={'id'}))
        user_info_db.create_document(document_id=user_info.id, body=body)

        user_info_status = srv.get_user_info(user_id=user_info.id)

        assert user_info_status.status == 'user_info'
        assert user_info_status.error is False
        assert user_info_status.details.description == 'User information.'
        assert user_info_status.details.data.get('_id') == user_info.id
        assert user_info_status.details.data.get('name') == user_info.name
        assert user_info_status.details.data.get('address') == user_info.address
        assert user_info_status.details.data.get('phone_number') is None

    def test_get_user_info__inexistent_user(
        self,
        test_db: Db,
        user_info: sch.UserInfo,
    ) -> None:
        user_info_db = test_db
        user_info_db.database_name = config.USER_INFO_DB_NAME

        user_info_db.create()
        user_info_db.add_permissions()

        body = utils.clear_nulls(user_info.model_dump(exclude={'id'}))
        user_info_db.create_document(document_id=user_info.id, body=body)

        user_info_status = srv.get_user_info(user_id='inexistent user id')

        assert user_info_status.status == 'user_info_not_found'
        assert user_info_status.error is True
        assert user_info_status.details.description == 'User or user information not found.'


# ==================================================================================================
#   Message delivery services
# ==================================================================================================
class TestMessageDeliveryServices:
    # ----------------------------------------------------------------------------------------------
    #   `stdout_message_delivery` service
    # ----------------------------------------------------------------------------------------------
    def test_stdout_message_delivery__general_case(self, capsys) -> None:
        test_message = '''Some multi-line message.
        To be delivered to stdout.
        '''
        srv.stdout_message_delivery(message=test_message)
        captured = capsys.readouterr()

        assert test_message in captured.out


# ==================================================================================================
#   Email confirmation functionality
# ==================================================================================================
class TestEmailConfirmationServices:
    # ----------------------------------------------------------------------------------------------
    #   `email_confirmation` consumer service
    # ----------------------------------------------------------------------------------------------
    def test_email_confirmation_consumer__general_case(
        self,
        capsys,
        callback_null_params,
        test_db: Db,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        serialized_confirmation_info = email_confirmation_info.model_dump_json()

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        email_confirmation_data = email_confirmation_db.get_document_by_id(
            document_id=email_confirmation_info.user_id
        )
        assert 'email_confirmation_token' not in email_confirmation_data

        with mock.patch(target='services.stdout_message_delivery') as mock_delivery:
            srv.email_confirmation(**callback_null_params, body=serialized_confirmation_info)
            mock_delivery.assert_called()

        srv.email_confirmation(**callback_null_params, body=serialized_confirmation_info)
        captured = capsys.readouterr()
        assert email_confirmation_info.user_name in captured.out
        assert 'To confirm you subscription, please access the following link:' in captured.out

        email_confirmation_data = email_confirmation_db.get_document_by_id(
            document_id=email_confirmation_info.user_id
        )
        assert 'email_confirmation_token' in email_confirmation_data
        assert email_confirmation_data['email_confirmation_token']

    # ----------------------------------------------------------------------------------------------
    #   `check_email_confirmation` service
    # ----------------------------------------------------------------------------------------------
    def test_check_email_confirmation__general_case(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
        test_db: Db,
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
            email_confirmation_status = srv.check_email_confirmation(token=test_token)

        assert email_confirmation_status.status == 'confirmed'
        assert email_confirmation_status.error is False
        assert email_confirmation_status.details.description == 'Email confirmed.'
        assert email_confirmation_status.details.data['email'] == token_confirmation_info.user_id
        assert email_confirmation_status.details.data['name'] == token_confirmation_info.user_name

        email_confirmation_data = email_confirmation_db.get_document_by_id(
            document_id=email_confirmation_info.user_id
        )

        this_moment = datetime.now(tz=UTC)
        assert utils.deep_traversal(email_confirmation_data, 'confirmed_datetime') is not None

        confirmed_datetime_iso = utils.deep_traversal(email_confirmation_data, 'confirmed_datetime')

        # Confirmed on this test
        assert (
            this_moment - datetime.fromisoformat(confirmed_datetime_iso)
        ) < timedelta(seconds=config.TEST_EXECUTION_LIMIT)

    def test_check_email_confirmation__invalid_token(
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
            email_confirmation_status = srv.check_email_confirmation(token=invalid_token)

        assert email_confirmation_status.status == 'invalid_token'
        assert email_confirmation_status.error is True
        assert email_confirmation_status.details.description == 'Invalid token.'
        assert email_confirmation_status.details.data['token'] == invalid_token
        assert email_confirmation_status.details.data['errors'] in (
            'Not enough segments',
            'Signature verification failed.'
        )

    def test_check_email_confirmation__invalid_token__payload_validation_error(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        token_confirmation_info.user_id = 'invalid id(email)'
        invalid_token = utils.create_token(payload=token_confirmation_info.model_dump())

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            email_confirmation_status = srv.check_email_confirmation(token=invalid_token)

        assert email_confirmation_status.status == 'invalid_token'
        assert email_confirmation_status.error is True
        assert email_confirmation_status.details.description == 'Invalid token.'
        assert email_confirmation_status.details.data['token'] == invalid_token
        assert email_confirmation_status.details.data['errors'][0]['type'] == 'value_error'
        assert email_confirmation_status.details.data['errors'][0]['loc'] == ('user_id',)

    def test_check_email_confirmation__inexistent_token(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
        test_db: Db,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        test_token = utils.create_token(payload=token_confirmation_info.model_dump())

        email_confirmation_db = test_db
        email_confirmation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confirmation_db.create()
        email_confirmation_db.add_permissions()

        email_confirmation_db.create_document(document_id=token_confirmation_info.user_id)

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            email_confirmation_status = srv.check_email_confirmation(token=test_token)

        assert email_confirmation_status.status == 'inexistent_token'
        assert email_confirmation_status.error is True
        assert email_confirmation_status.details.description == 'Inexistent token for the user id.'
        assert email_confirmation_status.details.data['token'] == test_token
        assert email_confirmation_status.details.data['email'] == token_confirmation_info.user_id

    def test_check_email_confirmation__expired_token(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
    ) -> None:
        token_confirmation_info = email_confirmation_info
        del(token_confirmation_info.base_url)

        expired_token = utils.create_token(
            payload=token_confirmation_info.model_dump(),
            expiration_hours=-1.0
        )

        # Blocks `email-confirmed` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            email_confirmation_status = srv.check_email_confirmation(token=expired_token)

        assert email_confirmation_status.status == 'expired_token'
        assert email_confirmation_status.error is True
        assert email_confirmation_status.details.description == 'The token has expired.'
        assert email_confirmation_status.details.data['token'] == expired_token

    def test_check_email_confirmation__previously_confirmed(
        self,
        email_confirmation_info: sch.EmailConfirmationInfo,
        test_db: Db,
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
            email_confirmation_status = srv.check_email_confirmation(token=test_token)

        assert email_confirmation_status.status == 'previously_confirmed'
        assert email_confirmation_status.error is True
        assert email_confirmation_status.details.description == 'The email was already confirmed.'
        assert (
            email_confirmation_status.details.data['confirmation_datetime'] ==
            previous_confirmation_datetime_iso
        )
        assert email_confirmation_status.details.data['email'] == token_confirmation_info.user_id

    # ----------------------------------------------------------------------------------------------
    #   `enable_user` consumer service
    # ----------------------------------------------------------------------------------------------
    def test_enable_user_consumer__general_case(
        self,
        callback_null_params,
        test_db: Db,
        user_id: str,
    ) -> None:
        user_credentials_db = test_db
        user_credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME

        user_credentials_db.create()
        user_credentials_db.add_permissions()

        user_credentials_db.create_document(document_id=user_id)

        user_credentials_data = user_credentials_db.get_document_by_id(document_id=user_id)
        assert 'validated' not in user_credentials_data

        srv.enable_user(**callback_null_params, body=user_id.encode(config.APP_ENCODING_FORMAT))

        user_credentials_data = user_credentials_db.get_document_by_id(document_id=user_id)
        assert utils.deep_traversal(user_credentials_data, 'validated') is True


# ==================================================================================================
#   Recipes functionality
# ==================================================================================================
class TestRecipesServices:
    # ----------------------------------------------------------------------------------------------
    #   `parse_recipe_data` service
    # ----------------------------------------------------------------------------------------------
    def test_parse_recipe_data__general_case(
        self,
        recipe_csv_data: dict[str, Any],
        this_moment: datetime
    ) -> None:
        recipe = srv.parse_recipe_data(csv_data=recipe_csv_data)

        assert recipe.summary.name == 'Lemon cake'
        assert recipe.summary.description == 'A great lemon cake'
        assert recipe.id == 'lemon-cake'
        assert recipe.category == 'dessert'
        assert recipe.easiness == 'medium'
        assert recipe.tags == ['dessert', 'lemon', 'cake']
        assert recipe.recipe.ingredients == [
            'lemon juice',
            'wheat flour',
            'milk',
            'sugar',
            'butter'
        ]
        assert recipe.recipe.directions == (
            'Mix everything.\nPut it in a greased pan and put it in the oven.'
        )
        # `recipe.modif_datetime` generated recently.
        assert recipe.modif_datetime - this_moment < timedelta(seconds=config.TEST_EXECUTION_LIMIT)

    def test_parse_recipe_data__missing_required_field(
        self,
        recipe_csv_data: dict[str, Any]
    ) -> None:
        del(recipe_csv_data['name'])

        with pytest.raises(InvalidCsvFormatError):
            srv.parse_recipe_data(csv_data=recipe_csv_data)

    def test_parse_recipe_data__empty_summary_name(self, recipe_csv_data: dict[str, Any]) -> None:
        recipe_csv_data['name'] = ''

        with pytest.raises(ValidationError):
            srv.parse_recipe_data(csv_data=recipe_csv_data)

    def test_parse_recipe_data__empty_ingredients(self, recipe_csv_data: dict[str, Any]) -> None:
        recipe_csv_data['ingredients'] = ''

        with pytest.raises(ValidationError):
            srv.parse_recipe_data(csv_data=recipe_csv_data)

    def test_parse_recipe_data__empty_directions(self, recipe_csv_data: dict[str, Any]) -> None:
        recipe_csv_data['directions'] = ''

        with pytest.raises(ValidationError):
            srv.parse_recipe_data(csv_data=recipe_csv_data)

    def test_parse_recipe_data__unknown_easiness(self, recipe_csv_data: dict[str, Any]) -> None:
        recipe_csv_data['easiness'] = 'invalid'

        with pytest.raises(ValidationError):
            srv.parse_recipe_data(csv_data=recipe_csv_data)

    def test_parse_recipe_data__invalid_data(self, recipe_csv_data: dict[str, Any]) -> None:
        recipe_csv_data['category'] = None

        with pytest.raises(InvalidCsvFormatError):
            srv.parse_recipe_data(csv_data=recipe_csv_data)

    # ----------------------------------------------------------------------------------------------
    #   `import_csv_recipes` service
    # ----------------------------------------------------------------------------------------------
    def test_import_csv_recipes__general_case(
        self,
        recipe_csv_file: io.BytesIO,
        this_moment: datetime
    ) -> None:
        import_recipes_status = srv.import_csv_recipes(csv_file=recipe_csv_file)

        assert import_recipes_status.status == 'csv_imported'
        assert import_recipes_status.error is False
        assert (
            import_recipes_status.details.description == 'CSV recipes file imported successfully.'
        )

        recipes = import_recipes_status.details.data['recipes']

        assert len(recipes) == 2

        first_recipe, second_recipe = recipes

        assert first_recipe.summary.name == 'Lemon cake'
        assert first_recipe.summary.description == 'A great lemon cake'
        assert first_recipe.id == 'lemon-cake'
        assert first_recipe.category == 'dessert'
        assert first_recipe.easiness == 'medium'
        assert first_recipe.price == 1.23
        assert first_recipe.status == 'available'
        assert first_recipe.tags == ['dessert', 'lemon', 'cake']
        assert first_recipe.recipe.ingredients == [
            'lemon juice',
            'wheat flour',
            'milk',
            'sugar',
            'butter'
        ]
        assert (
            first_recipe.modif_datetime - this_moment <
            timedelta(seconds=config.TEST_EXECUTION_LIMIT)
        )

        assert second_recipe.summary.name == 'Baked potatoes'
        assert second_recipe.summary.description == 'Hot and tasty baked potatoes.'
        assert second_recipe.id == 'baked-potatoes'
        assert second_recipe.category == ''
        assert second_recipe.easiness == 'easy'
        assert second_recipe.price == 1.2
        assert second_recipe.tags == []
        assert second_recipe.recipe.ingredients == [
            'potatoes',
            'milk',
            'butter',
            'spices',
        ]
        assert (
            second_recipe.modif_datetime - this_moment <
            timedelta(seconds=config.TEST_EXECUTION_LIMIT)
        )

    def test_import_csv_recipes__empty_file(self) -> None:
        recipe_csv_file = io.BytesIO(initial_bytes=b'')
        import_recipes_status = srv.import_csv_recipes(csv_file=recipe_csv_file)

        assert import_recipes_status.status == 'csv_imported'
        assert import_recipes_status.error is False
        assert (
            import_recipes_status.details.description == 'CSV recipes file imported successfully.'
        )

        recipes = import_recipes_status.details.data['recipes']

        assert recipes == []

    def test_import_csv_recipes__invalid_file(self) -> None:
        recipe_csv_file = io.BytesIO(initial_bytes=b'Some\tinvalid\tCSV\tfile')

        import_recipes_status = srv.import_csv_recipes(csv_file=recipe_csv_file)

        assert import_recipes_status.status == 'invalid_csv_format'
        assert import_recipes_status.error is True
        assert import_recipes_status.details.description == 'The format of the CSV file is invalid.'


    def test_import_csv_recipes__invalid_delimiter(self) -> None:
        recipe_csv_file = io.BytesIO(initial_bytes=b'Some,invalid,CSV,delimiter')

        import_recipes_status = srv.import_csv_recipes(csv_file=recipe_csv_file)

        assert import_recipes_status.status == 'invalid_csv_format'
        assert import_recipes_status.error is True
        assert import_recipes_status.details.description == 'The format of the CSV file is invalid.'

    def test_import_csv_recipe__invalid_content(self, recipe_csv_file: io.BytesIO) -> None:
        recipes_content = recipe_csv_file.read()
        recipes_content += (
            b'\n\tAnother great cake\tdessert\tmedium\t1.23\tdessert|cake\tanother thing|corn flour'
            b'|milk|sugar|butter\tMix everything.|Put it in a greased pan and put it in the oven.'
        )
        invalid_recipe_csv_file = io.BytesIO(initial_bytes=recipes_content)
        import_recipes_status = srv.import_csv_recipes(csv_file=invalid_recipe_csv_file)

        assert import_recipes_status.status == 'invalid_csv_content'
        assert import_recipes_status.error is True
        assert (
            import_recipes_status.details.description == 'The content of the CSV file is invalid.'
        )

    # ----------------------------------------------------------------------------------------------
    #   `store_recipe` service
    # ----------------------------------------------------------------------------------------------
    def test_store_recipe__general_case(self, recipe) -> None:
        with mock.patch(target='database.CouchDb.upsert_document') as mock_upsert:
            store_status = srv.store_recipe(recipe)
            fields = recipe.model_dump()
            recipe_id = fields.pop('id')
            fields['modif_datetime'] = fields['modif_datetime'].isoformat()
            mock_upsert.assert_called_with(
                database_name=config.RECIPES_DB_NAME,
                document_id=recipe_id,
                fields=fields
            )

        assert store_status.status == 'recipe_stored'
        assert store_status.error is False
        assert store_status.details.description == 'The recipe was stored successfully.'

    def test_store_recipe__database_errors(
        self,
        recipe: sch.Recipe,
        invalid_db_credentials: DbCredentials
    ) -> None:
        with mock.patch.object(
            target=srv.db,
            attribute='app_credentials',
            new=invalid_db_credentials,
        ):
            store_status = srv.store_recipe(recipe)

        assert store_status.status == 'error_storing_recipe'
        assert store_status.error is True
        assert store_status.details.description == 'An error ocurred trying to store the recipe.'
        assert store_status.details.data['errors'] == {
            'error': 'unauthorized',
            'reason': 'Name or password is incorrect.'
        }

    # ----------------------------------------------------------------------------------------------
    #   `get_all_recipes` service
    # ----------------------------------------------------------------------------------------------
    def test_get_all_recipes__general_case(
        self,
        test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
    ) -> None:
        recipe_db = test_db
        recipe_db.database_name = config.RECIPES_DB_NAME

        recipe_db.create()
        recipe_db.add_permissions()

        recipes = (recipe, another_recipe, one_more_recipe)
        for recipe_ in recipes:
            srv.store_recipe(recipe=recipe_)

        all_recipes_status = srv.get_all_recipes()

        assert all_recipes_status.status == 'all_recipes_retrieved'
        assert all_recipes_status.error is False
        assert all_recipes_status.details.description == 'All recipes retrieved successfully.'

        all_recipes = all_recipes_status.details.data['all_recipes']

        assert len(all_recipes) == len(recipes)
        for recipe in recipes:
            recipe.recipe = None
            assert recipe in all_recipes

    def test_get_all_recipes__database_error(
        self,
        test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        invalid_db_credentials: DbCredentials,
    ) -> None:
        recipe_db = test_db
        recipe_db.database_name = config.RECIPES_DB_NAME

        recipe_db.create()
        recipe_db.add_permissions()

        recipes = (recipe, another_recipe, one_more_recipe)
        for recipe_ in recipes:
            srv.store_recipe(recipe=recipe_)

        with mock.patch.object(
            target=srv.db,
            attribute='app_credentials',
            new=invalid_db_credentials,
        ):
            all_recipes_status = srv.get_all_recipes()

        assert all_recipes_status.status == 'error_retrieving_all_recipes'
        assert all_recipes_status.error is True
        assert (
            all_recipes_status.details.description ==
            'An error ocurred trying to retrieve all recipes.'
        )
        assert all_recipes_status.details.data['errors'] == {
            'error': 'unauthorized',
            'reason': 'Name or password is incorrect.'
        }

    # ----------------------------------------------------------------------------------------------
    #   `get_user_recipes` service
    # ----------------------------------------------------------------------------------------------
    def test_get_user_recipes__general_case(
        self,
        test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_id: str,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME

        user_recipe_db.create()
        user_recipe_db.add_permissions()

        recipe.status = 'purchased'
        another_recipe.status = 'requested'
        one_more_recipe.status = 'purchased'
        recipes = (recipe, another_recipe, one_more_recipe)
        user_recipes_data = {
            'recipes': [{'recipe_id': recipe.id, 'status': recipe.status} for recipe in recipes]
        }
        user_recipe_db.create_document(document_id=user_id, body=user_recipes_data)

        user_recipes_status = srv.get_user_recipes(user_id=user_id)

        assert user_recipes_status.status == 'user_recipes_retrieved'
        assert user_recipes_status.error is False
        assert user_recipes_status.details.description == 'User recipes retrieved successfully.'

        user_recipes = user_recipes_status.details.data['user_recipes']
        assert len(user_recipes) == len(recipes)
        assert [
            sch.UserRecipe(recipe_id=recipe.id, status=recipe.status)
            for recipe in recipes
        ] == user_recipes

    def test_get_user_recipes__database_error(
        self,
        test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        user_id: str,
        invalid_db_credentials: DbCredentials,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME

        user_recipe_db.create()
        user_recipe_db.add_permissions()

        recipe.status = 'purchased'
        another_recipe.status = 'requested'
        one_more_recipe.status = 'purchased'
        recipes = (recipe, another_recipe, one_more_recipe)
        user_recipes_data = {
            'recipes': [{'recipe_id': recipe.id, 'status': recipe.status} for recipe in recipes]
        }
        user_recipe_db.create_document(document_id=user_id, body=user_recipes_data)

        with mock.patch.object(
            target=srv.db,
            attribute='app_credentials',
            new=invalid_db_credentials,
        ):
            user_recipes_status = srv.get_user_recipes(user_id=user_id)

        assert user_recipes_status.status == 'error_retrieving_user_recipes'
        assert user_recipes_status.error is True
        assert (
            user_recipes_status.details.description ==
            'An error ocurred trying to retrieve user recipes.'
        )
        assert user_recipes_status.details.data['errors'] == {
            'error': 'unauthorized',
            'reason': 'Name or password is incorrect.'
        }

    # ----------------------------------------------------------------------------------------------
    #   `get_specific_recipe` service
    # ----------------------------------------------------------------------------------------------
    def test_get_specific_recipe__general_case(
        self,
        test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
    ) -> None:
        recipe_db = test_db
        recipe_db.database_name = config.RECIPES_DB_NAME

        recipe_db.create()
        recipe_db.add_permissions()

        recipes = (recipe, another_recipe, one_more_recipe)
        for recipe_ in recipes:
            srv.store_recipe(recipe=recipe_)

        specific_recipe_id = another_recipe.id

        specific_recipe_status = srv.get_specific_recipe(recipe_id=specific_recipe_id)

        assert specific_recipe_status.status == 'specific_recipe_retrieved'
        assert specific_recipe_status.error is False
        assert (
            specific_recipe_status.details.description == 'Specific recipe retrieved successfully.'
        )

        specific_recipe = specific_recipe_status.details.data['recipe']

        assert specific_recipe == another_recipe

    def test_get_specific_recipe__database_error(
        self,
        test_db: Db,
        recipe: sch.Recipe,
        another_recipe: sch.Recipe,
        one_more_recipe: sch.Recipe,
        invalid_db_credentials: DbCredentials,
    ) -> None:
        recipe_db = test_db
        recipe_db.database_name = config.RECIPES_DB_NAME

        recipe_db.create()
        recipe_db.add_permissions()

        recipes = (recipe, another_recipe, one_more_recipe)
        for recipe_ in recipes:
            srv.store_recipe(recipe=recipe_)

        with mock.patch.object(
            target=srv.db,
            attribute='app_credentials',
            new=invalid_db_credentials,
        ):
            specific_recipe_id = another_recipe.id
            specific_recipe_status = srv.get_specific_recipe(recipe_id=specific_recipe_id)

        assert specific_recipe_status.status == 'error_retrieving_specific_recipe'
        assert specific_recipe_status.error is True
        assert (
            specific_recipe_status.details.description ==
            'An error ocurred trying to retrieve specific recipe.'
        )
        assert specific_recipe_status.details.data['errors'] == {
            'error': 'unauthorized',
            'reason': 'Name or password is incorrect.'
        }


# ==================================================================================================
#   Purchasing functionality
# ==================================================================================================
class TestPurchasingServices:
    # ----------------------------------------------------------------------------------------------
    #   `start_checkout` service
    # ----------------------------------------------------------------------------------------------
    def test_start_checkout__general_case(
        self,
        test_db: Db,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
        checkout_id: str,
    ) -> None:
        payment_db = test_db
        payment_db.database_name = config.PAYMENT_DB_NAME
        payment_db.create()
        payment_db.add_permissions()

        test_payment_encr_info = cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
        body = {
            'payment_encr_info': {'encr_info': test_payment_encr_info},
            'api_key': config.PAYMENT_PROVIDER_API_KEY
        }

        test_create_checkout_status = ost.pprovider_create_checkout_status().model_dump()
        test_create_checkout_status['details']['data']={'checkout_id': checkout_id}

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_create_checkout_post:
            with mock.patch(target='pubsub.PubSub.publish') as mock_publish:
                # Avoiding a long line.
                mock_call = mock_create_checkout_post.return_value.raise_for_status.return_value
                mock_call.json.return_value = test_create_checkout_status

                checkout_status = srv.start_checkout(
                    user_id=user_credentials.id,
                    recipe_id=recipe.id,
                    payment_encr_info=test_payment_encr_info
                )

                mock_create_checkout_post.assert_called_with(
                    url=f'{config.PAYMENT_PROVIDER_CHECKOUT_URL}{recipe.id}',
                    json=body,
                )

                payment_db_data = payment_db.get_document_by_id(document_id=checkout_id)

                assert utils.deep_traversal(payment_db_data, '_id') == checkout_id
                assert utils.deep_traversal(payment_db_data, 'user_id') == user_credentials.id

                topic_message = {
                    'user_id': user_credentials.id,
                    'recipe_id': recipe.id
                }

                mock_publish.assert_called_with(
                    topic='recipe-purchase-requested',
                    # Avoiding spaces on the serialized data
                    message=json.dumps(topic_message, separators=(',', ':')),
                )
                assert checkout_status == ost.start_checkout_status()

    def test_start_checkout__create_checkout_error(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        test_payment_encr_info = cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
        body = {
            'payment_encr_info': {'encr_info': test_payment_encr_info},
            'api_key': config.PAYMENT_PROVIDER_API_KEY
        }

        test_create_checkout_error_status = ost.pprovider_payment_info_error_status().model_dump()

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_create_checkout_post:
            # Avoiding a long line.
            mock_call = mock_create_checkout_post.return_value.raise_for_status.return_value
            mock_call.json.return_value = test_create_checkout_error_status

            checkout_status = srv.start_checkout(
                user_id=user_credentials.id,
                recipe_id=recipe.id,
                payment_encr_info=test_payment_encr_info
            )

            mock_create_checkout_post.assert_called_with(
                url=f'{config.PAYMENT_PROVIDER_CHECKOUT_URL}{recipe.id}',
                json=body,
            )

            assert checkout_status == ost.pprovider_payment_info_error_status()

    def test_start_checkout__invalid_checkout_id(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        test_payment_encr_info = cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
        body = {
            'payment_encr_info': {'encr_info': test_payment_encr_info},
            'api_key': config.PAYMENT_PROVIDER_API_KEY
        }

        test_create_checkout_status = ost.pprovider_create_checkout_status().model_dump()

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_create_checkout_post:
            # Avoiding a long line.
            mock_call = mock_create_checkout_post.return_value.raise_for_status.return_value
            mock_call.json.return_value = test_create_checkout_status

            checkout_status = srv.start_checkout(
                user_id=user_credentials.id,
                recipe_id=recipe.id,
                payment_encr_info=test_payment_encr_info
            )

            mock_create_checkout_post.assert_called_with(
                url=f'{config.PAYMENT_PROVIDER_CHECKOUT_URL}{recipe.id}',
                json=body,
            )

            assert checkout_status == ost.api_invalid_checkout_id_error_status()

    def test_start_checkout__http_error(
        self,
        user_credentials: sch.UserCredentials,
        recipe: sch.Recipe,
        cc_payment_info: sch.PaymentCcInfo,
    ) -> None:
        test_payment_encr_info = cc_payment_info.encrypt().decode(config.APP_ENCODING_FORMAT)
        body = {
            'payment_encr_info': {'encr_info': test_payment_encr_info},
            'api_key': config.PAYMENT_PROVIDER_API_KEY
        }

        create_checkout_http_request = httpx.Request(
                method='POST',
                url=f'{config.PAYMENT_PROVIDER_CHECKOUT_URL}{recipe.id}'
            )
        create_checkout_http_response = httpx.Response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            json={'errors': ['Some HTTP error.']},
            request=create_checkout_http_request
        )
        create_checkout_http_error = httpx.HTTPStatusError(
            message='Some HTTP error from `create-checkout` endpoint.',
            request=create_checkout_http_request,
            response=create_checkout_http_response
        )

        test_create_checkout_status = ost.http_error_status(error=create_checkout_http_error)

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_create_checkout_post:
            # Avoiding a long line.
            mock_call = mock_create_checkout_post.return_value.raise_for_status
            mock_call.side_effect = create_checkout_http_error

            checkout_status = srv.start_checkout(
                user_id=user_credentials.id,
                recipe_id=recipe.id,
                payment_encr_info=test_payment_encr_info
            )

            mock_create_checkout_post.assert_called_with(
                url=f'{config.PAYMENT_PROVIDER_CHECKOUT_URL}{recipe.id}',
                json=body,
            )

            assert checkout_status == test_create_checkout_status
    # ----------------------------------------------------------------------------------------------
    #   `update_payment_status` service
    # ----------------------------------------------------------------------------------------------
    def test_update_payment_status__general_case(
        self,
        test_db: Db,
        user_id: str,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        payment_db = test_db
        payment_db.database_name = config.PAYMENT_DB_NAME
        payment_db.create()
        payment_db.add_permissions()

        webhook_payment_info = sch.WebhookPaymentInfo(
            recipe_id=recipe.id,
            payment_id=payment_id,
            payment_status=payment_status,
        )

        payment_db.create_document(document_id=checkout_id, body={'user_id': user_id})

        with mock.patch(target='pubsub.PubSub.publish') as mock_publish:
            update_payment_status_status = srv.update_payment_status(
                checkout_id=checkout_id,
                webhook_payment_info=webhook_payment_info
            )

            payment_db_data = payment_db.get_document_by_id(document_id=checkout_id)

            assert utils.deep_traversal(payment_db_data, '_id') == checkout_id
            assert utils.deep_traversal(payment_db_data, 'user_id') == user_id
            assert utils.deep_traversal(payment_db_data, 'recipe_id') == recipe.id
            assert utils.deep_traversal(payment_db_data, 'payment_id') == payment_id
            assert utils.deep_traversal(payment_db_data, 'payment_status') == payment_status

            message = sch.PurchaseStatusInfo(
                user_id=user_id,
                recipe_id=recipe.id,
                payment_status=payment_status,
            ).model_dump_json()

            mock_publish.assert_called_with(topic='purchase-status-changed', message=message)

            assert update_payment_status_status == ost.update_payment_status_status()

    def test_update_payment_status__checkout_not_found(
        self,
        test_db: Db,
        user_id: str,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        payment_db = test_db
        payment_db.database_name = config.PAYMENT_DB_NAME
        payment_db.create()
        payment_db.add_permissions()

        webhook_payment_info = sch.WebhookPaymentInfo(
            recipe_id=recipe.id,
            payment_id=payment_id,
            payment_status=payment_status,
        )

        with mock.patch(target='pubsub.PubSub.publish') as mock_publish:
            update_payment_status_status = srv.update_payment_status(
                checkout_id=checkout_id,
                webhook_payment_info=webhook_payment_info
            )

            payment_db_data = payment_db.get_document_by_id(document_id=checkout_id)

            assert payment_db_data  == {'error': 'not_found', 'reason': 'missing'}

            mock_publish.assert_not_called()

            assert (
                update_payment_status_status ==
                ost.update_payment_status_checkout_not_found_status()
            )

# ==================================================================================================
#   Payment Provider Simulator functionality
# ==================================================================================================
class TestPaymentProviderSimulator:
    # ----------------------------------------------------------------------------------------------
    #   `payment_processing` service
    # ----------------------------------------------------------------------------------------------
    def test_payment_processing__general_case(
        self,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        webhook_payment_info = sch.WebhookPaymentInfo(
            recipe_id=recipe.id,
            payment_id=payment_id,
            payment_status=payment_status,
        )

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_payment_webhook_post:
            with mock.patch(target='uuid.uuid4') as mock_uuid4:
                mock_uuid4.return_value = payment_id
                # Avoid the `time.sleep` by replacing it for a lambda that returns immediately.
                with mock.patch(target='time.sleep', wraps=lambda seconds: None):
                    # Avoiding a long line.
                    mock_call = mock_payment_webhook_post.return_value.raise_for_status.return_value
                    mock_call.json.return_value = ost.api_payment_webhook_status().model_dump()

                    payment_processing_status = srv.payment_processing(
                        checkout_id=checkout_id,
                        recipe_id=recipe.id,
                    )

                    mock_payment_webhook_post.assert_called_with(
                        url=f'{config.APP_WEBHOOK_URL}{checkout_id}',
                        json=webhook_payment_info.model_dump(),
                    )

                    assert payment_processing_status == ost.payment_processing_status()

    def test_payment_processing__payment_webhook_error(
        self,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        webhook_payment_info = sch.WebhookPaymentInfo(
            recipe_id=recipe.id,
            payment_id=payment_id,
            payment_status=payment_status,
        )

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_payment_webhook_post:
            with mock.patch(target='uuid.uuid4') as mock_uuid4:
                mock_uuid4.return_value = payment_id
                # Avoid the `time.sleep` by replacing it for a lambda that returns immediately.
                with mock.patch(target='time.sleep', wraps=lambda seconds: None):
                    # Avoiding a long line.
                    mock_call = mock_payment_webhook_post.return_value.raise_for_status.return_value
                    mock_call.json.return_value = (
                        ost.update_payment_status_checkout_not_found_status().model_dump()
                    )

                    payment_processing_status = srv.payment_processing(
                        checkout_id=checkout_id,
                        recipe_id=recipe.id,
                    )

                    mock_payment_webhook_post.assert_called_with(
                        url=f'{config.APP_WEBHOOK_URL}{checkout_id}',
                        json=webhook_payment_info.model_dump(),
                    )

                    assert payment_processing_status == ost.error_accessing_app_webhook_status()

    def test_payment_processing__http_error(
        self,
        recipe: sch.Recipe,
        checkout_id: str,
        payment_id: str,
        payment_status: int,
    ) -> None:
        webhook_payment_info = sch.WebhookPaymentInfo(
            recipe_id=recipe.id,
            payment_id=payment_id,
            payment_status=payment_status,
        )

        payment_webhook_http_request = httpx.Request(
                method='POST',
                url=f'{config.APP_WEBHOOK_URL}{checkout_id}'
            )
        payment_webhook_http_response = httpx.Response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            json={'errors': ['Some HTTP error.']},
            request=payment_webhook_http_request
        )
        payment_webhook_http_error = httpx.HTTPStatusError(
            message='Some HTTP error from `payment-webhook` endpoint.',
            request=payment_webhook_http_request,
            response=payment_webhook_http_response
        )

        with mock.patch.object(
            target=httpx,
            attribute='post',
            autospec=True
        ) as mock_payment_webhook_post:
            with mock.patch(target='uuid.uuid4') as mock_uuid4:
                mock_uuid4.return_value = payment_id
                # Avoid the `time.sleep` by replacing it for a lambda that returns immediately.
                with mock.patch(target='time.sleep', wraps=lambda seconds: None):
                    # Avoiding a long line.
                    mock_call = mock_payment_webhook_post.return_value.raise_for_status
                    mock_call.side_effect = payment_webhook_http_error

                    payment_processing_status = srv.payment_processing(
                        checkout_id=checkout_id,
                        recipe_id=recipe.id,
                    )

                    mock_payment_webhook_post.assert_called_with(
                        url=f'{config.APP_WEBHOOK_URL}{checkout_id}',
                        json=webhook_payment_info.model_dump(),
                    )

                    assert payment_processing_status == ost.http_error_status(
                        error=payment_webhook_http_error
                    )


# ==================================================================================================
#   Purchase events handling functionality
# ==================================================================================================
class TestPurchaseEventsHandling:
    # ----------------------------------------------------------------------------------------------
    #   `NotificationEventsManager` class
    # ----------------------------------------------------------------------------------------------
    def test_notification_events_manager__general_case(
        self,
        user_id: str,
        general_data: dict,
        notifications_manager: srv.NotificationEventsManager
    ) -> None:
        assert notifications_manager.users_mapping == {}

        notifications_manager.put(user_id=user_id, data=general_data)
        assert user_id in notifications_manager.users_mapping
        assert 'inexistent_user' not in notifications_manager.users_mapping

        user_queue =  notifications_manager.users_mapping[user_id]
        assert isinstance(user_queue, queue.SimpleQueue)
        assert not user_queue.empty()

        user_sse = notifications_manager.get(user_id=user_id)
        user_sse_data = json.loads(user_sse.data)

        assert user_sse_data['some_key'] == 'some_value'
        assert user_sse_data['another_key'] is None
        assert user_sse_data['yet_another_key'] == 123
        assert user_sse_data['321'] is None

        assert user_queue.empty()
        assert notifications_manager.get(user_id=user_id) is None

    @pytest.mark.asyncio
    async def test_notification_events_manager__generate(
        self,
        user_id: str,
        general_data: dict,
        notifications_manager: srv.NotificationEventsManager
    ) -> None:
        notifications_manager.put(user_id=user_id, data=general_data)

        notification_generator = notifications_manager.generate(user_id=user_id)

        user_sse = await anext(notification_generator)
        user_sse_data = json.loads(user_sse.data)

        assert user_sse_data['some_key'] == 'some_value'
        assert user_sse_data['another_key'] is None
        assert user_sse_data['yet_another_key'] == 123
        assert user_sse_data['321'] is None

    # ----------------------------------------------------------------------------------------------
    #   `error_response_generator`
    # ----------------------------------------------------------------------------------------------
    def test_error_response_generator__general_case(self) -> None:
        test_output_status = ost.invalid_token_status()
        error_event = next(srv.error_response_generator(output_status=test_output_status))

        assert json.loads(error_event.data) == test_output_status.model_dump()

        new_error_event = next(srv.error_response_generator(output_status=test_output_status))

        assert json.loads(new_error_event.data) == test_output_status.model_dump()

    # ----------------------------------------------------------------------------------------------
    #   `send_purchase_notification` consumer service
    # ----------------------------------------------------------------------------------------------
    def test_send_purchase_notification__general_case(
        self,
        callback_null_params,
        recipe: sch.Recipe,
        all_recipes_status: sch.OutputStatus,
        user_info_status: sch.OutputStatus,
        recipe_purchase_info: sch.RecipePurchaseInfo,
        notifications_manager: srv.NotificationEventsManager,
    ) -> None:
        serialized_recipe_purchase_info = recipe_purchase_info.model_dump_json()

        with mock.patch(target='services.notifications_manager', new=notifications_manager):
            with mock.patch(target='services.get_all_recipes') as mock_all_recipes:
                mock_all_recipes.return_value = all_recipes_status
                with mock.patch(target='services.get_user_info') as mock_user_info:
                    mock_user_info.return_value = user_info_status

                    srv.send_purchase_notification(
                        **callback_null_params,
                        body=serialized_recipe_purchase_info
                    )

                    user_id = recipe_purchase_info.user_id
                    recipe_id = recipe_purchase_info.recipe_id
                    assert user_id in srv.notifications_manager.users_mapping

                    user_queue = srv.notifications_manager.users_mapping[user_id]
                    assert isinstance(user_queue, queue.SimpleQueue)
                    assert not user_queue.empty()

                    notification = json.loads(user_queue.get_nowait().data)
                    assert notification['event_name'] == 'recipe-purchase-requested'
                    assert notification['user_id'] == user_id

                    notification_info = notification['data']

                    assert notification_info['user_name'] == user_info_status.details.data['name']
                    assert notification_info['recipe_id'] == recipe_id
                    assert notification_info['recipe_name'] == recipe.summary.name

    def test_send_purchase_notification__all_recipes_error(
        self,
        caplog,
        callback_null_params,
        recipe_purchase_info: sch.RecipePurchaseInfo,
        notifications_manager: srv.NotificationEventsManager,
    ) -> None:
        serialized_recipe_purchase_info = recipe_purchase_info.model_dump_json()

        with mock.patch(target='services.notifications_manager', new=notifications_manager):
            with mock.patch(target='services.get_all_recipes') as mock_all_recipes:
                mock_all_recipes.return_value = ost.error_retrieving_all_recipes_status()

                srv.send_purchase_notification(
                    **callback_null_params,
                    body=serialized_recipe_purchase_info
                )

                user_id = recipe_purchase_info.user_id
                assert user_id not in srv.notifications_manager.users_mapping

                message = 'An error ocurred trying to retrieve all recipes.'
                assert message in caplog.text

    def test_send_purchase_notification__inexistent_recipe(
        self,
        caplog,
        callback_null_params,
        all_recipes_status: sch.OutputStatus,
        user_info_status: sch.OutputStatus,
        recipe_purchase_info: sch.RecipePurchaseInfo,
        notifications_manager: srv.NotificationEventsManager,
    ) -> None:
        inexistent_recipe_info = recipe_purchase_info
        inexistent_recipe_info.recipe_id = 'inexistent_recipe'
        serialized_recipe_purchase_info = inexistent_recipe_info.model_dump_json()

        with mock.patch(target='services.notifications_manager', new=notifications_manager):
            with mock.patch(target='services.get_all_recipes') as mock_all_recipes:
                mock_all_recipes.return_value = all_recipes_status
                with mock.patch(target='services.get_user_info') as mock_user_info:
                    mock_user_info.return_value = user_info_status

                    srv.send_purchase_notification(
                        **callback_null_params,
                        body=serialized_recipe_purchase_info
                    )

                    user_id = recipe_purchase_info.user_id
                    assert user_id not in srv.notifications_manager.users_mapping

                    message = 'Purchase status changing event refers to an inexistent recipe.'
                    assert message in caplog.text

    # ----------------------------------------------------------------------------------------------
    #   `add_user_recipe` consumer service
    # ----------------------------------------------------------------------------------------------
    def test_add_user_recipe__general_case(
        self,
        callback_null_params,
        test_db: Db,
        recipe_purchase_info: sch.RecipePurchaseInfo,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME
        user_recipe_db.create()
        user_recipe_db.add_permissions()

        serialized_recipe_purchase_info = recipe_purchase_info.model_dump_json()

        srv.add_user_recipe(
            **callback_null_params,
            body=serialized_recipe_purchase_info
        )

        user_recipes_db = user_recipe_db.get_document_by_id(
            document_id=recipe_purchase_info.user_id
        )
        user_recipes = user_recipes_db.get('recipes', [])

        assert user_recipes == [
            {'recipe_id': recipe_purchase_info.recipe_id, 'status': sch.RecipeStatus.REQUESTED}
        ]

    def test_add_user_recipe__already_exists(
        self,
        caplog,
        callback_null_params,
        test_db: Db,
        recipe_purchase_info: sch.RecipePurchaseInfo,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME
        user_recipe_db.create()
        user_recipe_db.add_permissions()

        user_id = recipe_purchase_info.user_id
        recipe_id = recipe_purchase_info.recipe_id

        test_recipe = {'recipe_id': recipe_id}
        user_recipe_db.create_document(
            document_id=user_id,
            body={'recipes': [test_recipe]},
        )

        serialized_recipe_purchase_info = recipe_purchase_info.model_dump_json()

        srv.add_user_recipe(
            **callback_null_params,
            body=serialized_recipe_purchase_info
        )

        message = f'Trying to add an already existent recipe [{recipe_id}] for user [{user_id}].'
        assert message in caplog.text

        user_recipes_db = user_recipe_db.get_document_by_id(
            document_id=user_id
        )
        user_recipes = user_recipes_db.get('recipes', [])

        # The `test_recipe` doesn't have, purposely, a `status`, so this indicates the document
        # is untouched.
        assert user_recipes == [test_recipe]

    # ----------------------------------------------------------------------------------------------
    #   `update_recipe_status` consumer service
    # ----------------------------------------------------------------------------------------------
    def test_update_recipe_status__general_case(
        self,
        callback_null_params,
        test_db: Db,
        paid_purchase_status_info: sch.PurchaseStatusInfo,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME
        user_recipe_db.create()
        user_recipe_db.add_permissions()

        serialized_paid_purchase_status_info = paid_purchase_status_info.model_dump_json()
        user_id = paid_purchase_status_info.user_id
        recipe_id = paid_purchase_status_info.recipe_id

        body = {
            'recipes': [
                {'recipe_id': recipe_id, 'status': sch.RecipeStatus.REQUESTED}
            ]
        }
        user_recipe_db.create_document(document_id=user_id, body=body)

        srv.update_recipe_status(
            **callback_null_params,
            body=serialized_paid_purchase_status_info
        )

        user_recipes_db = user_recipe_db.get_document_by_id(
            document_id=user_id
        )
        user_recipes = user_recipes_db.get('recipes', [])

        assert user_recipes == [
            {'recipe_id': recipe_id, 'status': sch.RecipeStatus.PURCHASED}
        ]

    def test_update_recipe_status__no_recipes(
        self,
        caplog,
        callback_null_params,
        test_db: Db,
        paid_purchase_status_info: sch.PurchaseStatusInfo,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME
        user_recipe_db.create()
        user_recipe_db.add_permissions()

        serialized_paid_purchase_status_info = paid_purchase_status_info.model_dump_json()
        user_id = paid_purchase_status_info.user_id
        recipe_id = paid_purchase_status_info.recipe_id

        srv.update_recipe_status(
            **callback_null_params,
            body=serialized_paid_purchase_status_info
        )

        message = f'Trying to update an inexistent recipe [{recipe_id}] for user [{user_id}].'
        assert message in caplog.text

        user_recipes_db = user_recipe_db.get_document_by_id(
            document_id=user_id
        )
        user_recipes = user_recipes_db.get('recipes', [])

        assert user_recipes == []

    def test_update_recipe_status__unknown_payment_status(
        self,
        caplog,
        callback_null_params,
        test_db: Db,
        paid_purchase_status_info: sch.PurchaseStatusInfo,
    ) -> None:
        user_recipe_db = test_db
        user_recipe_db.database_name = config.USER_RECIPES_DB_NAME
        user_recipe_db.create()
        user_recipe_db.add_permissions()

        unknown_payment_status = sch.PaymentStatus.CANCELLED
        paid_purchase_status_info.payment_status = unknown_payment_status
        serialized_paid_purchase_status_info = paid_purchase_status_info.model_dump_json()
        user_id = paid_purchase_status_info.user_id
        recipe_id = paid_purchase_status_info.recipe_id

        test_recipe = {'recipe_id': recipe_id, 'status': sch.RecipeStatus.REQUESTED}
        body = {'recipes': [test_recipe]}
        user_recipe_db.create_document(document_id=user_id, body=body)

        srv.update_recipe_status(
            **callback_null_params,
            body=serialized_paid_purchase_status_info
        )

        message = f'Unable to update to unidentified status: {unknown_payment_status}.'
        assert message in caplog.text

        user_recipes_db = user_recipe_db.get_document_by_id(
            document_id=user_id
        )
        user_recipes = user_recipes_db.get('recipes', [])

        assert user_recipes == [test_recipe]

    # ----------------------------------------------------------------------------------------------
    #   `notify_recipe_state_change` consumer service
    # ----------------------------------------------------------------------------------------------
    def test_notify_recipe_state_change__general_case(
        self,
        callback_null_params,
        paid_purchase_status_info: sch.PurchaseStatusInfo,
        notifications_manager: srv.NotificationEventsManager,
    ) -> None:
        serialized_purchase_status_info = paid_purchase_status_info.model_dump_json()

        with mock.patch(target='services.notifications_manager', new=notifications_manager):
            srv.notify_recipe_state_change(
                **callback_null_params,
                body=serialized_purchase_status_info
            )

            user_id = paid_purchase_status_info.user_id
            recipe_id = paid_purchase_status_info.recipe_id
            assert user_id in srv.notifications_manager.users_mapping

            user_queue = srv.notifications_manager.users_mapping[user_id]
            assert isinstance(user_queue, queue.SimpleQueue)
            assert not user_queue.empty()

            notification = json.loads(user_queue.get_nowait().data)
            assert notification['event_name'] == 'purchase-status-changed'
            assert notification['user_id'] == user_id

            notification_info = notification['data']

            assert notification_info['user_id'] == user_id
            assert notification_info['recipe_id'] == recipe_id
            assert notification_info['payment_status'] == paid_purchase_status_info.payment_status
            assert notification_info.get('when') is not None
