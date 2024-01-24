# ==================================================================================================
#  Services module tests
# ==================================================================================================
import io
import json
from datetime import datetime, timedelta, UTC
from typing import Any
from unittest import mock

import bcrypt
import pytest
from pydantic import SecretStr, ValidationError

import config
import schemas as sch
import services as srv
import utils
from exceptions import InvalidCsvFormatError
from tests.helpers import Db


class TestServices:
    # ==============================================================================================
    #   user_sign_up service
    # ==============================================================================================
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
            expected_event_message = json.dumps(expected_event, separators=(',', ':'))
            mock_publish.assert_called_with(
                topic='user-signed-up',
                message=expected_event_message,
            )

            expected_status = sch.ServiceStatus(
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
            expected_status = sch.ServiceStatus(
                status='user_already_signed_up',
                error=True,
                details = sch.StatusDetails(
                    description='User already signed up.',
                    data={'version': credentials_doc['_rev']}
                )
            )
            assert sign_up_status == expected_status

    # ==============================================================================================
    #   authentication service
    # ==============================================================================================
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

    # ==============================================================================================
    #   Message delivery services
    # ==============================================================================================
    def test_stdout_message_delivery__general_case(self, capsys) -> None:
        test_message = '''Some multi-line message.
        To be delivered to stdout.
        '''
        srv.stdout_message_delivery(message=test_message)
        captured = capsys.readouterr()

        assert test_message in captured.out

    # ==============================================================================================
    #   email_confirmation consumer service
    # ==============================================================================================
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

    # ==============================================================================================
    #   check_email_confirmation service
    # ==============================================================================================
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

    # ==============================================================================================
    #   enable_user consumer service
    # ==============================================================================================
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

    # ==============================================================================================
    #   parse_recipe_data service
    # ==============================================================================================
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

    def test_parse_recipe_data__missing_required_field(self, recipe_csv_data: dict[str, Any]) -> None:
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

    # ==============================================================================================
    #   import_csv_recipes service
    # ==============================================================================================
    def test_import_csv_recipes__general_case(
        self,
        recipe_csv_file: io.BytesIO,
        this_moment: datetime
    ) -> None:
        recipes = srv.import_csv_recipes(csv_file=recipe_csv_file)

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
        recipes = srv.import_csv_recipes(csv_file=recipe_csv_file)

        assert recipes == []

    def test_import_csv_recipes__invalid_file(self) -> None:
        recipe_csv_file = io.BytesIO(initial_bytes=b'Some\tinvalid\tCSV\tfile')

        with pytest.raises(InvalidCsvFormatError):
            srv.import_csv_recipes(csv_file=recipe_csv_file)

    def test_import_csv_recipes__invalid_delimiter(self) -> None:
        recipe_csv_file = io.BytesIO(initial_bytes=b'Some,invalid,CSV,delimiter')

        with pytest.raises(InvalidCsvFormatError):
            srv.import_csv_recipes(csv_file=recipe_csv_file)

    # ==============================================================================================
    #   store_recipe service
    # ==============================================================================================
    def test_store_recipe__general_case(self, recipe) -> None:
        with mock.patch(target='database.CouchDb.upsert_document') as mock_upsert:
            srv.store_recipe(recipe)
            fields = recipe.model_dump()
            recipe_id = fields.pop('id')
            fields['modif_datetime'] = fields['modif_datetime'].isoformat()
            mock_upsert.assert_called_with(
                database_name=config.RECIPES_DB_NAME,
                document_id=recipe_id,
                fields=fields
            )

    # ==============================================================================================
    #   get_all_recipes service
    # ==============================================================================================
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

        all_recipes = srv.get_all_recipes()

        assert len(all_recipes) == len(recipes)
        for recipe in recipes:
            recipe.recipe = None
            assert recipe in all_recipes


    # ==============================================================================================
    #   get_user_recipes service
    # ==============================================================================================
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

        user_recipes = srv.get_user_recipes(user_id=user_id)

        assert len(user_recipes) == len(recipes)
        assert [
            sch.UserRecipe(recipe_id=recipe.id, status=recipe.status)
            for recipe in recipes
        ] == user_recipes
