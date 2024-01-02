# ==================================================================================================
#  Services module tests
# ==================================================================================================
import json
from datetime import datetime, timedelta, UTC
from unittest import mock

import bcrypt
import pytest
from pydantic import SecretStr, ValidationError

import config
import pubsub as ps
import schemas as sch
import services as srv
import utils
from exceptions import ProducerNotRegisteredError
from tests.helpers import Db


class TestServices:
    # ==============================================================================================
    #   get_producer() function
    # ==============================================================================================
    def test_get_producer__general_case(self) -> None:
        first_producer_name = utils.first(srv.REGISTERED_PRODUCERS)

        test_producer = srv.get_producer(producer_name=first_producer_name)

        assert first_producer_name
        assert isinstance(test_producer, ps.PubSub)

    def test_get_producer__inexistent_producer(self) -> None:
        with pytest.raises(ProducerNotRegisteredError):
            srv.get_producer(producer_name='inexistent_producer')

    # ==============================================================================================
    #   user_sign_in service
    # ==============================================================================================
    def test_user_sign_in__general_case(
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

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        with mock.patch(target='pubsub.PubSub.publish') as mock_publish:
            result = srv.user_sign_in(credentials=user_credentials, user_info=user_info)
            event_message = utils.filter_data(data=user_info.model_dump(), keep=['id', 'name'])
            expected_event_message = json.dumps(event_message, separators=(',', ':'))
            mock_publish.assert_called_with(
                topic='user-signed-in',
                message=expected_event_message
            )

            expected_result = {
                'status': 'successful_sign_in',
                'error': False,
                'details': {
                    'description': 'User signed in successfully.'
                }
            }
            assert result == expected_result

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

    def test_user_sign_in__already_signed_in(
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

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        # Blocks `user-signed-in` event publishing
        with mock.patch(target='pubsub.PubSub.publish'):
            srv.user_sign_in(credentials=user_credentials, user_info=user_info)

            # Try to sign in again an user already signed in.
            result = srv.user_sign_in(credentials=user_credentials, user_info=user_info)
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
            assert result == expected_result

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

        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'successfully_logged_in'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'User has successfully logged in.'
        assert utils.deep_traversal(auth_result, 'error') is False

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
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
        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'incorrect_login_credentials'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'Invalid user or password. Check if user has signed in.'
        assert utils.deep_traversal(auth_result, 'error') is True

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
        assert token is None

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
        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'incorrect_login_credentials'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'Invalid user or password. Check if user has signed in.'
        assert utils.deep_traversal(auth_result, 'error') is True

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
        assert token is None

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

        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'incorrect_login_credentials'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'Invalid user or password. Check if user has signed in.'
        assert utils.deep_traversal(auth_result, 'error') is True

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
        assert token is None

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

        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'email_not_validated'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'User email is not validated.'
        assert utils.deep_traversal(auth_result, 'error') is True

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
        assert token is None

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

        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'user_already_signed_in'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'User was already logged in.'
        assert utils.deep_traversal(auth_result, 'error') is True

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
        assert token is None

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

        auth_result = srv.authentication(credentials=user_credentials)
        assert utils.deep_traversal(auth_result, 'status') == 'successfully_logged_in'
        assert utils.deep_traversal(
            auth_result,
            'details',
            'description',
        ) == 'User has successfully logged in.'
        assert utils.deep_traversal(auth_result, 'error') is False

        token = utils.deep_traversal(auth_result, 'details', 'data', 'token')
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
    #   email_confirmation service
    # ==============================================================================================
    def test_email_confirmation__general_case(
        self,
        capsys,
        callback_null_params,
        test_db: Db,
    ) -> None:
        test_user_info = sch.EmailConfirmationUserInfo(id='test@user.id', name='Mr. Test')
        serialized_user_info = test_user_info.model_dump_json()

        email_confimation_db = test_db
        email_confimation_db.database_name = config.EMAIL_CONFIRMATION_DB_NAME

        email_confimation_db.create()
        email_confimation_db.add_permissions()

        email_confirmation_data = email_confimation_db.get_document_by_id(
            document_id=test_user_info.id
        )
        assert 'email_confirmation_token' not in email_confirmation_data

        with mock.patch(target='services.stdout_message_delivery') as mock_delivery:
            srv.email_confirmation(**callback_null_params, body=serialized_user_info)
            mock_delivery.assert_called()

        srv.email_confirmation(**callback_null_params, body=serialized_user_info)
        captured = capsys.readouterr()
        assert test_user_info.name in captured.out
        assert 'To confirm you subscription, please access the following link:' in captured.out

        email_confirmation_data = email_confimation_db.get_document_by_id(
            document_id=test_user_info.id
        )
        assert 'email_confirmation_token' in email_confirmation_data
        assert email_confirmation_data['email_confirmation_token']

    def test_email_confirmation__invalid_event_format(self, callback_null_params) -> None:
        test_user_info = {'invalid_field': 'invalid'}
        serialized_user_info = json.dumps(test_user_info)

        with pytest.raises(ValidationError):
            srv.email_confirmation(**callback_null_params, body=serialized_user_info)
