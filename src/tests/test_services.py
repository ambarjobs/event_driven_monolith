# ==================================================================================================
#  Services module tests
# ==================================================================================================
from datetime import datetime, timedelta, UTC
from typing import Type

import bcrypt
import pytest
from pydantic import SecretStr

import config
import schemas as sch
import services as srv
import utils
from tests.helpers import Db


config.USER_CREDENTIALS_DB_NAME = f'{config.TEST_PREFIX}-{config.USER_CREDENTIALS_DB_NAME}'
config.USER_INFO_DB_NAME = f'{config.TEST_PREFIX}-{config.USER_INFO_DB_NAME}'


class TestServices:
    # ==============================================================================================
    #   user_sign_in service
    # ==============================================================================================
    def test_user_sign_in__general_case(
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

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        try:
            credentials_db.create()
            info_db.create()
            credentials_db.add_permissions()
            info_db.add_permissions()

            result = srv.user_sign_in(credentials=user_credentials, user_info=user_info)
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
        finally:
            credentials_db.delete()
            info_db.delete()

    def test_user_sign_in__already_signed_in(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials,
        user_info: sch.UserInfo,
        known_salt: bytes,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        info_db = TestDb(database_name=config.USER_INFO_DB_NAME)

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        try:
            credentials_db.create()
            info_db.create()
            credentials_db.add_permissions()
            info_db.add_permissions()

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
        finally:
            credentials_db.delete()
            info_db.delete()

    # ==============================================================================================
    #   authentication service
    # ==============================================================================================
    def test_authentication__general_case(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        test_hash = utils.calc_hash(user_credentials.password)

        try:
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
        finally:
            credentials_db.delete()

    def test_authentication__inexistent_user(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        test_hash = utils.calc_hash(user_credentials.password)

        try:
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
        finally:
            credentials_db.delete()

    def test_authentication__incorrect_password(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        test_hash = utils.calc_hash(user_credentials.password)

        try:
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
        finally:
            credentials_db.delete()

    def test_authentication__no_hash(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)

        try:
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
        finally:
            credentials_db.delete()

    def test_authentication__not_validated(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        test_hash = utils.calc_hash(user_credentials.password)

        try:
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
        finally:
            credentials_db.delete()

    def test_authentication__already_logged_in(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        test_hash = utils.calc_hash(user_credentials.password)

        try:
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
        finally:
            credentials_db.delete()

    def test_authentication__expired_last_login(
        self,
        TestDb: Type[Db],
        user_credentials: sch.UserCredentials,
        this_moment: datetime,
    ) -> None:
        credentials_db = TestDb(database_name=config.USER_CREDENTIALS_DB_NAME)
        test_hash = utils.calc_hash(user_credentials.password)

        try:
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
        finally:
            credentials_db.delete()
