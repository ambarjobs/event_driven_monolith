# ==================================================================================================
#  Services module tests
# ==================================================================================================
import bcrypt
import pytest

import config
import schemas as sch
import services as srv
import utils


config.USER_CREDENTIALS_DB_NAME = f'{config.TEST_PREFIX}-{config.USER_CREDENTIALS_DB_NAME}'
config.USER_INFO_DB_NAME = f'{config.TEST_PREFIX}-{config.USER_INFO_DB_NAME}'


class TestServices:
    def test_user_sign_in__general_case(
        self,
        TestDb,
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

            assert result == {'status': 'signed_in'}

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

    def test_user_sign_in__already_signed_in(
        self,
        TestDb,
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

            srv.user_sign_in(credentials=user_credentials, user_info=user_info)

            # Try to sign in again an user already signed in.
            result = srv.user_sign_in(credentials=user_credentials, user_info=user_info)

            credentials_response = credentials_db.get_document_by_id(
                document_id=user_credentials.id,
                fields=['_id', '_rev', 'hash'],
            )
            credentials_doc =  utils.deep_traversal(credentials_response, 'docs', 0)

            expected_result = {
                'status': 'already_signed_in',
                'version': credentials_doc['_rev']
            }

            assert result == expected_result

        finally:
            credentials_db.delete()
            info_db.delete()
