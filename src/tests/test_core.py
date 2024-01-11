# ==================================================================================================
#  Core module tests
# ==================================================================================================
from unittest import mock

import bcrypt
import httpx
import pytest
from pydantic import SecretStr

import config
import core
import pubsub as ps
import utils
from database import DatabaseInfo, db, Index
from exceptions import ConsumerServiceNotFoundError
from tests.helpers import access_database, Db

class TestCore:
    # ----------------------------------------------------------------------------------------------
    #   Initialization
    # ----------------------------------------------------------------------------------------------
    def test_init_app_databases__general_case(self) -> None:
        test_database_info =  DatabaseInfo(
            name=config.USER_CREDENTIALS_DB_NAME,
            indexes=[
                Index(name=f'{config.USER_CREDENTIALS_DB_NAME}-id--index', fields=['_id']),
                Index(name='another-id--index', fields=['field']),
            ]
        )

        test_databases_infos = [test_database_info]

        try:
            core.init_app_databases(databases_info=test_databases_infos)

            all_dbs = access_database(
                access_function=httpx.get,
                url_parts=['_all_dbs'],
                credentials=db.admin_credentials,
            )

            assert test_database_info.name in all_dbs

            index_response = access_database(
                access_function=httpx.get,
                url_parts=[test_database_info.name, '_index'],
                credentials=db.admin_credentials,
            )
            test_db_indexes = [
                utils.deep_traversal(index, 'ddoc')
                for index in utils.deep_traversal(index_response, 'indexes')
            ]

            for index in test_database_info.indexes:
                assert f'_design/{index.name}' in test_db_indexes

        finally:
            for database_info in test_databases_infos:
                access_database(
                    access_function=httpx.delete,
                    url_parts=[database_info.name],
                    credentials=db.admin_credentials,
                )

    def test_start_consumers__general_case(self) -> None:
        test_subscription = ps.Subscription(topic_name='test_topic', consumer_service_name='email_confirmation')
        subscriptions = (test_subscription,)

        with mock.patch(target='threading.Thread') as mock_thread:
            mock_thread.return_value().is_alive.return_value = True
            with mock.patch(target='core.start_consumer_thread') as mock_spawn_thread:
                with mock.patch(target='pubsub.PubSub') as mock_pub_sub:
                    core.start_consumers(subscriptions=subscriptions)

                    mock_thread.assert_called_with(
                        target=mock_spawn_thread,
                        kwargs={
                            'pub_sub': mock_pub_sub(),
                            'subscription': test_subscription},
                            daemon=True,
                    )

        with mock.patch(target='threading.Thread.is_alive') as mock_alive:
            mock_alive.return_value = True
            with mock.patch(target='core.start_consumer_thread') as mock_spawn_thread:
                with mock.patch(target='pubsub.PubSub') as mock_pub_sub:
                    core.start_consumers(subscriptions=subscriptions)

                    mock_spawn_thread.assert_called_with(
                        pub_sub=mock_pub_sub(),
                        subscription=test_subscription
                    )

    @pytest.mark.filterwarnings('ignore::pytest.PytestUnhandledThreadExceptionWarning')
    def test_start_consumers__inexistent_consumer_service(self) -> None:
        test_subscription = ps.Subscription(topic_name='test_topic', consumer_service_name='inexistent')
        subscriptions = (test_subscription,)

        with pytest.raises(ConsumerServiceNotFoundError):
            core.start_consumers(subscriptions=subscriptions)

    def test_create_admin_user__general_case(
        self,
        test_db: Db,
        another_test_db: Db,
        known_salt: bytes,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        APP_ADM_USER = f'{config.TEST_PREFIX}@adm_user.tst'
        APP_ADM_PASSWORD = f'{config.TEST_PREFIX}_adm_passwd'

        monkeypatch.setenv(name='APP_ADM_USER', value=APP_ADM_USER)
        monkeypatch.setenv(name='APP_ADM_PASSWORD', value=APP_ADM_PASSWORD)

        credentials_db = test_db
        credentials_db.database_name = config.USER_CREDENTIALS_DB_NAME
        info_db = another_test_db
        info_db.database_name = config.USER_INFO_DB_NAME

        credentials_db.create()
        info_db.create()
        credentials_db.add_permissions()
        info_db.add_permissions()

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)
        known_hash = utils.calc_hash(SecretStr(APP_ADM_PASSWORD))

        assert credentials_db.check_document(document_id=APP_ADM_USER) is False
        assert info_db.check_document(document_id=APP_ADM_USER) is False

        core.create_admin_user()

        credentials_doc = credentials_db.get_document_by_id(
            document_id=APP_ADM_USER,
        )
        assert credentials_doc is not None
        assert credentials_doc.get('_id') == APP_ADM_USER
        assert credentials_doc.get('hash') == known_hash

        info_doc = info_db.get_document_by_id(
            document_id=APP_ADM_USER,
        )
        assert info_doc is not None
        assert info_doc.get('_id') == APP_ADM_USER
        assert info_doc.get('name') == 'Application Admin User'
        assert 'address' not in info_doc
        assert 'phone_number' not in info_doc
