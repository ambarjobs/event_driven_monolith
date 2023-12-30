# ==================================================================================================
#  Core module tests
# ==================================================================================================
import httpx
# import threading
from unittest import mock

import config
import core
import pubsub as ps
import utils
from database import DatabaseInfo, db, Index
from tests.helpers import access_database

class TestCore:
    # ----------------------------------------------------------------------------------------------
    #   Databases initialization
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

        with mock.patch(target='core.start_consumer_thread') as mock_spawn_thread:
            with mock.patch(target='pubsub.PubSub') as mock_pub_sub:
                core.start_consumers(subscriptions=subscriptions)

                mock_spawn_thread.assert_called_with(
                    pub_sub=mock_pub_sub(),
                    subscription=test_subscription
                )
