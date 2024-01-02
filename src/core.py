# ==================================================================================================
#  Application core data structures and functions
# ==================================================================================================
from collections.abc import Sequence

import httpx
import threading as thrd
from fastapi.security import OAuth2PasswordBearer

import config
import pubsub as ps
import services as srv
from config import logging as log
from database import DatabaseInfo, db, Index
from exceptions import ConsumerServiceNotFoundError


# ==================================================================================================
#   Data structures
# ==================================================================================================

# --------------------------------------------------------------------------------------------------
#   Databases
# --------------------------------------------------------------------------------------------------
APP_DATABASES_INFO = [
    DatabaseInfo(
        name=config.USER_CREDENTIALS_DB_NAME,
        indexes=[Index(name=f'{config.USER_CREDENTIALS_DB_NAME}-id--index', fields=['_id'])]
    ),
    DatabaseInfo(
        name=config.USER_INFO_DB_NAME,
        indexes=[Index(name=f'{config.USER_INFO_DB_NAME}-id--index', fields=['_id'])]),
    DatabaseInfo(
        name=config.EMAIL_CONFIRMATION_DB_NAME,
        indexes=[
            Index(name=f'{config.EMAIL_CONFIRMATION_DB_NAME}-id--index', fields=['_id']),
            Index(
                name=f'{config.EMAIL_CONFIRMATION_DB_NAME}-id--email-confirmation-token--index',
                fields=['_id', 'email_confirmation_token']
            )
        ]
    )
]

# ==================================================================================================
#   Initialization
# ==================================================================================================
def init_app_databases(databases_info: Sequence[DatabaseInfo]) -> None:
    try:
        db.init_databases(database_names=[info.name for info in databases_info])
        for db_info in databases_info:
            db.create_database_indexes(database_info=db_info)
    except httpx.HTTPError as err:
        error_msg = f'Error trying to initialize the databases: {err}'
        print(error_msg)
        exit(-1)
    except httpx.InvalidURL as err:
        error_msg = f'Invalid database URL: {err}'
        print(error_msg)
        exit(-1)


def start_consumer_thread(pub_sub: ps.PubSub, subscription: ps.Subscription) -> None:
    """Thread to start a consumer."""
    try:
        callback = getattr(srv, subscription.consumer_service_name)
    except AttributeError:
        exit(-1)
    consumer = pub_sub.consumer_factory(
        topic=subscription.topic_name,
        callback=callback
    )
    consumer.start()


def start_consumers(subscriptions: Sequence[ps.Subscription]) -> None:
    for subscription in subscriptions:
        pub_sub = ps.PubSub()
        thread = thrd.Thread(
            target=start_consumer_thread,
            kwargs={'pub_sub': pub_sub, 'subscription': subscription},
            daemon=True,
            )
        thread.start()
        log.info(f'Starting consumer thread: {thread.native_id}')
        thread.join(timeout=0.01)
        if not thread.is_alive():
            raise ConsumerServiceNotFoundError(
                f'The consumer service function [{subscription.consumer_service_name}] '
                'could not be found.'
        )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
