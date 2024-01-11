# ==================================================================================================
#  Application core data structures and functions
# ==================================================================================================
import os
from collections.abc import Sequence

import httpx
import threading as thrd
from fastapi.security import OAuth2PasswordBearer
from pydantic import SecretStr

import config
import pubsub as ps
import services as srv
import utils
from config import logging as log
from database import DatabaseInfo, db, Index
from exceptions import ConsumerServiceNotFoundError, InvalidAppAdminCredentialsError


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


def create_admin_user() -> None:
    """Create administrative application user."""
    adm_user = os.getenv('APP_ADM_USER')
    adm_passwd = os.getenv('APP_ADM_PASSWORD')
    if not adm_user or not adm_passwd:
        msg = 'Invalid application administrator credentials'
        log.error(msg=msg)
        raise InvalidAppAdminCredentialsError(msg)
    hash_ = utils.calc_hash(SecretStr(adm_passwd))

    db.upsert_document(
        database_name=config.USER_CREDENTIALS_DB_NAME,
        document_id=adm_user,
        fields={'hash': hash_, 'validated': True}
    )

    db.upsert_document(
        database_name=config.USER_INFO_DB_NAME,
        document_id=adm_user,
        fields={'name': 'Application Admin User'}
    )


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
