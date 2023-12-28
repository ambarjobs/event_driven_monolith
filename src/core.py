# ==================================================================================================
#  Application core data structures and functions
# ==================================================================================================
import httpx
import threading as thrd
from fastapi.security import OAuth2PasswordBearer

import config
import services as srv
import pubsub as ps
from database import DatabaseInfo, db, Index


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

# --------------------------------------------------------------------------------------------------
#   PubSub
# --------------------------------------------------------------------------------------------------
APP_CONSUMERS = [
    ps.Subscription(consumer_service=srv.email_confirmation, topic_name='user-signed-in')
]


# ==================================================================================================
#   Initialization
# ==================================================================================================
def init_app_databases() -> None:
    try:
        db.init_databases(database_names=[info.name for info in APP_DATABASES_INFO])
        for db_info in APP_DATABASES_INFO:
            db.create_database_indexes(database_info=db_info)
    except httpx.HTTPError as err:
        print(f'Error trying to initialize the databases: {err}')
        exit(-1)
    except httpx.InvalidURL as err:
        print(f'Invalid database URL: {err}')
        exit(-1)


def start_consumer_thread(pub_sub: ps.PubSub, subscription: ps.Subscription) -> None:
    """Thread to start a consumer."""
    consumer = pub_sub.consumer_factory(
        topic=subscription.topic_name,
        callback=subscription.consumer_service
    )
    consumer.start()


def start_consumers(subscriptions: list[ps.Subscription]) -> None:
    for subscription in subscriptions:
        pub_sub = ps.PubSub()
        thread = thrd.Thread(
            target=start_consumer_thread,
            kwargs={'pub_sub': pub_sub, 'subscription': subscription},
            daemon=True,
            )
        thread.start()
        thread.join(timeout=0.0)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
