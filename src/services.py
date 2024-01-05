# ==================================================================================================
#  Application services
# ==================================================================================================
from datetime import datetime, timedelta, UTC
from typing import Any

import httpx
from fastapi import status
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties
from pydantic import ValidationError

import config
import pubsub as ps
import schemas as sch
import utils
from database import db
from exceptions import ProducerNotRegisteredError
from jose import ExpiredSignatureError, JWTError


CONSUMERS_SUBSCRIPTIONS = (
    ps.Subscription(topic_name='user-signed-in', consumer_service_name='email_confirmation'),
    ps.Subscription(topic_name='email-confirmed', consumer_service_name='enable_user'),
)

PRODUCERS_NAMES = (
    'user_sign_in',
    'email-confirmed',
)
REGISTERED_PRODUCERS = {producer_name: ps.PubSub() for producer_name in PRODUCERS_NAMES}

# --------------------------------------------------------------------------------------------------
#   Normalized HTTP error status
# --------------------------------------------------------------------------------------------------
def http_error_status(error: httpx.HTTPStatusError) -> sch.ServiceStatus:
    """Return normalized HTTP error data."""
    error_status = sch.ServiceStatus(
            status='http_error',
            error=True,
            details=sch.StatusDetails(
                description='',
            ),
        )
    error_status.details.description = str(error)
    error_status.details.data = {'errors': error.response.json()}
    error_status.details.error_code = error.response.status_code
    return error_status


# ==================================================================================================
#   Generic functions
# ==================================================================================================
def user_is_logged_in(db_user_credentials: dict[str, Any]) -> bool:
    """Check if user is logged in."""
    this_moment = datetime.now(tz=UTC)

    last_login = utils.deep_traversal(db_user_credentials, 'last_login')
    return (
        last_login and
        this_moment - datetime.fromisoformat(last_login) <
        timedelta(hours=config.TOKEN_DEFAULT_EXPIRATION_HOURS)
    )


def get_producer(producer_name: str) -> ps.PubSub:
    """Get the PubSub instance of a registered producer."""
    producer = REGISTERED_PRODUCERS.get(producer_name)
    if not producer:
        raise ProducerNotRegisteredError(f'Producer [{producer_name}] not registered.')
    return producer

# ==================================================================================================
#   Services
# ==================================================================================================

# --------------------------------------------------------------------------------------------------
#   Message delivery
# --------------------------------------------------------------------------------------------------
def stdout_message_delivery(message: str) -> None:
    print(f'\n>>>>> Sending:\n{message}\n', flush=True)

# --------------------------------------------------------------------------------------------------
#   Sign in
# --------------------------------------------------------------------------------------------------
def user_sign_in(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
    base_url: str,
) -> sch.ServiceStatus:
    """User sign in service."""
    # ----------------------------------------------------------------------------------------------
    #   Output status
    # ----------------------------------------------------------------------------------------------
    successful_sign_in_status = sch.ServiceStatus(
            status='successful_sign_in',
            error=False,
            details=sch.StatusDetails(description='User signed in successfully.'),
        )

    user_already_signed_in_status = sch.ServiceStatus(
            status='user_already_signed_in',
            error=True,
            details=sch.StatusDetails(description='User already signed in.'),
        )
    # ----------------------------------------------------------------------------------------------

    try:
        version = db.check_document_available(
            database_name=config.USER_CREDENTIALS_DB_NAME,
            document_id=credentials.id
        )
        if version is None:
            hash_ = utils.calc_hash(credentials.password)

            db.upsert_document(
                database_name=config.USER_CREDENTIALS_DB_NAME,
                document_id=credentials.id,
                fields={'hash': hash_}
            )

            fields = utils.clear_nulls(user_info.model_dump(exclude={'id'}))
            db.upsert_document(
                database_name=config.USER_INFO_DB_NAME,
                document_id=credentials.id,
                fields=fields
            )

            sign_in_producer = get_producer('user_sign_in')
            message = sch.EmailConfirmationInfo(
                user_id=credentials.id,
                user_name=user_info.name,
                base_url=base_url,
            ).model_dump_json()
            sign_in_producer.publish(topic='user-signed-in', message=message)

            return successful_sign_in_status

        user_already_signed_in_status.details.data = {'version': version}
        return user_already_signed_in_status
    except httpx.HTTPStatusError as err:
        return http_error_status(error=err)

# --------------------------------------------------------------------------------------------------
#   Login
# --------------------------------------------------------------------------------------------------
def authentication(credentials: sch.UserCredentials) -> sch.ServiceStatus:
    """User login service."""
    try:
        # ------------------------------------------------------------------------------------------
        #   Output status
        # ------------------------------------------------------------------------------------------
        # Some situations below are aggregated into the same message in manner to avoid
        # username prospection.
        incorrect_login_status = sch.ServiceStatus(
            status='incorrect_login_credentials',
            error=True,
            details=sch.StatusDetails(
                description='Invalid user or password. Check if user has signed in.'
            ),
        )

        email_not_validated_status = sch.ServiceStatus(
            status='email_not_validated',
            error=True,
            details=sch.StatusDetails(description='User email is not validated.'),
        )

        user_already_logged_in_status = sch.ServiceStatus(
            status='user_already_signed_in',
            error=True,
            details=sch.StatusDetails(description='User was already logged in.'),
        )

        successful_logged_in_status = sch.ServiceStatus(
            status='successfully_logged_in',
            error=False,
            details=sch.StatusDetails(description='User has successfully logged in.'),
        )
        # ------------------------------------------------------------------------------------------

        try:
            db_user_credentials = db.get_document_by_id(
                database_name=config.USER_CREDENTIALS_DB_NAME,
                document_id=credentials.id
            )
        except httpx.HTTPStatusError as err:
            if err.response.status_code == status.HTTP_404_NOT_FOUND:
                # Usuário não encontrado
                return incorrect_login_status
            return http_error_status(error=err)

        user_hash = utils.deep_traversal(db_user_credentials, 'hash')
        if user_hash is None:
            # User has no hash.
            return incorrect_login_status

        hash_match = utils.check_password(password=credentials.password, hash_value=user_hash)
        if not hash_match:
            # Invalid password.
            return incorrect_login_status

        validated  = utils.deep_traversal(db_user_credentials, 'validated')
        if not validated:
            return email_not_validated_status

        logged_in = user_is_logged_in(db_user_credentials=db_user_credentials)
        if logged_in:
            return user_already_logged_in_status

        payload = {'sub': credentials.id}
        access_token = utils.create_token(payload=payload)
        db.upsert_document(
            database_name=config.USER_CREDENTIALS_DB_NAME,
            document_id=credentials.id,
            fields={'last_login': datetime.now(tz=UTC).isoformat()}
        )

        successful_logged_in_status.details.data = {'token': access_token}
        return successful_logged_in_status
    except httpx.HTTPStatusError as err:
        return http_error_status(error=err)

# --------------------------------------------------------------------------------------------------
#   Email confirmation
# --------------------------------------------------------------------------------------------------
def email_confirmation(
    channel: BlockingChannel,
    method: Basic.Deliver,
    properties: BasicProperties,
    body: bytes
) -> None:
    """Email confirmation service."""
    email_confirmation_info = sch.EmailConfirmationInfo.model_validate_json(body)
    email_confirmation_info.base_url = None
    token = utils.create_token(
        payload=email_confirmation_info.model_dump(),
        expiration_hours=config.EMAIL_VALIDATION_TIMEOUT_HOURS
    )

    db.upsert_document(
        database_name=config.EMAIL_CONFIRMATION_DB_NAME,
        document_id=email_confirmation_info.user_id,
        fields={'email_confirmation_token': token}
    )

    email_info = sch.EmailConfirmationMessageInfo(
        confirmation_info=email_confirmation_info,
        validation_expiration_period=config.EMAIL_VALIDATION_TIMEOUT_HOURS,
        email_confirmation_token=token,
    )

    message = f'''Dear {email_info.confirmation_info.user_name}, thank you for subscribing this PoC.

    To confirm you subscription, please access the following link:
    {email_info.confirmation_info.base_url}/confirm-email/{email_info.email_confirmation_token}

    You have {email_info.validation_expiration_period} hours to confirm your subscription.

    Best regards,
    PoC team.
    '''
    stdout_message_delivery(message=message)

    # On tests there is no channel or method because the parameters are mocked
    if channel:
        # Acknowledging the message.
        channel.basic_ack(delivery_tag=method.delivery_tag)

def check_email_confirmation(token: str) -> sch.ServiceStatus:
    """Checks the status corresponding to passed email confirmation token and database state."""
    # ------------------------------------------------------------------------------------------
    #   Output status
    # ------------------------------------------------------------------------------------------
    invalid_token_status = sch.ServiceStatus(
        status='invalid_token',
        error=True,
        details=sch.StatusDetails(
            description='Invalid token.'
        ),
    )

    inexistent_token_status = sch.ServiceStatus(
        status='inexistent_token',
        error=True,
        details=sch.StatusDetails(
            description='Inexistent token for the user id.'
        ),
    )

    expired_token_status = sch.ServiceStatus(
        status='expired_token',
        error=True,
        details=sch.StatusDetails(
            description='The token has expired.'
        ),
    )

    previously_confirmed_status = sch.ServiceStatus(
        status='previously_confirmed',
        error=True,
        details=sch.StatusDetails(
            description='The email was already confirmed.'
        ),
    )

    confirmed_status = sch.ServiceStatus(
        status='confirmed',
        error=False,
        details=sch.StatusDetails(
            description='Email confirmed.'
        ),
    )
    # ------------------------------------------------------------------------------------------

    try:
        try:
            token_payload = utils.get_token_payload(token=token)
        except ExpiredSignatureError:
            # It's not possible to get user_info from token payload beacuse it's expired (exception).
            # TODO: Maybe to pass `id` and `name` in addition to token to `confirm_email` endpoint
            #       This would duplicate information inside the token (maybe there is a better
            #       solution).

            # email_confirmation(
            #     channel=None,
            #     method=None,
            #     properties=None,
            #     body=user_info.model_dump()
            # )
            expired_token_status.details.data = {'token': token}
            return expired_token_status
        except JWTError as err:
            invalid_token_status.details.data = {'errors': str(err), 'token': token}
            return invalid_token_status
        try:
            email_confirmation_info = sch.EmailConfirmationInfo.model_validate(token_payload)
        except ValidationError as err:
            invalid_token_status.details.data = {'errors': err.errors(), 'token': token}
            return invalid_token_status
        user_confirmation = db.get_document_by_fields(
            database_name=config.EMAIL_CONFIRMATION_DB_NAME,
            fields_dict={'_id': email_confirmation_info.user_id, 'email_confirmation_token': token},
            additional_fields=['confirmed_datetime']
        )
        if not user_confirmation:
            inexistent_token_status.details.data = {
                'token': token,
                'email': email_confirmation_info.user_id
            }
            return inexistent_token_status
        confirmed_datetime = utils.deep_traversal(user_confirmation, 'confirmed_datetime')
        if confirmed_datetime:
            previously_confirmed_status.details.data = {
                'confirmation_datetime': confirmed_datetime,
                'email': email_confirmation_info.user_id
            }
            return previously_confirmed_status

        this_moment = datetime.now(tz=UTC)
        confirmation_datetime = this_moment.isoformat()
        db.upsert_document(
            database_name=config.EMAIL_CONFIRMATION_DB_NAME,
            document_id=email_confirmation_info.user_id,
            fields={'confirmed_datetime': confirmation_datetime}
        )

        # Awaiting consumer implementation.
        email_confirmed_producer = get_producer('email-confirmed')
        email_confirmed_producer.publish(topic='email-confirmed', message=email_confirmation_info.user_id)
        confirmed_status.details.data = {'email': email_confirmation_info.user_id, 'name': email_confirmation_info.user_name}
        return confirmed_status
    except httpx.HTTPStatusError as err:
        return http_error_status(error=err)

def enable_user(
    channel: BlockingChannel,
    method: Basic.Deliver,
    properties: BasicProperties,
    body: bytes
) -> None:
    """Mark user email as validated."""
    user_id = body.decode(config.APP_ENCODING_FORMAT)

    db.upsert_document(
        database_name=config.USER_CREDENTIALS_DB_NAME,
        document_id=user_id,
        fields={'validated': True}
    )

    # On tests there is no channel or method because the parameters are mocked
    if channel:
        # Acknowledging the message.
        channel.basic_ack(delivery_tag=method.delivery_tag)
