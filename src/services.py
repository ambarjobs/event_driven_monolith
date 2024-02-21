# ==================================================================================================
#  Application services
# ==================================================================================================
import asyncio
import csv
import io
import json
import queue
import random
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, UTC
from typing import Any, AsyncIterator, BinaryIO, Iterator

import httpx
from fastapi import status
from jose import ExpiredSignatureError, JWTError
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties
from pydantic import JsonValue, ValidationError
from sse_starlette.sse import ServerSentEvent

import config
import pubsub as ps
import schemas as sch
import output_status as ost
import utils
from config import logging as log
from database import db
from exceptions import InvalidCsvFormatError


MIN_MINUTES_PROCESSING_PAYMENT = 1
MAX_MINUTES_PROCESSING_PAYMENT = 5

CONSUMERS_SUBSCRIPTIONS = (
    ps.Subscription(topic_name='user-signed-up', consumer_service_name='email_confirmation'),
    ps.Subscription(topic_name='email-confirmed', consumer_service_name='enable_user'),
    ps.Subscription(
        topic_name='recipe-purchase-requested',
        consumer_service_name='send_purchase_notification'
    ),
)


# TODO: Substitute with something using CouchDB instead of `queue.SimpleQueue` for scalability.
class NotificationEventsManager:
    """Manages notification event queues mapped for each user."""

    def __init__(self):
        self.users_mapping = defaultdict(queue.SimpleQueue)

    def put(self, user_id: str, data: JsonValue) -> None:
        """Enqueue data on specific `user_id` queue."""
        queue = self.users_mapping[user_id]
        queue.put(ServerSentEvent(data=json.dumps(data)))

    def get(self, user_id: str) -> ServerSentEvent | None:
        """Dequeue data from specific `user_id` queue."""
        queue = self.users_mapping.get(user_id)
        if queue is None or queue.empty():
            return None
        return queue.get_nowait()

    async def generate(self, user_id: str) -> AsyncIterator[ServerSentEvent]:
        """Async generator that provides notification data to SSE on `notifications` endpoint"""
        while True:
            next_notification_event = self.get(user_id=user_id)
            if next_notification_event:
                yield next_notification_event
            await asyncio.sleep(1)


notifications_manager = NotificationEventsManager()


# ==================================================================================================
#   Generic functions
# ==================================================================================================
def user_is_logged_in(db_user_credentials: JsonValue) -> bool:
    """Check if user is logged in."""
    this_moment = datetime.now(tz=UTC)

    last_login = utils.deep_traversal(db_user_credentials, 'last_login')
    return (
        last_login and
        this_moment - datetime.fromisoformat(last_login) <
        timedelta(hours=config.TOKEN_DEFAULT_EXPIRATION_HOURS)
    )

def handle_token(token: str) -> sch.OutputStatus:
    try:
        payload = utils.get_token_payload(token=token)
        content_data = ost.ok_status()
        content_data.details.data = payload
    except (ExpiredSignatureError, JWTError) as err:
        match err:
            case ExpiredSignatureError():
                content_data = ost.expired_token_status()
                content_data.details.description = f'The token has expired, log in again: {err}'
            case JWTError():
                content_data = ost.invalid_token_status()
                content_data.details.description = f'Invalid token: {err}'
    return content_data


# ==================================================================================================
#   Services
# ==================================================================================================

# --------------------------------------------------------------------------------------------------
#   Message delivery
# --------------------------------------------------------------------------------------------------
def stdout_message_delivery(message: str) -> None:
    print(f'\n>>>>> Sending:\n{message}\n', flush=True)

# --------------------------------------------------------------------------------------------------
#   Authentication functionality
# --------------------------------------------------------------------------------------------------
def user_sign_up(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
    base_url: str,
) -> sch.OutputStatus:
    """User sign up service."""
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

            sign_up_producer = ps.PubSub()
            message = sch.EmailConfirmationInfo(
                user_id=credentials.id,
                user_name=user_info.name,
                base_url=base_url,
            ).model_dump_json()
            sign_up_producer.publish(topic='user-signed-up', message=message)

            return ost.successful_sign_up_status()

        output_status = ost.user_already_signed_up_status()
        output_status.details.data = {'version': version}
        return output_status
    except httpx.HTTPStatusError as err:
        return ost.http_error_status(error=err)

def authentication(credentials: sch.UserCredentials) -> sch.OutputStatus:
    """User login service."""
    try:
        db_user_credentials = db.get_document_by_id(
            database_name=config.USER_CREDENTIALS_DB_NAME,
            document_id=credentials.id
        )
    except httpx.HTTPStatusError as err:
        if err.response.status_code == status.HTTP_404_NOT_FOUND:
            # User not found
            return ost.incorrect_login_status()
        return ost.http_error_status(error=err)

    user_hash = utils.deep_traversal(db_user_credentials, 'hash')
    if user_hash is None:
        # User has no hash.
        return ost.incorrect_login_status()

    hash_match = utils.check_password(password=credentials.password, hash_value=user_hash)
    if not hash_match:
        # Invalid password.
        return ost.incorrect_login_status()

    validated  = utils.deep_traversal(db_user_credentials, 'validated')
    if not validated:
        return ost.email_not_validated_status()

    db.upsert_document(
        database_name=config.USER_CREDENTIALS_DB_NAME,
        document_id=credentials.id,
        fields={'last_login': datetime.now(tz=UTC).isoformat()}
    )

    payload: JsonValue = {'sub': credentials.id}
    access_token = utils.create_token(payload=payload)

    logged_in = user_is_logged_in(db_user_credentials=db_user_credentials)
    if logged_in:
        output_status = ost.user_already_logged_in_status()
        output_status.details.data = {'new_token': access_token}
        return output_status

    output_status = ost.successful_logged_in_status()
    output_status.details.data = {'token': access_token}
    return output_status

def get_user_info(user_id: str) -> sch.OutputStatus:
    """Return user info stored in `user-info` database."""
    try:
        db_user_info = db.get_document_by_id(
            database_name=config.USER_INFO_DB_NAME,
            document_id=user_id
        )
    except httpx.HTTPStatusError as err:
        if err.response.status_code == status.HTTP_404_NOT_FOUND:
            # User not found
            return ost.user_info_not_found_status()
        return ost.http_error_status(error=err)

    output_status = ost.get_user_info_status()
    output_status.details.data = db_user_info
    return output_status

# --------------------------------------------------------------------------------------------------
#   Email confirmation functionality
# --------------------------------------------------------------------------------------------------
def email_confirmation(
    channel: BlockingChannel,
    method: Basic.Deliver,
    properties: BasicProperties,
    body: bytes
) -> None:
    """Email confirmation consumer service."""
    email_confirmation_info = sch.EmailConfirmationInfo.model_validate_json(body)
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
    {email_info.confirmation_info.base_url}confirm-email?token={email_info.email_confirmation_token}

    You have {email_info.validation_expiration_period} hours to confirm your subscription.

    Best regards,
    PoC team.
    '''
    stdout_message_delivery(message=message)

    # On tests there is no channel or method because the parameters are mocked
    if channel:
        # Acknowledging the message.
        channel.basic_ack(delivery_tag=method.delivery_tag)

def check_email_confirmation(token: str) -> sch.OutputStatus:
    """Checks the status corresponding to passed email confirmation token and database state."""
    try:
        try:
            token_payload = utils.get_token_payload(token=token)
        except ExpiredSignatureError:
            # It's not possible to get user_info from token payload because it's expired (exception).
            # TODO: Maybe to pass `id` and `name` in addition to token to `confirm_email` endpoint
            #       This would duplicate information inside the token (maybe there is a better
            #       solution).

            # email_confirmation(
            #     channel=None,
            #     method=None,
            #     properties=None,
            #     body=user_info.model_dump()
            # )
            output_status = ost.expired_token_status()
            output_status.details.data = {'token': token}
            return output_status
        except JWTError as err:
            output_status = ost.invalid_token_status()
            output_status.details.data = {'errors': str(err), 'token': token}
            return output_status
        try:
            email_confirmation_info = sch.EmailConfirmationInfo.model_validate(token_payload)
        except ValidationError as err:
            output_status = ost.invalid_token_status()
            output_status.details.data = {'errors': err.errors(), 'token': token}
            return output_status
        user_confirmation = db.get_document_by_fields(
            database_name=config.EMAIL_CONFIRMATION_DB_NAME,
            fields_dict={'_id': email_confirmation_info.user_id, 'email_confirmation_token': token},
            additional_fields=['confirmed_datetime']
        )
        if not user_confirmation:
            output_status = ost.inexistent_token_status()
            output_status.details.data = {
                'token': token,
                'email': email_confirmation_info.user_id
            }
            return output_status
        confirmed_datetime = utils.deep_traversal(user_confirmation, 'confirmed_datetime')
        if confirmed_datetime:
            output_status = ost.previously_confirmed_status()
            output_status.details.data = {
                'confirmation_datetime': confirmed_datetime,
                'email': email_confirmation_info.user_id
            }
            return output_status

        this_moment = datetime.now(tz=UTC)
        confirmation_datetime = this_moment.isoformat()
        db.upsert_document(
            database_name=config.EMAIL_CONFIRMATION_DB_NAME,
            document_id=email_confirmation_info.user_id,
            fields={'confirmed_datetime': confirmation_datetime}
        )

        email_confirmed_producer = ps.PubSub()
        email_confirmed_producer.publish(topic='email-confirmed', message=email_confirmation_info.user_id)
        output_status = ost.confirmed_status()
        output_status.details.data = {'email': email_confirmation_info.user_id, 'name': email_confirmation_info.user_name}
        return output_status
    except httpx.HTTPStatusError as err:
        return ost.http_error_status(error=err)

def enable_user(
    channel: BlockingChannel,
    method: Basic.Deliver,
    properties: BasicProperties,
    body: bytes
) -> None:
    """Mark user email as validated consumer service."""
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

# --------------------------------------------------------------------------------------------------
#   Recipes functionality
# --------------------------------------------------------------------------------------------------
def parse_recipe_data(csv_data: dict[str, Any]) -> sch.Recipe:
    """Parse a record of recipe read from .csv into a `Recipe` schema.

    recipe_data: {
        'name':         str                                     =>  'summary.name'
        'description':  str                                     =>  'summary.description'
        'category':     str                                     =>  'category'
        'easiness':     str ('easy', 'medium', 'hard')          =>  'easiness'
        'price':        float                                   =>  'price'
        'tags':         list[str] (items separated by '|')      =>  'tags'
        'ingredients':  list[str] (items separated by '|')      =>  'recipe.ingredients'
        'directions':   str (lines separated by '|')            =>  'recipe.directions'
                        slugify(name)                           =>  'id'
                        datetime.now()                          =>  'modif_time'
    }
    """
    required_fields = [
        'name',
        'description',
        'category',
        'easiness',
        'price',
        'tags',
        'ingredients',
        'directions'
    ]

    if None in csv_data.values() or (set(csv_data) < set(required_fields)):
        raise InvalidCsvFormatError

    description = '\n'.join(
        utils.split_or_empty(csv_data['description'], separator=config.CSV_LIST_SEPARATOR)
    )
    summary = sch.RecipeSummary(name=csv_data['name'], description=description)

    recipe_direct_data = {
        key: value for key, value in csv_data.items() if key in ('category', 'easiness', 'price')
    }

    tags = utils.split_or_empty(csv_data['tags'], separator=config.CSV_LIST_SEPARATOR)
    ingredients = utils.split_or_empty(csv_data['ingredients'], separator=config.CSV_LIST_SEPARATOR)
    directions = '\n'.join(
        utils.split_or_empty(csv_data['directions'], separator=config.CSV_LIST_SEPARATOR)
    )

    recipe_info = sch.RecipeInformation(ingredients=ingredients, directions=directions)
    parsed_recipe = sch.Recipe(
        summary=summary,
        **recipe_direct_data,
        tags=tags,
        recipe=recipe_info,
        status=sch.RecipeStatus.available,
    )
    return parsed_recipe

def import_csv_recipes(csv_file: BinaryIO) -> sch.OutputStatus:
    """Read a .csv file and return a list of schema objects representing the recipes."""
    csv_text_file = io.TextIOWrapper(csv_file, encoding=config.APP_ENCODING_FORMAT)
    recipe_reader = csv.DictReader(
        csv_text_file,
        fieldnames=[
            'name',
            'description',
            'category',
            'easiness',
            'price',
            'tags',
            'ingredients',
            'directions'
        ],
        delimiter=config.CSV_FIELD_SEPARATOR,
    )
    try:
        recipes_data = [parse_recipe_data(recipe) for recipe in recipe_reader]
    except InvalidCsvFormatError:
        return ost.invalid_csv_format_status()
    except ValidationError as err:
        output_status = ost.invalid_csv_content_status()
        output_status.details.data = {'errors': err.errors()}
        return output_status
    output_status = ost.imported_csv_status()
    output_status.details.data = {'recipes': recipes_data}
    return output_status

def store_recipe(recipe: sch.Recipe) -> sch.OutputStatus:
    """Stores the recipe on database."""
    db_recipe = recipe.to_json()
    recipe_id = db_recipe.pop('id')
    try:
        db.upsert_document(
            database_name=config.RECIPES_DB_NAME,
            document_id=recipe_id,
            fields=db_recipe
        )
        return ost.recipe_stored_status()
    except httpx.HTTPStatusError as err:
        error_status = ost.http_error_status(error=err)
        error_status.status = 'error_storing_recipe'
        error_status.details.description = 'An error ocurred trying to store the recipe.'
        return error_status

def get_all_recipes() -> sch.OutputStatus:
    """Return all recipes on `recipe` database."""
    recipes_fields = [field for field in sch.Recipe.model_fields if field != 'recipe']
    try:
        db_all_recipes = db.get_all_documents(
            database_name=config.RECIPES_DB_NAME,
            fields=recipes_fields,
        )
        output_status = ost.all_recipes_status()
        output_status.details.data = {
            'all_recipes': [sch.Recipe.from_record(record=db_recipe)
            for db_recipe in db_all_recipes]
        }
        return output_status
    except httpx.HTTPStatusError as err:
        service_status = ost.error_retrieving_all_recipes_status()
        error_status = ost.http_error_status(error=err)
        error_status.status = service_status.status
        error_status.details.description = service_status.details.description
        return error_status

def get_user_recipes(user_id: str) -> sch.OutputStatus:
    """Return user recipes on `user-recipe` database."""
    try:
        db_user_recipes = db.get_document_by_id(
            database_name=config.USER_RECIPES_DB_NAME,
            document_id=user_id
        )
        user_recipes = utils.deep_traversal(db_user_recipes, 'recipes')
        output_status = ost.user_recipes_status()
        output_status.details.data = {
            'user_recipes': [sch.UserRecipe(**recipe) for recipe in user_recipes]
        }
        return output_status
    except httpx.HTTPStatusError as err:
        service_status = ost.error_retrieving_user_recipes_status()
        error_status = ost.http_error_status(error=err)
        error_status.status = service_status.status
        error_status.details.description = service_status.details.description
        return error_status

def get_specific_recipe(recipe_id: str) -> sch.OutputStatus:
    """Return an specific recipe from `recipe` database."""
    try:
        db_recipe = db.get_document_by_id(
            database_name=config.RECIPES_DB_NAME,
            document_id=recipe_id,
        )
        output_status = ost.specific_recipe_status()
        output_status.details.data = {'recipe': sch.Recipe.from_record(record=db_recipe)}
        return output_status
    except httpx.HTTPStatusError as err:
        service_status = ost.error_retrieving_specific_recipe_status()
        error_status = ost.http_error_status(error=err)
        error_status.status = service_status.status
        error_status.details.description = service_status.details.description
        return error_status

# --------------------------------------------------------------------------------------------------
#   Purchasing functionality
# --------------------------------------------------------------------------------------------------
def start_checkout(user_id: str, recipe_id: str, payment_encr_info: bytes) -> sch.OutputStatus:
    """Start the checkout process for purchasing a recipe."""
    body = sch.PaymentCheckoutInfo(
        payment_encr_info=sch.PaymentEncrInfo(encr_info=payment_encr_info),
        api_key=config.PAYMENT_PROVIDER_API_KEY
    ).model_dump()

    try:
        checkout_response = httpx.post(
            url=f'{config.PAYMENT_PROVIDER_CHECKOUT_URL}{recipe_id}',
            json=body,
        ).raise_for_status()

        checkout_response_json = checkout_response.json()
        if utils.deep_traversal(checkout_response_json, 'error'):
            return sch.OutputStatus(**checkout_response_json)
    except httpx.HTTPStatusError as err:
        return ost.http_error_status(error=err)

    checkout_id = utils.deep_traversal(checkout_response_json, 'details', 'data', 'checkout_id')

    if not checkout_id:
        return ost.api_invalid_checkout_id_error_status()

    db.upsert_document(
        database_name=config.PAYMENT_DB_NAME,
        document_id=checkout_id,
        fields={'user_id': user_id}
    )

    recipe_purchase_producer = ps.PubSub()
    message = sch.RecipePurchaseInfo(user_id=user_id, recipe_id=recipe_id).model_dump_json()
    recipe_purchase_producer.publish(topic='recipe-purchase-requested', message=message)

    return ost.start_checkout_status()

def update_payment_status(
    checkout_id: str,
    webhook_payment_info: sch.WebhookPaymentInfo
) -> sch.OutputStatus:
    """Process payment provider's payment status notification."""
    try:
        checkout_db_data = db.get_document_by_id(
            database_name=config.PAYMENT_DB_NAME,
            document_id=checkout_id
        )
    except httpx.HTTPStatusError:
        output_status = ost.update_payment_status_checkout_not_found_status()
        log.error(msg=output_status.details.description)
        return output_status

    user_id = checkout_db_data['user_id']

    db_fields = webhook_payment_info.model_dump()
    db_fields['user_id'] = user_id

    db.upsert_document(
        database_name=config.PAYMENT_DB_NAME,
        document_id=checkout_id,
        fields=db_fields
    )

    update_payment_status_producer = ps.PubSub()
    message = sch.PurchaseStatusInfo(
        user_id=user_id,
        recipe_id=webhook_payment_info.recipe_id,
        payment_status=webhook_payment_info.payment_status,
    ).model_dump_json()
    update_payment_status_producer.publish(topic='purchase-status-changed', message=message)

    log.info(
        f'Payment status of [{webhook_payment_info.payment_id}] changed'
        f' to {webhook_payment_info.payment_status}'
    )

    return ost.update_payment_status_status()


# --------------------------------------------------------------------------------------------------
#   Payment Provider Simulator
# --------------------------------------------------------------------------------------------------
def payment_processing(checkout_id: str, recipe_id: str) -> sch.OutputStatus:
    """Notify application payment webhook of result of payment process."""
    minutes_processing = random.randint(
        MIN_MINUTES_PROCESSING_PAYMENT,
        MAX_MINUTES_PROCESSING_PAYMENT
    )
    payment_id = str(uuid.uuid4())
    payment_status = sch.PaymentStatus.PAID

    # Simulating payment processing.
    time.sleep(minutes_processing * 60)

    webhook_payment_info = sch.WebhookPaymentInfo(
        recipe_id=recipe_id,
        payment_id=payment_id,
        payment_status=payment_status,
    )

    try:
        webhook_response = httpx.post(
            url=f'{config.APP_WEBHOOK_URL}{checkout_id}',
            json=webhook_payment_info.model_dump(),
        ).raise_for_status()

        webhook_response_json = webhook_response.json()
        if utils.deep_traversal(webhook_response_json, 'error'):
            output_status = ost.error_accessing_app_webhook_status()
            output_status.details.data = utils.deep_traversal(
                webhook_response_json,
                'details',
                'data'
            ) or {}
            output_status.details.error_code = utils.deep_traversal(
                webhook_response_json,
                'details',
                'error_code'
            )
            return sch.OutputStatus(**output_status.model_dump())
    except httpx.HTTPStatusError as err:
        return ost.http_error_status(error=err)
    return ost.payment_processing_status()


# --------------------------------------------------------------------------------------------------
#   Purchase events handling functionality
# --------------------------------------------------------------------------------------------------
def error_response_generator(output_status: sch.OutputStatus) -> Iterator[ServerSentEvent]:
    """Generator to deliver an error response content through SSE."""
    yield ServerSentEvent(data=json.dumps(output_status.model_dump()))

def send_purchase_notification(
    channel: BlockingChannel,
    method: Basic.Deliver,
    properties: BasicProperties,
    body: bytes
) -> None:
    """Send notification by SSE about a recipe purchased currently."""
    recipe_purchase_info = sch.RecipePurchaseInfo.model_validate_json(body)

    all_recipes_status = get_all_recipes()
    if all_recipes_status.error:
        notification = sch.Notification(
            event_name='error',
            user_id=recipe_purchase_info.user_id,
            data=all_recipes_status.details.data
        )
        return

    all_recipes = utils.deep_traversal(all_recipes_status.details.data, 'all_recipes')
    purchased_recipe = utils.first(
        seq=[recipe for recipe in all_recipes if recipe.id == recipe_purchase_info.recipe_id]
    )
    if not purchased_recipe:
        notification = sch.Notification(
            event_name='error',
            user_id=recipe_purchase_info.user_id,
            data={'errors': ['recipe not found']}
        )
        return

    user_info_status = get_user_info(user_id=recipe_purchase_info.user_id)
    user_info = user_info_status.details.data

    notification_info = sch.RecipePurchaseRequestInfo(
        user_name=user_info.get('name', ''),
        recipe_id=purchased_recipe.id,
        recipe_name=purchased_recipe.summary.name
    )

    notification = sch.Notification(
        event_name='recipe-purchase-requested',
        user_id=recipe_purchase_info.user_id,
        data=notification_info.model_dump()
    )

    notifications_manager.put(user_id=recipe_purchase_info.user_id, data=notification.model_dump())

    # On tests there is no channel or method because the parameters are mocked
    if channel:
        # Acknowledging the message.
        channel.basic_ack(delivery_tag=method.delivery_tag)
