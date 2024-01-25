# ==================================================================================================
#  Application services
# ==================================================================================================
import csv
import io
from datetime import datetime, timedelta, UTC
from typing import Any, BinaryIO

import httpx
from fastapi import status
from jose import ExpiredSignatureError, JWTError
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties
from pydantic import ValidationError

import config
import pubsub as ps
import schemas as sch
import utils
from database import db
from exceptions import InvalidCsvFormatError


CONSUMERS_SUBSCRIPTIONS = (
    ps.Subscription(topic_name='user-signed-up', consumer_service_name='email_confirmation'),
    ps.Subscription(topic_name='email-confirmed', consumer_service_name='enable_user'),
)

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

def handle_token(token: str) -> sch.ServiceStatus:
    # ------------------------------------------------------------------------------------------
    #   Output status
    # ------------------------------------------------------------------------------------------
    ok_status = sch.ServiceStatus(
        status='OK',
        error=False,
        details=sch.StatusDetails(
            description='OK.',
        ),
    )

    invalid_token_status = sch.ServiceStatus(
        status='invalid_token',
        error=True,
        details=sch.StatusDetails(
            description='Invalid token.',
        ),
    )

    expired_token_status = sch.ServiceStatus(
        status='expired_token',
        error=True,
        details=sch.StatusDetails(
            description='The token has expired.',
        ),
    )
    # ------------------------------------------------------------------------------------------
    try:
        payload = utils.get_token_payload(token=token)
        content_data = ok_status
        content_data.details.data = payload
    except (ExpiredSignatureError, JWTError) as err:
        match err:
            case ExpiredSignatureError():
                content_data = expired_token_status
                content_data.details.description = f'The token has expired, log in again: {err}'
            case JWTError():
                content_data = invalid_token_status
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
#   Sign in
# --------------------------------------------------------------------------------------------------
def user_sign_up(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
    base_url: str,
) -> sch.ServiceStatus:
    """User sign up service."""
    # ----------------------------------------------------------------------------------------------
    #   Output status
    # ----------------------------------------------------------------------------------------------
    successful_sign_up_status = sch.ServiceStatus(
            status='successful_sign_up',
            error=False,
            details=sch.StatusDetails(description='User signed up successfully.'),
        )

    user_already_signed_up_status = sch.ServiceStatus(
            status='user_already_signed_up',
            error=True,
            details=sch.StatusDetails(description='User already signed up.'),
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

            sign_up_producer = ps.PubSub()
            message = sch.EmailConfirmationInfo(
                user_id=credentials.id,
                user_name=user_info.name,
                base_url=base_url,
            ).model_dump_json()
            sign_up_producer.publish(topic='user-signed-up', message=message)

            return successful_sign_up_status

        user_already_signed_up_status.details.data = {'version': version}
        return user_already_signed_up_status
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
        successful_logged_in_status = sch.ServiceStatus(
            status='successfully_logged_in',
            error=False,
            details=sch.StatusDetails(description='User has successfully logged in.'),
        )

        # Some situations below are aggregated into the same message in manner to avoid
        # username prospecting.
        incorrect_login_status = sch.ServiceStatus(
            status='incorrect_login_credentials',
            error=True,
            details=sch.StatusDetails(
                description='Invalid user or password. Check if user has signed up.'
            ),
        )

        email_not_validated_status = sch.ServiceStatus(
            status='email_not_validated',
            error=True,
            details=sch.StatusDetails(description='User email is not validated.'),
        )

        user_already_logged_in_status = sch.ServiceStatus(
            status='user_already_logged_in',
            error=False,
            details=sch.StatusDetails(
                description='User was already logged in and last token is still valid.'
            ),
        )
        # ------------------------------------------------------------------------------------------

        try:
            db_user_credentials = db.get_document_by_id(
                database_name=config.USER_CREDENTIALS_DB_NAME,
                document_id=credentials.id
            )
        except httpx.HTTPStatusError as err:
            if err.response.status_code == status.HTTP_404_NOT_FOUND:
                # User not found
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

        db.upsert_document(
            database_name=config.USER_CREDENTIALS_DB_NAME,
            document_id=credentials.id,
            fields={'last_login': datetime.now(tz=UTC).isoformat()}
        )

        payload = {'sub': credentials.id}
        access_token = utils.create_token(payload=payload)

        logged_in = user_is_logged_in(db_user_credentials=db_user_credentials)
        if logged_in:
            user_already_logged_in_status.details.data = {'new_token': access_token}
            return user_already_logged_in_status

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

def check_email_confirmation(token: str) -> sch.ServiceStatus:
    """Checks the status corresponding to passed email confirmation token and database state."""
    # ------------------------------------------------------------------------------------------
    #   Output status
    # ------------------------------------------------------------------------------------------
    confirmed_status = sch.ServiceStatus(
        status='confirmed',
        error=False,
        details=sch.StatusDetails(
            description='Email confirmed.'
        ),
    )

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
    # ------------------------------------------------------------------------------------------

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

        email_confirmed_producer = ps.PubSub()
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
#   Recipes
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

    if None in csv_data.values() or (set(csv_data.keys()) < set(required_fields)):
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

def import_csv_recipes(csv_file: BinaryIO) -> sch.ServiceStatus:
    """Read a .csv file and return a list of schema objects representing the recipes."""
    # ----------------------------------------------------------------------------------------------
    #   Output status
    # ----------------------------------------------------------------------------------------------
    imported_csv_status = sch.ServiceStatus(
        status='csv_imported',
        error=False,
        details=sch.StatusDetails(
            description='CSV recipes file imported successfully.'
        ),
    )

    invalid_csv_format_status = sch.ServiceStatus(
        status='invalid_csv_format',
        error=True,
        details=sch.StatusDetails(
            description='The format of the CSV file is invalid.'
        ),
    )

    invalid_csv_content_status = sch.ServiceStatus(
        status='invalid_csv_content',
        error=True,
        details=sch.StatusDetails(
            description='The content of the CSV file is invalid.'
        ),
    )
    # ----------------------------------------------------------------------------------------------
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
        return invalid_csv_format_status
    except ValidationError as err:
        invalid_csv_content_status.details.data = {'errors': err.errors()}
        return invalid_csv_content_status
    imported_csv_status.details.data = {'recipes': recipes_data}
    return imported_csv_status

def store_recipe(recipe: sch.Recipe) -> None:
    """Stores the recipe on database."""
    db_recipe = recipe.to_json()
    recipe_id = db_recipe.pop('id')
    db.upsert_document(
        database_name=config.RECIPES_DB_NAME,
        document_id=recipe_id,
        fields=db_recipe
    )

def get_all_recipes() -> list[sch.Recipe]:
    """Return all recipes on `recipe` database."""
    recipes_fields = [field for field in sch.Recipe.model_fields if field != 'recipe']
    db_all_recipes = db.get_all_documents(
        database_name=config.RECIPES_DB_NAME,
        fields=recipes_fields,
    )
    return [sch.Recipe.from_record(record=db_recipe) for db_recipe in db_all_recipes]

def get_user_recipes(user_id: str) -> list[sch.UserRecipe]:
    """Return user recipes on `user-recipe` database."""
    db_user_recipes = db.get_document_by_id(
        database_name=config.USER_RECIPES_DB_NAME,
        document_id=user_id
    )

    user_recipes = utils.deep_traversal(db_user_recipes, 'recipes')
    return [sch.UserRecipe(**recipe) for recipe in user_recipes]
