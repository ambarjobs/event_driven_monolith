# ==================================================================================================
#  Tests fixtures
# ==================================================================================================
import io
from datetime import datetime, UTC
from typing import Any

import pytest
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties
from pydantic import SecretStr

import config
import output_status as ost
import pubsub as ps
import schemas as sch
import services as srv
import utils
from database import DbCredentials
from tests.helpers import Db


# --------------------------------------------------------------------------------------------------
#   Hashing
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def password() -> SecretStr:
    """General test password."""
    return SecretStr('A_complex-password#%1234')

@pytest.fixture
def known_salt() -> bytes:
    """Salt used to generate a known hash from a known password."""
    return b'$2b$12$Og1J/Lxkk95WVFDThqRGPe'

@pytest.fixture
def known_hash() -> str:
    """Hash generated with the known_salt and general test password."""
    return (
        '243262243132244f67314a2f4c786b6b3935575646445468715247506552'
        '4f51674243702f426f6c495747562e7072493576364f79312e3557683143'
    )

@pytest.fixture
def known_empty_hash() -> str:
    """Hash generated with the known_salt and empty password."""
    return (
        '243262243132244f67314a2f4c786b6b393557564644546871524750654e'
        '4a5855756c3956554c47474b65306c3653534937375761794961576a4e57'
    )


# --------------------------------------------------------------------------------------------------
#   General
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def general_data() -> dict:
    """General data with some keys with `None` values."""
    return {
        'some_key': 'some_value',
        'another_key': None,
        'yet_another_key': 123,
        321: None
    }

@pytest.fixture
def json_data() -> dict:
    """Generic JSON data."""
    return {
        'field0': 'value0',
        'field1': 123.45,
        'field2': ['alpha', 'beta', 456],
        'field3': {
            'f3_0': 'value3_0',
            'f3_1': [
                {
                    'field3_1_0': 'value3_1_0'
                },
                {
                    'field3_1_1a': 'value3_1_1a',
                    'field3_1_1b': 'value3_1_1b',
                    'field3_1_1c': 'value3_1_1c',
                },
                {
                    'field3_1_2': 'value3_1_2'
                },
            ]
        },
        'field4': None,
        'field5': 0.0,
        'field6': False,
    }

@pytest.fixture
def this_moment() -> datetime:
    """Provide current datetime with UTC timezone."""
    return datetime.now(tz=UTC)


@pytest.fixture
def base_url() -> str:
    """Provide the base url for testing environment."""
    return 'http://testserver'


@pytest.fixture
def user_id() -> str:
    """Test user id."""
    return f'{config.TEST_PREFIX}@user.id'


@pytest.fixture
def user_name() -> str:
    """Test user name."""
    return f'Mr. {config.TEST_PREFIX.capitalize()}'


@pytest.fixture
def another_user_id() -> str:
    """Another test user id."""
    return f'{config.TEST_PREFIX}-another@user.id'


# --------------------------------------------------------------------------------------------------
#   Database
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def test_db() -> Db:
    """Test database instance."""
    db = Db(database_name=f'{config.TEST_PREFIX}-database')
    yield db
    db.delete()


@pytest.fixture
def another_test_db() -> Db:
    """Another test database instance."""
    db = Db(database_name=f'another-{config.TEST_PREFIX}-database')
    yield db
    db.delete()


@pytest.fixture
def user_credentials(user_id, password) -> sch.UserCredentials:
    """Test user credentials."""
    return sch.UserCredentials(
        id=user_id,
        password=password
    )


@pytest.fixture
def admin_credentials(password) -> sch.UserCredentials:
    """Test admin user credentials."""
    return sch.UserCredentials(
        id=config.APP_ADM_USER,
        password=password
    )


@pytest.fixture(autouse=True)
def clean_databases() -> None:
    yield None
    for database_name in (
        config.USER_CREDENTIALS_DB_NAME,
        config.USER_INFO_DB_NAME,
        config.EMAIL_CONFIRMATION_DB_NAME,
        config.RECIPES_DB_NAME,
        config.USER_RECIPES_DB_NAME
    ):
        Db(database_name=database_name).delete()


@pytest.fixture
def invalid_db_credentials() -> DbCredentials:
    """Invalid Db credentials."""
    return DbCredentials(user='inexistent', password='invalid')


# --------------------------------------------------------------------------------------------------
#   Pubsub
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def pub_sub() -> ps.PubSub:
    """Test PubSub instance."""
    pub_sub = ps.PubSub()
    yield pub_sub
    pub_sub.connection.close()


@pytest.fixture
def another_pub_sub() -> ps.PubSub:
    """Another test PubSub instance."""
    pub_sub = ps.PubSub()
    yield pub_sub
    pub_sub.connection.close()


@pytest.fixture
def consumer_callback() -> ps.ConsumerCallback:
    """Test Consumer callback function factory."""
    def callback_function(
        channel: BlockingChannel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes
    ) -> None:
        pass
    return callback_function


@pytest.fixture
def callback_null_params() -> dict[str, None]:
    """Null parameters for consumer callback functions"""
    return {'channel': None, 'method': None, 'properties': None}


# --------------------------------------------------------------------------------------------------
#   Services
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def user_info(user_id: str, user_name: str) -> sch.UserInfo:
    """Test user information."""
    return sch.UserInfo(
        id=user_id,
        name=user_name,
        address=f'{config.TEST_PREFIX.title()} Street, 123'
    )


@pytest.fixture
def email_confirmation_info(
    user_id: str,
    user_name: str,
    base_url: str
) -> sch.EmailConfirmationInfo:
    """Return an `EmailConfirmationInfo` structure."""
    return sch.EmailConfirmationInfo(user_id=user_id, user_name=user_name, base_url=base_url)


@pytest.fixture
def user_info_status(user_info: sch.UserInfo) -> sch.OutputStatus:
    """Return an output status with user info inside."""
    output_status = ost.get_user_info_status()
    output_status.details.data = {
        '_id': user_info.id,
        '_rev': '1-ee4accf3657d300155b9228a21f75000',
        'name': user_info.name,
        'phone_number': user_info.phone_number,
        'address': user_info.address,
    }
    return output_status


# --------------------------------------------------------------------------------------------------
#   Recipes
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def recipe_csv_data() -> dict[str, Any]:
    """Return recipe data as read from a .csv file."""

    # Great culinary skills involved 🙂
    return {
        'name': 'Lemon cake',
        'description': 'A great lemon cake',
        'category': 'dessert',
        'easiness': 'medium',
        'price': '1.23',
        'tags': 'dessert|lemon|cake',
        'ingredients': 'lemon juice|wheat flour|milk|sugar|butter',
        'directions': 'Mix everything.|Put it in a greased pan and put it in the oven.'
    }


@pytest.fixture
def another_recipe_csv_data() -> dict[str, Any]:
    """Return another recipe data as read from a .csv file."""

    # Great culinary skills involved 🙂
    return {
        'name': 'Baked potatoes',
        'description': 'Hot and tasty baked potatoes.',
        'category': '',
        'easiness': 'easy',
        'price': '1.20',
        'tags': '',
        'ingredients': 'potatoes|milk|butter|spices',
        'directions': 'Open the potatoes in halves.|Spread butter in each half.|Put on the owen.'
    }


@pytest.fixture
def one_more_recipe_csv_data() -> dict[str, Any]:
    """Return one more recipe data as read from a .csv file."""

    # Great culinary skills involved 🙂
    return {
        'name': 'Popcorn',
        'description': "Who doesn't like popcorn?",
        'category': '',
        'easiness': 'easy',
        'price': '1.20',
        'tags': '',
        'ingredients': 'popcorn|oil|salt',
        'directions': (
            'Put 3 spoons of popcorn on a pan.|Join 2 spoons of oil and mix.|'
            'Put on the fire and wait it to pop.'
        )
    }


@pytest.fixture
def recipe_csv_file(
    recipe_csv_data: dict[str, Any],
    another_recipe_csv_data: dict[str, Any]
) -> io.BytesIO:
    """Return a CSV file like."""
    first_record_content = config.CSV_FIELD_SEPARATOR.join(recipe_csv_data.values())
    second_record_content = config.CSV_FIELD_SEPARATOR.join(another_recipe_csv_data.values())

    return io.BytesIO(
        initial_bytes=b'\n'.join(
            (
                first_record_content.encode(config.APP_ENCODING_FORMAT),
                second_record_content.encode(config.APP_ENCODING_FORMAT)
            )
        )
    )


def csv_data_to_recipe(recipe_csv_data: dict[str, Any]) -> sch.Recipe:
    """Convert .csv data to a `Recipe`."""
    summary = sch.RecipeSummary(
        name=recipe_csv_data['name'],
        description=recipe_csv_data['description']
    )

    tags = utils.split_or_empty(recipe_csv_data['tags'], separator='|')

    ingredients = recipe_csv_data['ingredients'].split('|')
    directions = recipe_csv_data['directions'].replace('|', '\n')
    recipe_info = sch.RecipeInformation(ingredients=ingredients, directions=directions)

    direct_fields = {
        key: value for key, value in recipe_csv_data.items()
        if key in ('category', 'easiness', 'price')
    }

    return sch.Recipe(
        summary=summary,
        **direct_fields,
        tags=tags,
        recipe=recipe_info,
        status='available'
    )


@pytest.fixture
def recipe(recipe_csv_data: dict[str, Any]) -> sch.Recipe:
    """Return a Recipe."""
    return csv_data_to_recipe(recipe_csv_data=recipe_csv_data)


@pytest.fixture
def another_recipe(another_recipe_csv_data: dict[str, Any]) -> sch.Recipe:
    """Return another Recipe."""
    return csv_data_to_recipe(recipe_csv_data=another_recipe_csv_data)


@pytest.fixture
def one_more_recipe(one_more_recipe_csv_data: dict[str, Any]) -> sch.Recipe:
    """Return one more Recipe."""
    return csv_data_to_recipe(recipe_csv_data=one_more_recipe_csv_data)


@pytest.fixture
def all_recipes_status(
    recipe: sch.Recipe,
    another_recipe: sch.Recipe,
    one_more_recipe: sch.Recipe
) -> sch.OutputStatus:
    """Return a list of all recipes."""
    output_status = ost.all_recipes_status()
    output_status.details.data = {
        'all_recipes': [recipe, another_recipe, one_more_recipe]
    }
    return output_status


# --------------------------------------------------------------------------------------------------
#   Purchasing
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def credit_card_number() -> str:
    """Return a credit card number."""
    # Test credit card number generated automatically here:
    #   https://www.4devs.com.br/gerador_de_numero_cartao_credito
    return '4539216056985199'

@pytest.fixture
def cc_payment_info(credit_card_number) -> sch.PaymentCcInfo:
    """Return a credit card payment info structure."""
    this_year = datetime.now(tz=UTC).year
    return sch.PaymentCcInfo(
        card_holder_name='Test User Name',
        card_number=credit_card_number,
        expiration_month=7,
        expiration_year=this_year + 1,
        cvv=567,
    )

@pytest.fixture
def checkout_id() -> str:
    """Return a payment provider's checkout id."""
    return '1234567890-abcd'

@pytest.fixture
def payment_id() -> str:
    """Return a payment id."""
    return 'c722bb1a-c14c-48e0-a3a3-92c71e986acd'

@pytest.fixture
def payment_status() -> int:
    """Return a payment status."""
    return sch.PaymentStatus.PAID

@pytest.fixture
def recipe_purchase_info(
    user_id: str,
    recipe: sch.Recipe,
) -> sch.RecipePurchaseInfo:
    """Return an `RecipePurchaseInfo` structure."""
    return sch.RecipePurchaseInfo(user_id=user_id, recipe_id=recipe.id)


# --------------------------------------------------------------------------------------------------
#   Purchase events handling
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def notifications_manager() -> srv.NotificationEventsManager:
    """A copy of the app's notification events manager."""
    return srv.NotificationEventsManager()
