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
import schemas as sch
import pubsub as ps
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
def user_credentials(password) -> sch.UserCredentials:
    """Test user credentials."""
    return sch.UserCredentials(
        id=f'{config.TEST_PREFIX}@user.id',
        password=password
    )


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
def recipe_csv_file(recipe_csv_data: dict[str, Any]) -> io.BytesIO:
    """Return a CSV file like."""
    first_record_content = config.CSV_FIELD_SEPARATOR.join(recipe_csv_data.values())

    second_record = {
        'name': 'Baked potatoes',
        'description': 'Hot and tasty baked potatoes.',
        'category': '',
        'easiness': 'easy',
        'price': '1.20',
        'tags': '',
        'ingredients': 'potatoes|milk|butter|spices',
        'directions': 'Open the potatoes in halves.|Spread butter in each half.|Put on the owen.'
    }
    second_record_content = config.CSV_FIELD_SEPARATOR.join(second_record.values())

    return io.BytesIO(
        initial_bytes=b'\n'.join(
            (
                first_record_content.encode(config.APP_ENCODING_FORMAT),
                second_record_content.encode(config.APP_ENCODING_FORMAT)
            )
        )
    )

@pytest.fixture
def recipe(recipe_csv_data: dict[str, Any]) -> sch.Recipe:
    """Return a Recipe."""
    summary = sch.RecipeSummary(
        name=recipe_csv_data['name'],
        description=recipe_csv_data['description']
    )

    tags = recipe_csv_data['tags'].split('|')

    ingredients = recipe_csv_data['ingredients'].split('|')
    directions = recipe_csv_data['directions'].replace('|', '\n')
    recipe_info = sch.RecipeInformation(ingredients=ingredients, directions=directions)

    direct_fields = {
        key: value for key, value in recipe_csv_data.items()
        if key in ('category', 'easiness', 'price')
    }

    return sch.Recipe(summary=summary, **direct_fields, tags=tags, recipe=recipe_info)
