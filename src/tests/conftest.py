# ==================================================================================================
#  Tests fixtures
# ==================================================================================================
from typing import Type
from datetime import datetime, UTC

import pytest
from pydantic import SecretStr

import config
import schemas as sch
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
        'field2': ['alfa', 'beta', 456],
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


# --------------------------------------------------------------------------------------------------
#   Database
# --------------------------------------------------------------------------------------------------
@pytest.fixture
def TestDb() -> Type[Db]:
    """Fixture factory for database access class."""
    return Db

@pytest.fixture
def user_credentials(password) -> sch.UserCredentials:
    """Test user credentials."""
    return sch.UserCredentials(
        id=f'{config.TEST_PREFIX}@user.id',
        password=password
    )

@pytest.fixture
def user_info() -> sch.UserInfo:
    """Test user information."""
    return sch.UserInfo(
        id=f'{config.TEST_PREFIX}@user.id',
        name=f'{config.TEST_PREFIX.title()} User Name',
        address=f'{config.TEST_PREFIX.title()} Streeet, 123'
    )

@pytest.fixture
def user_id() -> str:
    """Test user id."""
    return f'{config.TEST_PREFIX}@user.id'
