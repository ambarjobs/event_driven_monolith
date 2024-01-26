# ==================================================================================================
#  Application utility functions
# ==================================================================================================
import string
import unicodedata
from copy import deepcopy
from collections.abc import Generator, Mapping, Sequence
from datetime import datetime, timedelta, UTC
from functools import reduce
from typing import Any

import bcrypt
from jose import jwt
from pydantic import JsonValue, SecretStr

import config
from exceptions import InvalidAccessTokenKeyError


# --------------------------------------------------------------------------------------------------
#   Json data manipulation
# --------------------------------------------------------------------------------------------------
def clear_nulls(data: dict) -> dict:
    """Return data removing fields with value `None`."""
    return {key: value for key, value in data.items() if value is not None}

def filter_data(data: dict, keep: Sequence[Any]) -> dict:
    """Return data filtering keys not in `keep`."""
    return {key: value for key, value in data.items() if key in keep}

# --------------------------------------------------------------------------------------------------
#   Hashing
# --------------------------------------------------------------------------------------------------
def calc_hash(password: SecretStr) -> str:
    """Calculate a hash (with salt) for a password."""
    salt = bcrypt.gensalt()
    hash_bytes = bcrypt.hashpw(
        password=password.get_secret_value().encode(config.APP_ENCODING_FORMAT),
        salt=salt
    )
    return hash_bytes.hex()

def check_password(password: SecretStr, hash_value: str) -> bool:
    """Check if the `password` corresponds to the `hash_value`."""
    return bcrypt.checkpw(
        password=password.get_secret_value().encode(config.APP_ENCODING_FORMAT),
        hashed_password=bytes.fromhex(hash_value),
    )


# --------------------------------------------------------------------------------------------------
#   Tokens
# --------------------------------------------------------------------------------------------------
def create_token(
    payload: JsonValue = None,
    expiration_hours = float(config.TOKEN_DEFAULT_EXPIRATION_HOURS)
) -> str:
    """Create a signed JWT."""
    payload = payload or {}
    this_moment = datetime.now(tz=UTC)
    token_expiration = this_moment + timedelta(hours=expiration_hours)
    key = config.ACCESS_TOKEN_SECRET_KEY
    if not key:
        raise InvalidAccessTokenKeyError
    return jwt.encode(
        claims=payload | {'exp': token_expiration},
        key=key,
        algorithm=config.TOKEN_ALGORITHM
    )

def get_token_payload(token: str) -> dict:
    """Get token payload if it is valid and not expired."""
    key = config.ACCESS_TOKEN_SECRET_KEY
    if not key:
        raise InvalidAccessTokenKeyError
    return jwt.decode(
        token=token,
        key=key,
        algorithms=[config.TOKEN_ALGORITHM]
    )


# --------------------------------------------------------------------------------------------------
#   JSON traversal
# --------------------------------------------------------------------------------------------------
def get_elem_value(elem: Any, nav_key: str) -> dict | list | Any | None:
    """Get current traversing element value."""
    if isinstance(elem, dict):
        return elem.get(nav_key)
    elif isinstance(elem, Sequence) and isinstance(nav_key, int):
        try:
            return elem[nav_key]
        except IndexError:
            return None
    else:
        return elem

def deep_traversal(obj, *keys):
    """Traverse through the dictionary and sequences data structure."""
    result = reduce(
        get_elem_value,
        keys,
        deepcopy(obj)
    )
    if result is False or result == 0:
        return result
    return result or None


# --------------------------------------------------------------------------------------------------
#   List manipulation
# --------------------------------------------------------------------------------------------------
def first(seq: Sequence | Generator | Mapping | None) -> Any | None:
    """Return the first element of a sequence or `None` for empty sequences"""
    first, *_ = seq if seq else [None]
    return first


def split_or_empty(string: str, separator: str) -> list:
    """Split a string using a separator or return an empty list."""
    if not separator:
        raise ValueError
    normalized_separator = separator[0]
    if string in ('', normalized_separator):
        return []
    return string.split(normalized_separator)

# --------------------------------------------------------------------------------------------------
#   String manipulation
# --------------------------------------------------------------------------------------------------
def remove_punctuation(text: str) -> str:
    """Remove punctuation from text."""
    translate_tbl = str.maketrans('', '', string.punctuation)
    return text.translate(translate_tbl)

def remove_unicode_and_accents(text: str) -> str:
    """Remove unicode characters and accents from text."""
    return unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode()

def slugify(text: str, separator: str = '-') -> str:
    """Transform the text into a slug, removing unicode, accents and special characters."""
    normalized_text = remove_punctuation(remove_unicode_and_accents(text.replace('-', ' '))).lower()
    return separator.join(normalized_text.split())
