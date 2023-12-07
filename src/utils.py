# ==================================================================================================
#  Application utility functions
# ==================================================================================================

from copy import deepcopy
from functools import reduce
from typing import Any, Generator, Sequence

import bcrypt
from pydantic import SecretStr


# --------------------------------------------------------------------------------------------------
#   Json data manipulation
# --------------------------------------------------------------------------------------------------
def clear_nulls(data: dict[str, Any]) -> dict[Any, Any]:
    """Return data removing fields with value `None`."""
    return {key: value for key, value in data.items() if value is not None}

# --------------------------------------------------------------------------------------------------
#   Hashing
# --------------------------------------------------------------------------------------------------
def calc_hash(password: SecretStr) -> str:
    """Calculate a hash (with salt) for a password."""
    salt = bcrypt.gensalt()
    hash_bytes = bcrypt.hashpw(password=password.get_secret_value().encode('utf-8'), salt=salt)
    return hash_bytes.hex()

def check_password(password: SecretStr, hash_value: str) -> bool:
    """Check if the `password` corresponds to the `hash_value`."""
    return bcrypt.checkpw(
        password=password.get_secret_value().encode('utf-8'),
        hashed_password=bytes.fromhex(hash_value),
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
    return result or None


# --------------------------------------------------------------------------------------------------
#   List manipulation
# --------------------------------------------------------------------------------------------------
def first(seq: Sequence | Generator | None) -> Any | None:
    """Return the first element of a sequence or `None` for empty sequences"""
    first, *_ = seq if seq else [None]
    return first
