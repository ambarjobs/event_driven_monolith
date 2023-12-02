# ==================================================================================================
#  Application utility functions
# ==================================================================================================

from typing import Any

import bcrypt
from pydantic import SecretStr

# --------------------------------------------------------------------------------------------------
#   Json data manipulation
# --------------------------------------------------------------------------------------------------
def clear_nulls(data: dict[str, Any]) -> dict[str, Any]:
    """Return data removing fields with value `None`."""
    return {key: value for key, value in data.items() if value is not None}

# --------------------------------------------------------------------------------------------------
#   Hashing
# --------------------------------------------------------------------------------------------------
def calc_hash(password: SecretStr) -> str:
    """Calculate a hash (with salt) for a password."""
    salt = bcrypt.gensalt()
    hash_bytes = bcrypt.hashpw(password=str(password).encode('utf-8'), salt=salt)
    return hash_bytes.hex()
