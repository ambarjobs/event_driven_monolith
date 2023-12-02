# ==================================================================================================
#  Application schemas (validation and serialization)
# ==================================================================================================

from pydantic import BaseModel, EmailStr, Field, SecretStr


NAME_MAX_LENGHT = 100
PASSWD_MAX_LENGHT = 64
PHONE_MAX_LENGHT = 20
ADDRESS_MAX_LENGHT = 20


class UserCredentials(BaseModel):
    """User credentials schema (used for login and signin)."""
    id: EmailStr
    password: SecretStr = Field(max_length=PASSWD_MAX_LENGHT)

class UserInfo(BaseModel):
    """User informations schema."""
    id: EmailStr
    name: str = Field(max_length=NAME_MAX_LENGHT)
    phone_number: str = Field(default=None, max_length=PHONE_MAX_LENGHT)
    address: str = Field(default=None, max_length=ADDRESS_MAX_LENGHT)
