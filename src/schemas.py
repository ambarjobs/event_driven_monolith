# ==================================================================================================
#  Application schemas (validation and serialization)
# ==================================================================================================
from typing import Any

from pydantic import BaseModel, EmailStr, Field, SecretStr

NAME_MAX_LENGTH = 100
PASSWD_MAX_LENGTH = 64
PHONE_MAX_LENGTH = 20
ADDRESS_MAX_LENGTH = 20
TOKEN_MAX_LENGTH = 1024


class StatusDetails(BaseModel):
    """Service status details schema."""
    description: str
    data: dict[str, Any] | None = None
    error_code: int | None = None


class ServiceStatus(BaseModel):
    """Normalized service status schema."""
    status: str
    error: bool = Field(default=False)
    details: StatusDetails

    def model_dump(self, *args, **kwargs) -> dict[str, Any]:
        kwargs['exclude_unset'] = True
        return super().model_dump(*args, **kwargs)


class UserCredentials(BaseModel):
    """User credentials schema (used for login and sign up)."""
    id: EmailStr
    password: SecretStr = Field(max_length=PASSWD_MAX_LENGTH)


class UserInfo(BaseModel):
    """User information schema."""
    id: EmailStr
    name: str = Field(max_length=NAME_MAX_LENGTH)
    phone_number: str | None = Field(default=None, max_length=PHONE_MAX_LENGTH)
    address: str | None = Field(default=None, max_length=ADDRESS_MAX_LENGTH)


class EmailConfirmationInfo(BaseModel):
    """User information used for email confirmation."""
    user_id: EmailStr
    user_name: str = Field(max_length=NAME_MAX_LENGTH)
    base_url: str | None = None


class EmailConfirmationMessageInfo(BaseModel):
    """Info needed for email confirmation message."""
    confirmation_info: EmailConfirmationInfo
    validation_expiration_period: int
    email_confirmation_token: str


class EmailConfirmationToken(BaseModel):
    """Token used in email confirmation."""
    token: str = Field(max_length=TOKEN_MAX_LENGTH)
