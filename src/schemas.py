# ==================================================================================================
#  Application schemas (validation and serialization)
# ==================================================================================================
from typing import Any

from pydantic import BaseModel, EmailStr, Field, SecretStr


NAME_MAX_LENGHT = 100
PASSWD_MAX_LENGHT = 64
PHONE_MAX_LENGHT = 20
ADDRESS_MAX_LENGHT = 20


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


class UserCredentials(BaseModel):
    """User credentials schema (used for login and signin)."""
    id: EmailStr
    password: SecretStr = Field(max_length=PASSWD_MAX_LENGHT)


class UserInfo(BaseModel):
    """User informations schema."""
    id: EmailStr
    name: str = Field(max_length=NAME_MAX_LENGHT)
    phone_number: str | None = Field(default=None, max_length=PHONE_MAX_LENGHT)
    address: str | None = Field(default=None, max_length=ADDRESS_MAX_LENGHT)
