# ==================================================================================================
#  Application schemas (validation and serialization)
# ==================================================================================================
import json
from datetime import datetime, UTC
from enum import IntEnum, StrEnum
from typing import Annotated, Any

from fastapi.encoders import jsonable_encoder
from pydantic import (
    AwareDatetime,
    BaseModel,
    computed_field,
    EmailStr,
    Field,
    JsonValue,
    SecretStr,
)
from pydantic_extra_types.payment import PaymentCardNumber
from pydantic.functional_validators import AfterValidator

import config
import utils


# --------------------------------------------------------------------------------------------------
#   Fields limits
# --------------------------------------------------------------------------------------------------
NAME_MIN_LENGTH = 4
NAME_MAX_LENGTH = 100
GENERAL_TEXT_MAX_LENGTH = 1024
MEDIUM_TEXT_MAX_LENGTH = 2048
LARGE_TEXT_MAX_LENGTH = 4096
SMALL_FIELD_MAX_LENGTH = 20
LARGE_FIELD_MAX_LENGTH = 80
UUID4_SIZE = 36

PASSWD_MAX_LENGTH = 64
PHONE_MAX_LENGTH = SMALL_FIELD_MAX_LENGTH
ADDRESS_MAX_LENGTH = SMALL_FIELD_MAX_LENGTH
TOKEN_MAX_LENGTH = GENERAL_TEXT_MAX_LENGTH

MEDIUM_LIST_ITEMS_LIMIT = 20

CURRENT_YEAR = datetime.now(tz=UTC).year
CC_EXPIRATION_RANGE = 4
MAX_CC_INSTALLMENTS = 12

PAYMENT_PROVIDER_API_KEY_LENGTH = 64

# --------------------------------------------------------------------------------------------------
#   Base output status
# --------------------------------------------------------------------------------------------------
class StatusDetails(BaseModel):
    """Service status details schema."""
    description: str
    data: dict[str, Any] = {}
    error_code: int | None = None


class OutputStatus(BaseModel):
    """Normalized output status schema."""
    status: str
    error: bool = Field(default=False)
    details: StatusDetails

    def model_dump(self, *args, **kwargs) -> dict[str, Any]:
        kwargs['exclude_unset'] = True
        return super().model_dump(*args, **kwargs)


# --------------------------------------------------------------------------------------------------
#   Authentication functionality
# --------------------------------------------------------------------------------------------------
class UserCredentials(BaseModel):
    """User credentials schema (used for login and sign up)."""
    id: EmailStr
    password: SecretStr = Field(max_length=PASSWD_MAX_LENGTH)


class UserInfo(BaseModel):
    """User information schema."""
    id: EmailStr
    name: str = Field(min_length=NAME_MIN_LENGTH, max_length=NAME_MAX_LENGTH)
    phone_number: str | None = Field(default=None, max_length=PHONE_MAX_LENGTH)
    address: str | None = Field(default=None, max_length=ADDRESS_MAX_LENGTH)


# --------------------------------------------------------------------------------------------------
#   Email confirmation functionality
# --------------------------------------------------------------------------------------------------
class EmailConfirmationInfo(BaseModel):
    """User information used for email confirmation."""
    user_id: EmailStr
    user_name: str = Field(min_length=NAME_MIN_LENGTH, max_length=NAME_MAX_LENGTH)
    base_url: str | None = None


class EmailConfirmationMessageInfo(BaseModel):
    """Info needed for email confirmation message."""
    confirmation_info: EmailConfirmationInfo
    validation_expiration_period: int
    email_confirmation_token: str


class EmailConfirmationToken(BaseModel):
    """Token used in email confirmation."""
    token: str = Field(max_length=TOKEN_MAX_LENGTH)


# --------------------------------------------------------------------------------------------------
#   Recipes functionality
# --------------------------------------------------------------------------------------------------
def no_empty_list(value: list[str]) -> list:
    """Validate the list field is not empty."""
    assert len(value) > 0, 'This field cannot be an empty list.'
    return value

NoEmptyList = Annotated[list[str], AfterValidator(no_empty_list)]


class RecipeEasiness(StrEnum):
    """Options of recipe easiness."""
    easy = 'easy'
    medium = 'medium'
    hard = 'hard'


class RecipeStatus(StrEnum):
    """Options of recipe status."""
    available = 'available'
    requested = 'requested'
    purchased = 'purchased'


class RecipeSummary(BaseModel):
    """Summary description of the recipe."""
    name: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    description: str = Field(max_length=GENERAL_TEXT_MAX_LENGTH)


class RecipeInformation(BaseModel):
    """Recipe information."""
    ingredients: NoEmptyList = Field(max_length=LARGE_FIELD_MAX_LENGTH)
    directions: str = Field(min_length=1, max_length=MEDIUM_TEXT_MAX_LENGTH)


class Recipe(BaseModel):
    """Recipe representation."""
    summary: RecipeSummary
    category: str = Field(max_length=SMALL_FIELD_MAX_LENGTH, default='')
    easiness: RecipeEasiness = RecipeEasiness.medium
    tags: list[str] = Field(
        default_factory=list,
        max_length=SMALL_FIELD_MAX_LENGTH,
    )
    recipe: RecipeInformation | None = None
    price: float | None = None
    status: RecipeStatus = RecipeStatus.available
    modif_datetime: AwareDatetime = datetime.now(tz=UTC)

    @computed_field(alias='recipe_id')  # type: ignore[misc]
    @property
    def id(self) -> str:
        """Recipe `id` (serialized as `recipe_id`), that's a slug based on `summary.name`"""
        return utils.slugify(self.summary.name)

    @classmethod
    def from_record(cls, record: dict) -> 'Recipe':
        """Return a Recipe schema from a `recipe` database record."""
        db_summary = record.pop('summary')
        summary = RecipeSummary(**db_summary)
        recipe = RecipeInformation(**record.pop('recipe')) if 'recipe' in record else None
        return cls(summary = summary, **record, recipe=recipe)

    def to_json(self, *args, **kwargs) -> dict:
        """Return a JSON serializable representation of the Recipe."""
        return jsonable_encoder(self.model_dump(*args, **kwargs))


class UserRecipe(BaseModel):
    """User recipe representation."""
    recipe_id: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    status: str = Field(min_length=1, max_length=SMALL_FIELD_MAX_LENGTH)


# --------------------------------------------------------------------------------------------------
#   Purchasing functionality
# --------------------------------------------------------------------------------------------------
class PaymentStatus(IntEnum):
    """Payment status"""
    PENDING = 0
    PAID = 1
    CANCELLED = 2
    FAILED = 3


class PaymentCcInfo(BaseModel):
    """Payment information for credit cards representation."""
    card_holder_name: str = Field(min_length=NAME_MIN_LENGTH, max_length=NAME_MAX_LENGTH)
    card_number: PaymentCardNumber
    expiration_month: int = Field(ge=1, le=12)
    expiration_year: int = Field(
        ge=CURRENT_YEAR,
        le=CURRENT_YEAR + CC_EXPIRATION_RANGE
    )
    cvv: int = Field(ge=0, le=999)
    number_installments: int = Field(ge=1, le=MAX_CC_INSTALLMENTS, default=MAX_CC_INSTALLMENTS)

    @classmethod
    def decrypt(cls, data: bytes) -> 'PaymentCcInfo':
        """Get encrypted data and generate a `PaymentCcInfo` schema object from it."""
        serialized_data = utils.decr_data(data=data, key=config.PAYMENT_PROVIDER_ENCRYPTION_KEY)
        return cls(**json.loads(serialized_data))

    def encrypt(self) -> bytes:
        """Provide encrypted data corresponding to this schema object."""
        return utils.encr_data(
            data=self.model_dump_json(),
            key=config.PAYMENT_PROVIDER_ENCRYPTION_KEY
        )


class PaymentEncrInfo(BaseModel):
    """Encrypted payment information."""
    encr_info: str = Field(min_length=1, max_length=LARGE_TEXT_MAX_LENGTH)


class PaymentCheckoutInfo(BaseModel):
    """Payment information for checkout on simulated payment provider."""
    payment_encr_info: PaymentEncrInfo
    api_key: str = Field(
        min_length=PAYMENT_PROVIDER_API_KEY_LENGTH,
        max_length=PAYMENT_PROVIDER_API_KEY_LENGTH
    )


class RecipePurchaseInfo(BaseModel):
    """Recipe purchase request message."""
    user_id: EmailStr
    recipe_id: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)


class PurchaseStatusInfo(RecipePurchaseInfo):
    """Purchased payment status change event message."""
    payment_status: PaymentStatus
    when: AwareDatetime = datetime.now(tz=UTC)


class WebhookPaymentInfo(BaseModel):
    """Payment provider payment info sent to application webhook."""
    recipe_id: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    payment_id: str = Field(min_length=UUID4_SIZE, max_length=UUID4_SIZE)
    payment_status: PaymentStatus


# --------------------------------------------------------------------------------------------------
#   Events handling functionality
# --------------------------------------------------------------------------------------------------
class Notification(BaseModel):
    """General notification message for using with SSE (Server Sent Events) push events."""
    event_name: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    user_id: EmailStr
    data: JsonValue


class RecipePurchaseRequestInfo(BaseModel):
    """Information about recipe purchase request."""
    user_name: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    recipe_id: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    recipe_name: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
