# ==================================================================================================
#  Application schemas (validation and serialization)
# ==================================================================================================
from datetime import datetime, UTC
from enum import Enum
from typing import Annotated, Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    computed_field,
    EmailStr,
    Field,
    SecretStr,
)
from pydantic.functional_validators import AfterValidator

import utils

# --------------------------------------------------------------------------------------------------
#   Fields limits
# --------------------------------------------------------------------------------------------------
NAME_MAX_LENGTH = 100
GENERAL_TEXT_MAX_LENGTH = 1024
MEDIUM_TEXT_MAX_LENGTH = 2048
SMALL_FIELD_MAX_LENGTH = 20
LARGE_FIELD_MAX_LENGTH = 80

PASSWD_MAX_LENGTH = 64
PHONE_MAX_LENGTH = SMALL_FIELD_MAX_LENGTH
ADDRESS_MAX_LENGTH = SMALL_FIELD_MAX_LENGTH
TOKEN_MAX_LENGTH = GENERAL_TEXT_MAX_LENGTH

MEDIUM_LIST_ITEMS_LIMIT = 20


# --------------------------------------------------------------------------------------------------
#   Service status
# --------------------------------------------------------------------------------------------------
class StatusDetails(BaseModel):
    """Service status details schema."""
    description: str
    data: dict[str, Any] = {}
    error_code: int | None = None


class ServiceStatus(BaseModel):
    """Normalized service status schema."""
    status: str
    error: bool = Field(default=False)
    details: StatusDetails

    def model_dump(self, *args, **kwargs) -> dict[str, Any]:
        kwargs['exclude_unset'] = True
        return super().model_dump(*args, **kwargs)


# --------------------------------------------------------------------------------------------------
#   User
# --------------------------------------------------------------------------------------------------
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


# --------------------------------------------------------------------------------------------------
#   Email confirmation
# --------------------------------------------------------------------------------------------------
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


# --------------------------------------------------------------------------------------------------
#   Recipes
# --------------------------------------------------------------------------------------------------
def no_empty_list(value: list[str]) -> list:
    """Validate the list field is not empty."""
    assert len(value) > 0, 'This field cannot be an empty list.'
    return value

NoEmptyList = Annotated[list[str], AfterValidator(no_empty_list)]


class RecipeEasiness(str, Enum):
    """Options of recipe easiness."""
    easy = 'easy'
    medium = 'medium'
    hard = 'hard'


class RecipeStatus(str, Enum):
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
    price: float
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

    def to_json(self) -> dict:
        """Return a JSON serializable representation of the Recipe."""
        recipe_data = self.model_dump()
        recipe_data['easiness'] =recipe_data['easiness'].value
        recipe_data['status'] =recipe_data['status'].value
        recipe_data['modif_datetime'] = recipe_data['modif_datetime'].isoformat()
        return recipe_data


class UserRecipe(BaseModel):
    """User recipe representation."""
    recipe_id: str
    status: str
