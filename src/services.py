# ==================================================================================================
#  Application services
# ==================================================================================================
from datetime import datetime, timedelta, UTC
from typing import Any

import httpx
from fastapi import status

import config
import schemas as sch
import utils
from database import db


# --------------------------------------------------------------------------------------------------
#   Normalized HTTP error status
# --------------------------------------------------------------------------------------------------
def http_error_status(error: httpx.HTTPStatusError):
    """Return normalized HTTP error data."""
    error_status = sch.ServiceStatus(
            status='http_error',
            error=True,
            details=sch.StatusDetails(
                description='',
            ),
        )
    error_status.details.description = str(error)
    error_status.details.error_code = error.response.status_code
    return error_status.model_dump(exclude_unset=True)


# ==================================================================================================
#   Specific utils
# ==================================================================================================
def user_is_logged_in(db_user_credentials: dict[str, Any]) -> bool:
    """Check if user is logged in."""
    this_moment = datetime.now(tz=UTC)

    last_login = utils.deep_traversal(db_user_credentials, 'last_login')
    return (
        last_login and
        this_moment - datetime.fromisoformat(last_login) <
        timedelta(hours=config.TOKEN_DEFAULT_EXPIRATION_HOURS)
    )

# ==================================================================================================
#   Services
# ==================================================================================================
def user_sign_in(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
) -> dict[str, Any]:
    """User sign in service."""
    # ----------------------------------------------------------------------------------------------
    #   Output status
    # ----------------------------------------------------------------------------------------------
    successful_sign_in_status = sch.ServiceStatus(
            status='successful_sign_in',
            error=False,
            details=sch.StatusDetails(description='User signed in successfully.'),
        )

    user_already_signed_in_status = sch.ServiceStatus(
            status='user_already_signed_in',
            error=True,
            details=sch.StatusDetails(description='User already signed in.'),
        )
    # ----------------------------------------------------------------------------------------------

    try:
        version = db.check_document_available(
            database_name=config.USER_CREDENTIALS_DB_NAME,
            document_id=credentials.id
        )
        if version is None:
            hash_ = utils.calc_hash(credentials.password)
            db.sign_in_user(
                id=credentials.id,
                hash_=hash_,
                user_info=user_info,
            )
            return successful_sign_in_status.model_dump(exclude_unset=True)

        user_already_signed_in_status.details.data = {'version': version}
        return user_already_signed_in_status.model_dump(exclude_unset=True)
    except httpx.HTTPStatusError as err:
        return http_error_status(error=err)

def authentication(credentials: sch.UserCredentials) -> dict[str, Any]:
    """User login service."""
    try:
        # ------------------------------------------------------------------------------------------
        #   Output status
        # ------------------------------------------------------------------------------------------
        # Some situations below are aggregated into the same message in manner to avoid
        # username prospection.
        incorrect_login_status = sch.ServiceStatus(
            status='incorrect_login_credentials',
            error=True,
            details=sch.StatusDetails(
                description='Invalid user or password. Check if user has signed in.'
            ),
        )

        email_not_validated_status = sch.ServiceStatus(
            status='email_not_validated',
            error=True,
            details=sch.StatusDetails(description='User email is not validated.'),
        )

        user_already_logged_in_status = sch.ServiceStatus(
            status='user_already_signed_in',
            error=True,
            details=sch.StatusDetails(description='User was already logged in.'),
        )

        successful_logged_in_status = sch.ServiceStatus(
            status='successfully_logged_in',
            error=False,
            details=sch.StatusDetails(description='User has successfully logged in.'),
        )
        # ------------------------------------------------------------------------------------------

        try:
            db_user_credentials = db.get_document_by_id(
                database_name=config.USER_CREDENTIALS_DB_NAME,
                document_id=credentials.id
            )
        except httpx.HTTPStatusError as err:
            if err.response.status_code == status.HTTP_404_NOT_FOUND:
                # Usuário não encontrado
                return incorrect_login_status.model_dump(exclude_unset=True)
            return http_error_status(error=err)

        user_hash = utils.deep_traversal(db_user_credentials, 'hash')
        if user_hash is None:
            # User has no hash.
            return incorrect_login_status.model_dump(exclude_unset=True)

        hash_match = utils.check_password(password=credentials.password, hash_value=user_hash)
        if not hash_match:
            # Invalid password.
            return incorrect_login_status.model_dump(exclude_unset=True)

        validated  = utils.deep_traversal(db_user_credentials, 'validated')
        if not validated:
            return email_not_validated_status.model_dump(exclude_unset=True)

        logged_in = user_is_logged_in(db_user_credentials=db_user_credentials)
        if logged_in:
            return user_already_logged_in_status.model_dump(exclude_unset=True)

        payload = {'sub': credentials.id}
        access_token = utils.create_token(payload=payload)
        db.update_document(
            database_name=config.USER_CREDENTIALS_DB_NAME,
            document_id=credentials.id,
            fields_to_change={
                'last_login': datetime.now(tz=UTC).isoformat(),
            }
        )

        successful_logged_in_status.details.data = {'token': access_token}
        return successful_logged_in_status.model_dump(exclude_unset=True)
    except httpx.HTTPStatusError as err:
        return http_error_status(error=err)
