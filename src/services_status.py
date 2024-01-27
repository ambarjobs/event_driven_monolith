# ==================================================================================================
#  Services output status
# ==================================================================================================

import httpx

import schemas as sch

# --------------------------------------------------------------------------------------------------
#   Normalized HTTP error status
# --------------------------------------------------------------------------------------------------
def http_error_status(error: httpx.HTTPStatusError) -> sch.ServiceStatus:
    """Return normalized HTTP error data."""
    error_status = sch.ServiceStatus(
            status='http_error',
            error=True,
            details=sch.StatusDetails(
                description='',
            ),
        )
    error_status.details.description = str(error)
    error_status.details.data = {'errors': error.response.json()}
    error_status.details.error_code = error.response.status_code
    return error_status

# --------------------------------------------------------------------------------------------------
#   handle_token output status
# --------------------------------------------------------------------------------------------------
def ok_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='OK',
        error=False,
        details=sch.StatusDetails(
            description='OK.',
        ),
    )

def invalid_token_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='invalid_token',
        error=True,
        details=sch.StatusDetails(
            description='Invalid token.',
        ),
    )

def expired_token_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='expired_token',
        error=True,
        details=sch.StatusDetails(
            description='The token has expired.',
        ),
    )

# ----------------------------------------------------------------------------------------------
#   user_sign_up output status
# ----------------------------------------------------------------------------------------------
def successful_sign_up_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='successful_sign_up',
        error=False,
        details=sch.StatusDetails(description='User signed up successfully.'),
    )

def user_already_signed_up_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='user_already_signed_up',
        error=True,
        details=sch.StatusDetails(description='User already signed up.'),
    )

# ------------------------------------------------------------------------------------------
#   authentication output status
# ------------------------------------------------------------------------------------------
def successful_logged_in_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='successfully_logged_in',
        error=False,
        details=sch.StatusDetails(description='User has successfully logged in.'),
    )

# Some situations below are aggregated into the same message in manner to avoid
# username prospecting.
def incorrect_login_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='incorrect_login_credentials',
        error=True,
        details=sch.StatusDetails(
            description='Invalid user or password. Check if user has signed up.'
        ),
    )

def email_not_validated_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='email_not_validated',
        error=True,
        details=sch.StatusDetails(description='User email is not validated.'),
    )

def user_already_logged_in_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='user_already_logged_in',
        error=False,
        details=sch.StatusDetails(
            description='User was already logged in and last token is still valid.'
        ),
    )

# ------------------------------------------------------------------------------------------
#   check_email_confirmation output status
# ------------------------------------------------------------------------------------------
def confirmed_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='confirmed',
        error=False,
        details=sch.StatusDetails(
            description='Email confirmed.'
        ),
    )

def inexistent_token_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='inexistent_token',
        error=True,
        details=sch.StatusDetails(
            description='Inexistent token for the user id.'
        ),
    )

def previously_confirmed_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='previously_confirmed',
        error=True,
        details=sch.StatusDetails(
            description='The email was already confirmed.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   import_csv_recipes output status
# ----------------------------------------------------------------------------------------------
def imported_csv_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='csv_imported',
        error=False,
        details=sch.StatusDetails(
            description='CSV recipes file imported successfully.'
        ),
    )

def invalid_csv_format_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='invalid_csv_format',
        error=True,
        details=sch.StatusDetails(
            description='The format of the CSV file is invalid.'
        ),
    )

def invalid_csv_content_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='invalid_csv_content',
        error=True,
        details=sch.StatusDetails(
            description='The content of the CSV file is invalid.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   store_recipe output status
# ----------------------------------------------------------------------------------------------
def recipe_stored_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='recipe_stored',
        error=False,
        details=sch.StatusDetails(
            description='The recipe was stored successfully.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   get_all_recipes output status
# ----------------------------------------------------------------------------------------------
def all_recipes_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='all_recipes_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='All recipes retrieved successfully.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   get_user_recipes output status
# ----------------------------------------------------------------------------------------------
def user_recipes_status() -> sch.ServiceStatus:
    return sch.ServiceStatus(
        status='user_recipes_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='User recipes retrieved successfully.'
        ),
    )
