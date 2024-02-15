# ==================================================================================================
#   Output status
# ==================================================================================================

import httpx

import schemas as sch

# --------------------------------------------------------------------------------------------------
#   Normalized HTTP error status
# --------------------------------------------------------------------------------------------------
def http_error_status(error: httpx.HTTPStatusError) -> sch.OutputStatus:
    """Return normalized HTTP error data."""
    error_status = sch.OutputStatus(
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

# ==================================================================================================
#   Services output status
# ==================================================================================================
# --------------------------------------------------------------------------------------------------
#   `handle_token` output status
# --------------------------------------------------------------------------------------------------
def ok_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='OK',
        error=False,
        details=sch.StatusDetails(
            description='OK.',
        ),
    )

def invalid_token_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='invalid_token',
        error=True,
        details=sch.StatusDetails(
            description='Invalid token.',
        ),
    )

def expired_token_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='expired_token',
        error=True,
        details=sch.StatusDetails(
            description='The token has expired.',
        ),
    )

# ==================================================================================================
#  Authentication services output status
# ==================================================================================================
# ----------------------------------------------------------------------------------------------
#   `user_sign_up` output status
# ----------------------------------------------------------------------------------------------
def successful_sign_up_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='successful_sign_up',
        error=False,
        details=sch.StatusDetails(description='User signed up successfully.'),
    )

def user_already_signed_up_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='user_already_signed_up',
        error=True,
        details=sch.StatusDetails(description='User already signed up.'),
    )

# ------------------------------------------------------------------------------------------
#   `authentication` output status
# ------------------------------------------------------------------------------------------
def successful_logged_in_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='successfully_logged_in',
        error=False,
        details=sch.StatusDetails(description='User has successfully logged in.'),
    )

# Some situations below are aggregated into the same message in manner to avoid
# username prospecting.
def incorrect_login_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='incorrect_login_credentials',
        error=True,
        details=sch.StatusDetails(
            description='Invalid user or password. Check if user has signed up.'
        ),
    )

def email_not_validated_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='email_not_validated',
        error=True,
        details=sch.StatusDetails(description='User email is not validated.'),
    )

def user_already_logged_in_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='user_already_logged_in',
        error=False,
        details=sch.StatusDetails(
            description='User was already logged in and last token is still valid.'
        ),
    )

# ------------------------------------------------------------------------------------------
#   `get_user_info` output status
# ------------------------------------------------------------------------------------------
def get_user_info_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='user_info',
        error=False,
        details=sch.StatusDetails(description='User information.'),
    )

def user_info_not_found_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='user_info_not_found',
        error=True,
        details=sch.StatusDetails(description='User or user information not found.'),
    )

# ==================================================================================================
#  Email confirmation services output status
# ==================================================================================================
# ------------------------------------------------------------------------------------------
#   `check_email_confirmation` output status
# ------------------------------------------------------------------------------------------
def confirmed_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='confirmed',
        error=False,
        details=sch.StatusDetails(
            description='Email confirmed.'
        ),
    )

def inexistent_token_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='inexistent_token',
        error=True,
        details=sch.StatusDetails(
            description='Inexistent token for the user id.'
        ),
    )

def previously_confirmed_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='previously_confirmed',
        error=True,
        details=sch.StatusDetails(
            description='The email was already confirmed.'
        ),
    )

# ==================================================================================================
#  Recipes services output status
# ==================================================================================================
# ----------------------------------------------------------------------------------------------
#   `import_csv_recipes` output status
# ----------------------------------------------------------------------------------------------
def imported_csv_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='csv_imported',
        error=False,
        details=sch.StatusDetails(
            description='CSV recipes file imported successfully.'
        ),
    )

def invalid_csv_format_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='invalid_csv_format',
        error=True,
        details=sch.StatusDetails(
            description='The format of the CSV file is invalid.'
        ),
    )

def invalid_csv_content_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='invalid_csv_content',
        error=True,
        details=sch.StatusDetails(
            description='The content of the CSV file is invalid.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `store_recipe` output status
# ----------------------------------------------------------------------------------------------
def recipe_stored_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='recipe_stored',
        error=False,
        details=sch.StatusDetails(
            description='The recipe was stored successfully.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `get_all_recipes` output status
# ----------------------------------------------------------------------------------------------
def all_recipes_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='all_recipes_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='All recipes retrieved successfully.'
        ),
    )

def error_retrieving_all_recipes_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='error_retrieving_all_recipes',
        error=True,
        details=sch.StatusDetails(
            description='An error ocurred trying to retrieve all recipes.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `get_user_recipes` output status
# ----------------------------------------------------------------------------------------------
def user_recipes_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='user_recipes_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='User recipes retrieved successfully.'
        ),
    )

def error_retrieving_user_recipes_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='error_retrieving_user_recipes',
        error=True,
        details=sch.StatusDetails(
            description='An error ocurred trying to retrieve user recipes.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `get_specific_recipe` output status
# ----------------------------------------------------------------------------------------------
def specific_recipe_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='specific_recipe_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='Specific recipe retrieved successfully.'
        ),
    )

def error_retrieving_specific_recipe_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='error_retrieving_specific_recipe',
        error=True,
        details=sch.StatusDetails(
            description='An error ocurred trying to retrieve specific recipe.'
        ),
    )

# ==================================================================================================
#  Purchasing services output status
# ==================================================================================================
# ----------------------------------------------------------------------------------------------
#   `update_payment_status` output status
# ----------------------------------------------------------------------------------------------
def update_payment_status_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='specific_recipe_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='Specific recipe retrieved successfully.'
        ),
    )

def update_payment_status_checkout_not_found_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='update_payment_status_checkout_not_found',
        error=True,
        details=sch.StatusDetails(
            description='The `checkout_id` sent by payment provider was not found in database.'
        ),
    )

# ==================================================================================================
#  Payment provider simulator services output status
# ==================================================================================================
# ----------------------------------------------------------------------------------------------
#   `start_checkout` output status
# ----------------------------------------------------------------------------------------------
def start_checkout_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='recipe_purchase_checkout_started',
        error=False,
        details=sch.StatusDetails(
            description='Recipe purchase checkout started successfully.'
        ),
    )


# ----------------------------------------------------------------------------------------------
#   `payment_processing` output status
# ----------------------------------------------------------------------------------------------
def payment_processing_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='payment_status_notified',
        error=False,
        details=sch.StatusDetails(
            description='The payment status change was notified to the application webhook.'
        ),
    )

def error_accessing_app_webhook_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='error_accessing_app_webhook',
        error=True,
        details=sch.StatusDetails(
            description='Error trying to access application webhook.'
        ),
    )


# ==================================================================================================
#  Endpoints output status
# ==================================================================================================
# ----------------------------------------------------------------------------------------------
#   `login` output status
# ----------------------------------------------------------------------------------------------
def api_invalid_credentials_format_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_invalid_credentials_format',
        error=True,
        details=sch.StatusDetails(description='The credentials are in an invalid format.'),
    )

# ----------------------------------------------------------------------------------------------
#   `load-recipes` output status
# ----------------------------------------------------------------------------------------------
def api_recipes_loaded_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_recipes_loaded',
        error=False,
        details=sch.StatusDetails(
            description='Recipes loaded successfully.'
        ),
    )

def api_error_loading_recipe_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_error_loading_recipes',
        error=True,
        details=sch.StatusDetails(
            description='An error ocurred trying to load the recipes.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `get-all-recipes` output status
# ----------------------------------------------------------------------------------------------
def api_all_recipes_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_all_recipes_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='All recipes retrieved successfully.'
        ),
    )

def api_error_getting_all_recipes_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_error_getting_all_recipes',
        error=True,
        details=sch.StatusDetails(
            description='An error ocurred trying to get all recipes.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `get-recipe-details` output status
# ----------------------------------------------------------------------------------------------
def api_recipe_details_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_recipe_details_retrieved',
        error=False,
        details=sch.StatusDetails(
            description='Recipe details retrieved successfully.'
        ),
    )

def api_error_getting_recipe_details_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_error_getting_recipe_details',
        error=True,
        details=sch.StatusDetails(
            description='An error ocurred trying to get recipe details.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `buy-recipe` output status
# ----------------------------------------------------------------------------------------------
def api_buy_recipe_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_recipe_purchase_requested',
        error=False,
        details=sch.StatusDetails(
            description='Recipe purchase requested successfully.'
        ),
    )

def api_invalid_checkout_id_error_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='invalid_checkout_id_error',
        error=True,
        details=sch.StatusDetails(
            description='The checkout_id returned by the payment provider is invalid or missing.'
        ),
    )

def api_start_checkout_error_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_start_checkout_error',
        error=True,
        details=sch.StatusDetails(
            description='To be override with error detail.'
        ),
    )

# ----------------------------------------------------------------------------------------------
#   `payment-webhook` output status
# ----------------------------------------------------------------------------------------------
def api_payment_webhook_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='api_payment_webhook_notified',
        error=False,
        details=sch.StatusDetails(
            description='Application payment webhook notified of payment status change.'
        ),
    )


# ==================================================================================================
#  Payment provider simulator endpoints output status
# ==================================================================================================
# ----------------------------------------------------------------------------------------------
#   `create-checkout` output status
# ----------------------------------------------------------------------------------------------
def pprovider_create_checkout_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='pprovider_checkout_received',
        error=False,
        details=sch.StatusDetails(
            description='Checkout request received.'
        ),
    )

def pprovider_payment_info_error_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='pprovider_payment_info_error',
        error=True,
        details=sch.StatusDetails(
            description='Invalid encrypted payment info.'
        ),
    )

def pprovider_api_key_error_status() -> sch.OutputStatus:
    return sch.OutputStatus(
        status='pprovider_api_key_error',
        error=True,
        details=sch.StatusDetails(
            description='Invalid API key.'
        ),
    )
