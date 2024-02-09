# ==================================================================================================
#  Application endpoints
# ==================================================================================================
from uuid import uuid4
from typing import Annotated

from cryptography.fernet import InvalidToken
from fastapi import Depends, FastAPI, Request, status, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import SecretStr, ValidationError

import config
import core
import output_status as ost
import schemas as sch
import services as srv
from config import logging as log
from core import oauth2_scheme


core.init_app_databases(core.APP_DATABASES_INFO)
core.create_admin_user()
core.start_consumers(subscriptions=srv.CONSUMERS_SUBSCRIPTIONS)

app = FastAPI()


# ==================================================================================================
#  General functions
# ==================================================================================================
def oauth2form_to_credentials(form_data: OAuth2PasswordRequestForm) -> sch.UserCredentials:
    """Get the UserCredentials object corresponding to the OAuth2 request form."""
    return sch.UserCredentials(id=form_data.username, password=SecretStr(form_data.password))

# ==================================================================================================
#  Authentication functionality
# ==================================================================================================
@app.post('/signup')
def signup(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
    request: Request,
) -> JSONResponse:
    """Sign in endpoint."""
    sign_up_status = srv.user_sign_up(
        credentials=credentials,
        user_info=user_info,
        base_url=str(request.base_url)
    )
    match sign_up_status:
        case sch.OutputStatus(status='user_already_signed_up'):
            log.warning(f'User already signed up: {credentials.id}')
            status_code = status.HTTP_409_CONFLICT
        case sch.OutputStatus(status='http_error'):
            error_code = sign_up_status.details.error_code
            log.error(f'Signin endpoint error: {error_code}')
            status_code = error_code or 500
        case _:
            log.info(f'User signed up: {credentials.id}')
            status_code = status.HTTP_201_CREATED
    return JSONResponse(content=sign_up_status.model_dump(), status_code=status_code)


@app.post('/login')
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> JSONResponse:
    """Login endpoint.

    Returns a JWT token to access other endpoints through OAuth2.
    """
    try:
        credentials =oauth2form_to_credentials(form_data=form)
    except ValidationError as err:
        output_status = ost.api_invalid_credentials_format_status()
        output_status.details.data = {'errors': err.errors()}
        return JSONResponse(
            content=output_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    login_status = srv.authentication(credentials=credentials)
    match login_status:
        case (
            sch.OutputStatus(status='incorrect_login_credentials') |
            sch.OutputStatus(status='email_not_validated')
        ):
            log.warning(f'Login non authorized: {credentials.id}')
            status_code = status.HTTP_401_UNAUTHORIZED
        case sch.OutputStatus(status='http_error'):
            error_code = login_status.details.error_code
            log.error(f'login endpoint error: {error_code}')
            status_code = error_code or 500
        case sch.OutputStatus(status='user_already_logged_in'):
            log.info(f'User already logged in: {credentials.id}')
            status_code = status.HTTP_200_OK
        case sch.OutputStatus(status='successfully_logged_in'):
            log.info(f'User logged in: {credentials.id}')
            status_code = status.HTTP_200_OK
    return JSONResponse(content=login_status.model_dump(), status_code=status_code)

# ==================================================================================================
#  Email confirmation functionality
# ==================================================================================================
@app.post('/confirm-email-api')
def confirm_email_api(token_data: sch.EmailConfirmationToken) -> JSONResponse:
    """Receives email token confirmation through RESTful API."""
    email_confirmation_token = sch.EmailConfirmationToken.model_validate(token_data)
    token = email_confirmation_token.token
    confirmation_status = srv.check_email_confirmation(token=token)
    email = (
        confirmation_status.details.data.get('email', '') if confirmation_status.details.data
        else ''
    )
    match confirmation_status:
        case (
            sch.OutputStatus(status='invalid_token') |
            sch.OutputStatus(status='expired_token')
        ):
            log.error(f'Invalid token: {token}')
            status_code = status.HTTP_400_BAD_REQUEST
        case sch.OutputStatus(status='inexistent_token'):
            log.error(f'Inexistent token: {token}')
            status_code = status.HTTP_404_NOT_FOUND
        case sch.OutputStatus(status='previously_confirmed'):
            log.warning(f'Email already confirmed: {email}')
            status_code = status.HTTP_409_CONFLICT
        case sch.OutputStatus(status='http_error'):
            error_code = confirmation_status.details.error_code
            log.error(f'confirm-mail endpoint error: {error_code}')
            status_code = error_code or 500
        case _:
            log.info(f'User email confirmed: {email}')
            status_code = status.HTTP_200_OK
    return JSONResponse(content=confirmation_status.model_dump(), status_code=status_code)

@app.get('/confirm-email')
def confirm_email(token: str, request: Request) -> HTMLResponse:
    """Receives email token confirmation through an HTML URL."""
    confirmation_status = srv.check_email_confirmation(token=token)
    token = (
        confirmation_status.details.data.get('token', '')
        if confirmation_status.details.data else ''
    )
    email = (
        confirmation_status.details.data.get('email', '')
        if confirmation_status.details.data else ''
    )

    error_msg_template = """<h2>Unfortunately an error occurred:</h2></br>
    <div class="tab">
        {error_msg}
    </div>
    """
    match confirmation_status:
        case (
            sch.OutputStatus(status='invalid_token') |
            sch.OutputStatus(status='expired_token')
        ):
            log.error(f'Invalid token: {token}')
            message = error_msg_template.format(
                error_msg='The confirmation link is corrupted or expired.'
            )
        case sch.OutputStatus(status='inexistent_token'):
            log.error(f'Inexistent token: {token}')
            message = error_msg_template.format(
                error_msg='There is no sign up corresponding to the confirmation link.'
            )
        case sch.OutputStatus(status='previously_confirmed'):
            log.warning(f'Email already confirmed: {email}')
            message = f""" Your email address was confirmed previously. </br>
            You can just log in on:</br>
                <div class="tab">
                    {request.base_url}/login</br>
                </div>
            to access our platform.
            """
        case sch.OutputStatus(status='http_error'):
            error_code = confirmation_status.details.error_code
            log.error(f'confirm-mail endpoint error: {error_code}')
            message = error_msg_template.format(
                error_msg=f"""Our servers couldn't process your requests (HTTP error: {error_code})<br>
                Try to click on the link later, if the error persists, contact our support.
                """
            )
        case _:
            log.info(f'User email confirmed: {email}')
            message = f""" <h2>Thank you for confirm your email.</h2> </br>
            Now you can log in on:</br>
                <div class="tab">
                    {request.base_url}login</br>
                </div>
            to access our platform.
            """
    # TODO: Use some template mechanism (like Jinja) to provide a better message template.
    content = f"""<html>
        <head>
            <style type="text/css">
            <!--
            .tab {{ margin-left: 40px; }}
            -->
            </style>
        </head>
        <body>
            <div>
                {message}
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=content)

# ==================================================================================================
#  Recipes functionality
# ==================================================================================================
@app.post('/load-recipes')
def load_recipes(
    token: Annotated[str, Depends(oauth2_scheme)],
    recipes_csv: UploadFile
) -> JSONResponse:
    """Load a .csv file with recipes content to the `recipe` database."""
    token_status = srv.handle_token(token=token)
    if token_status.status in ('invalid_token', 'expired_token'):
        return JSONResponse(
            content=token_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    token_user = token_status.details.data.get('sub')
    if not token_user or token_user != config.APP_ADM_USER:
        token_status.status = 'invalid_user'
        token_status.details.description = 'Only application admin can load recipes.'
        token_status.error = True
        return JSONResponse(
            content=token_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )

    csv_import_status = srv.import_csv_recipes(csv_file=recipes_csv.file)

    match csv_import_status:
        case (
                sch.OutputStatus(status='invalid_csv_format') |
                sch.OutputStatus(status='invalid_csv_content')
            ):
            log.error(csv_import_status.details.description)
            output_status = csv_import_status
            status_code = status.HTTP_400_BAD_REQUEST
        case _:
            recipes_errors = {}
            for recipe in csv_import_status.details.data['recipes']:
                store_recipe_status = srv.store_recipe(recipe)
                if store_recipe_status.status == 'error_storing_recipe':
                    recipes_errors[recipe.id] = store_recipe_status.details.data
            if recipes_errors:
                output_status = ost.api_error_loading_recipe_status()
                output_status.details.data = recipes_errors
                status_code = status.HTTP_400_BAD_REQUEST
            else:
                output_status = ost.api_recipes_loaded_status()
                status_code = status.HTTP_201_CREATED
    return JSONResponse(content=output_status.model_dump(), status_code=status_code)

@app.get('/get-all-recipes')
def get_all_recipes(token: Annotated[str, Depends(oauth2_scheme)]) -> JSONResponse:
    """Return all recipes with basic information and status regarding the user."""
    token_status = srv.handle_token(token=token)
    if token_status.status in ('invalid_token', 'expired_token'):
        return JSONResponse(
            content=token_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    user_id = token_status.details.data.get('sub', '')
    all_recipes_service_status = srv.get_all_recipes()
    user_recipes_service_status = srv.get_user_recipes(user_id=user_id)

    if all_recipes_service_status.error:
        status_code = status.HTTP_400_BAD_REQUEST
        output_status = ost.api_error_getting_all_recipes_status()
        output_status.details.data = all_recipes_service_status.details.data
        log.error(output_status.details.description)
    elif user_recipes_service_status.error:
        status_code = status.HTTP_400_BAD_REQUEST
        output_status = ost.api_error_getting_all_recipes_status()
        output_status.details.data = user_recipes_service_status.details.data
        log.error(output_status.details.description)
    else:
        all_recipes = all_recipes_service_status.details.data['all_recipes']
        user_recipes = user_recipes_service_status.details.data['user_recipes']
        user_recipe_status_mapping = {
            recipe.recipe_id: sch.RecipeStatus(value=recipe.status)
            for recipe in user_recipes
        }

        resulting_recipes = []
        for recipe in all_recipes:
            exclude_fields = {'recipe'}
            if recipe.id in user_recipe_status_mapping:
                exclude_fields.add('price')
                recipe.status = user_recipe_status_mapping[recipe.id]
            resulting_recipes.append(recipe.to_json(exclude=exclude_fields))

        status_code = status.HTTP_200_OK
        output_status = ost.api_all_recipes_status()
        output_status.details.data = {'all_recipes': resulting_recipes}

    return JSONResponse(content=output_status.model_dump(), status_code=status_code)

@app.get('/get-recipe-details/{recipe_id}')
def get_recipe_details(
    token: Annotated[str, Depends(oauth2_scheme)],
    recipe_id: str,
) -> JSONResponse:
    """Return specific recipe with information and status regarding the user."""
    token_status = srv.handle_token(token=token)
    if token_status.status in ('invalid_token', 'expired_token'):
        return JSONResponse(
            content=token_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    user_id = token_status.details.data.get('sub', '')

    recipe_service_status = srv.get_specific_recipe(recipe_id=recipe_id)
    user_recipes_service_status = srv.get_user_recipes(user_id=user_id)

    if recipe_service_status.error:
        status_code = status.HTTP_400_BAD_REQUEST
        output_status = ost.api_error_getting_recipe_details_status()
        output_status.details.data = recipe_service_status.details.data
        log.error(output_status.details.description)
    elif user_recipes_service_status.error:
        status_code = status.HTTP_400_BAD_REQUEST
        output_status = ost.api_error_getting_recipe_details_status()
        output_status.details.data = user_recipes_service_status.details.data
        log.error(output_status.details.description)
    else:
        specific_recipe = recipe_service_status.details.data['recipe']
        user_recipes = user_recipes_service_status.details.data['user_recipes']
        user_recipe_status_mapping = {
            recipe.recipe_id: sch.RecipeStatus(value=recipe.status)
            for recipe in user_recipes
        }

        exclude_fields = set()
        if specific_recipe.id in user_recipe_status_mapping:
            exclude_fields.add('price')
            specific_recipe.status = user_recipe_status_mapping[specific_recipe.id]
            if specific_recipe.status == 'requested':
                exclude_fields.add('recipe')
        resulting_recipe = specific_recipe.to_json(exclude=exclude_fields)

        status_code = status.HTTP_200_OK
        output_status = ost.api_recipe_details_status()
        output_status.details.data = {'recipe': resulting_recipe}

    return JSONResponse(content=output_status.model_dump(), status_code=status_code)

# ==================================================================================================
#  Purchasing functionality
# ==================================================================================================
@app.post('/buy-recipe/{recipe_id}')
def buy_recipe(
    token: Annotated[str, Depends(oauth2_scheme)],
    recipe_id: str,
    encr_payment_info: sch.PaymentEncrInfo,
) -> JSONResponse:
    """Send encrypted payment information to buy the recipe."""
    token_status = srv.handle_token(token=token)
    if token_status.status in ('invalid_token', 'expired_token'):
        return JSONResponse(
            content=token_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    user_id = token_status.details.data.get('sub', '')

    checkout_status = srv.start_checkout(
        user_id=user_id,
        recipe_id=recipe_id,
        payment_encr_info=encr_payment_info.encr_info
    )

    if checkout_status.error:
        output_status = checkout_status
        status_code = checkout_status.details.error_code or status.HTTP_422_UNPROCESSABLE_ENTITY
        log.error(output_status.details.description)
    else:
        output_status = ost.api_buy_recipe_status()
        status_code = status.HTTP_201_CREATED

    return JSONResponse(content=output_status.model_dump(), status_code=status_code)

@app.post('/payment-webhook/{checkout_id}')
def payment_webhook(
    checkout_id: str,
    webhook_payment_info: sch.WebhookPaymentInfo,
) -> JSONResponse:
    """Receive payment status notification from payment provider."""

    update_payment_status_status = srv.update_payment_status(
        checkout_id=checkout_id,
        webhook_payment_info=webhook_payment_info,
    )

    if update_payment_status_status.error:
        output_status = update_payment_status_status
        status_code = (
            update_payment_status_status.details.error_code or status.HTTP_422_UNPROCESSABLE_ENTITY
        )
        log.error(output_status.details.description)
    else:
        output_status = ost.api_payment_webhook_status()
        status_code = status.HTTP_202_ACCEPTED

    return JSONResponse(content=output_status.model_dump(), status_code=status_code)



# ==================================================================================================
#  Payment Provider Simulator
# ==================================================================================================
@app.post('/create-checkout/{recipe_id}')
def create_checkout(
    recipe_id: str,
    payment_checkout_info: sch.PaymentCheckoutInfo,
) -> JSONResponse:
    """Simulate the Payment provider endpoint that accepts checkout requisitions."""
    api_key = payment_checkout_info.api_key
    if api_key == config.PAYMENT_PROVIDER_API_KEY:
        checkout_id = str(uuid4())

        try:
            payment_info = sch.PaymentCcInfo.decrypt(
                payment_checkout_info.payment_encr_info.encr_info
            )
            # Use `payment_info` to charge the credit card through an operator.
            payment_info # ...

            payment_process_status = srv.payment_processing(
                checkout_id=checkout_id,
                recipe_id=recipe_id
            )

            if payment_process_status.error:
                output_status = payment_process_status
                status_code = (
                    payment_process_status.details.error_code or
                    status.HTTP_422_UNPROCESSABLE_ENTITY
                )
            else:
                output_status = ost.pprovider_create_checkout_status()
                output_status.details.data = {'checkout_id': checkout_id}
                status_code = status.HTTP_201_CREATED
        except (ValidationError, InvalidToken) as err:
            output_status = ost.pprovider_payment_info_error_status()
            if hasattr(err, 'errors'):
                output_status.details.data = {'errors': err.errors()}
            status_code = status.HTTP_400_BAD_REQUEST
    else:
        output_status = ost.pprovider_api_key_error_status()
        status_code = status.HTTP_401_UNAUTHORIZED

    return JSONResponse(content=output_status.model_dump(), status_code=status_code)
