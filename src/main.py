# ==================================================================================================
#  Application endpoints
# ==================================================================================================
from typing import Annotated

from fastapi import Depends, FastAPI, Request, status, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import SecretStr, ValidationError

import config
import core
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
#  Sign in
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
        case sch.ServiceStatus(status='user_already_signed_up'):
            log.warning(f'User already signed up: {credentials.id}')
            status_code = status.HTTP_409_CONFLICT
        case sch.ServiceStatus(status='http_error'):
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
    # ----------------------------------------------------------------------------------------------
    #   Output status
    # ----------------------------------------------------------------------------------------------
    invalid_credentials_format_status = sch.ServiceStatus(
            status='invalid_credentials_format',
            error=True,
            details=sch.StatusDetails(description='The credentials are in an invalid format.'),
        )
    # ----------------------------------------------------------------------------------------------
    try:
        credentials =oauth2form_to_credentials(form_data=form)
    except ValidationError as err:
        invalid_credentials_format_status.details.data = {'errors': err.errors()}
        return JSONResponse(
            content=invalid_credentials_format_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    login_status = srv.authentication(credentials=credentials)
    match login_status:
        case (
            sch.ServiceStatus(status='incorrect_login_credentials') |
            sch.ServiceStatus(status='email_not_validated')
        ):
            log.warning(f'Login non authorized: {credentials.id}')
            status_code = status.HTTP_401_UNAUTHORIZED
        case sch.ServiceStatus(status='http_error'):
            error_code = login_status.details.error_code
            log.error(f'login endpoint error: {error_code}')
            status_code = error_code or 500
        case sch.ServiceStatus(status='user_already_logged_in'):
            log.info(f'User already logged in: {credentials.id}')
            status_code = status.HTTP_200_OK
        case sch.ServiceStatus(status='successfully_logged_in'):
            log.info(f'User logged in: {credentials.id}')
            status_code = status.HTTP_200_OK
    return JSONResponse(content=login_status.model_dump(), status_code=status_code)

# ==================================================================================================
#  Email confirmation
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
            sch.ServiceStatus(status='invalid_token') |
            sch.ServiceStatus(status='expired_token')
        ):
            log.error(f'Invalid token: {token}')
            status_code = status.HTTP_400_BAD_REQUEST
        case sch.ServiceStatus(status='inexistent_token'):
            log.error(f'Inexistent token: {token}')
            status_code = status.HTTP_404_NOT_FOUND
        case sch.ServiceStatus(status='previously_confirmed'):
            log.warning(f'Email already confirmed: {email}')
            status_code = status.HTTP_409_CONFLICT
        case sch.ServiceStatus(status='http_error'):
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
            sch.ServiceStatus(status='invalid_token') |
            sch.ServiceStatus(status='expired_token')
        ):
            log.error(f'Invalid token: {token}')
            message = error_msg_template.format(
                error_msg='The confirmation link is corrupted or expired.'
            )
        case sch.ServiceStatus(status='inexistent_token'):
            log.error(f'Inexistent token: {token}')
            message = error_msg_template.format(
                error_msg='There is no sign up corresponding to the confirmation link.'
            )
        case sch.ServiceStatus(status='previously_confirmed'):
            log.warning(f'Email already confirmed: {email}')
            message = f""" Your email address was confirmed previously. </br>
            You can just log in on:</br>
                <div class="tab">
                    {request.base_url}/login</br>
                </div>
            to access our platform.
            """
        case sch.ServiceStatus(status='http_error'):
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
#  Recipes
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

    recipes = srv.import_csv_recipes(csv_file=recipes_csv.file)
    for recipe in recipes:
        srv.store_recipe(recipe)

    token_status.status = 'recipes_loaded'
    token_status.details.description = 'Recipes loaded with success.'
    return JSONResponse(content=token_status.model_dump(), status_code=status.HTTP_201_CREATED)

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
    all_recipes = srv.get_all_recipes()
    user_recipes = srv.get_user_recipes(user_id=user_id)
    # Converts recipe.status to str be it Recipe.Status or already a str
    user_mapping = {recipe.recipe_id: recipe.status.strip('') for recipe in user_recipes}

    resulting_recipes = []
    for recipe in all_recipes:
        exclude_fields = {'recipe'}
        if recipe.id in user_mapping:
            exclude_fields.add('price')
            recipe.status = sch.RecipeStatus(value=user_mapping[recipe.id])
        resulting_recipes.append(recipe.to_json(exclude=exclude_fields))
    return JSONResponse(content={'recipes': resulting_recipes}, status_code=status.HTTP_200_OK)


# ==================================================================================================
@app.get('/tst')
def test(token: Annotated[str, Depends(oauth2_scheme)]) -> JSONResponse:
    """Example endpoint using JWT OAuth2 authentication."""
    token_status = srv.handle_token(token=token)
    if token_status.status in ('invalid_token', 'expired_token'):
        return JSONResponse(
            content=token_status.model_dump(),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    token_status.status = 'ok'
    token_status.details.description = 'Test was well.'
    return JSONResponse(content=token_status.model_dump(), status_code=status.HTTP_201_CREATED)
