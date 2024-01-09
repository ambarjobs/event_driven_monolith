# ==================================================================================================
#  Application endpoints
# ==================================================================================================
from typing import Annotated

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import ExpiredSignatureError, JWTError
from pydantic import SecretStr

import core
import schemas as sch
import services as srv
import utils
from config import logging as log
from core import oauth2_scheme


core.init_app_databases(core.APP_DATABASES_INFO)
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
@app.post('/signin')
def signin(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
    request: Request,
) -> JSONResponse:
    """Sign in endpoint."""
    sign_in_status = srv.user_sign_in(
        credentials=credentials,
        user_info=user_info,
        base_url=str(request.base_url)
    )
    match sign_in_status:
        case sch.ServiceStatus(status='user_already_signed_in'):
            log.warning(f'User already signed in: {credentials.id}')
            status_code = status.HTTP_409_CONFLICT
        case sch.ServiceStatus(status='http_error'):
            error_code = sign_in_status.details.error_code
            log.error(f'Signin endpoint error: {error_code}')
            status_code = error_code or 500
        case _:
            log.info(f'User signed in: {credentials.id}')
            status_code = status.HTTP_201_CREATED
    return JSONResponse(content=sign_in_status.model_dump(), status_code=status_code)


@app.post('/login')
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> JSONResponse:
    """Login endpoint.

    Returns a JWT token to access other endpoints through OAuth2.
    """
    credentials =oauth2form_to_credentials(form_data=form)
    login_status = srv.authentication(credentials=credentials)
    match login_status:
        case (
            sch.ServiceStatus(status='incorrect_login_credentials') |
            sch.ServiceStatus(status='email_not_validated') |
            sch.ServiceStatus(status='user_already_signed_in')
        ):
            log.warning(f'Login non authorized: {credentials.id}')
            status_code = status.HTTP_401_UNAUTHORIZED
        case sch.ServiceStatus(status='http_error'):
            error_code = login_status.details.error_code
            log.error(f'login endpoint error: {error_code}')
            status_code = error_code or 500
        case _:
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
                error_msg='There is no sign in corresponding to the confirmation link.'
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


@app.get('/tst')
def test(token: Annotated[str, Depends(oauth2_scheme)]):
    """Example endpoint using JWT OAuth2 authentication."""
    # ------------------------------------------------------------------------------------------
    #   Output status
    # ------------------------------------------------------------------------------------------
    ok_status = sch.ServiceStatus(
        status='ok',
        error=False,
        details=sch.StatusDetails(
            description='Test was well.'
        ),
    )

    invalid_token_status = sch.ServiceStatus(
        status='invalid_token',
        error=True,
        details=sch.StatusDetails(
            description='Invalid token.'
        ),
    )

    expired_token_status = sch.ServiceStatus(
        status='expired_token',
        error=True,
        details=sch.StatusDetails(
            description='The token has expired.'
        ),
    )
    # ------------------------------------------------------------------------------------------
    try:
        payload = utils.get_token_payload(token=token)
        content_data = ok_status
        content_data.details.data = payload
        status_code = status.HTTP_200_OK
    except (JWTError, ExpiredSignatureError) as err:
        status_code = status.HTTP_400_BAD_REQUEST
        match err:
            case JWTError():
                content_data = invalid_token_status
                content_data.details.description = f'Invalid token: {err}'
            case ExpiredSignatureError():
                content_data = expired_token_status
                content_data.details.description = f'The token has expired, log in again: {err}'
    return JSONResponse(content=content_data.model_dump(), status_code=status_code)
