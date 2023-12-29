# ==================================================================================================
#  Application endpoints
# ==================================================================================================
from typing import Annotated

from fastapi import Depends, FastAPI, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import SecretStr

import core
import schemas as sch
import services as srv
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
    user_info: sch.UserInfo
) -> JSONResponse:
    """Sign in endpoint."""
    result = srv.user_sign_in(credentials=credentials, user_info=user_info)
    result_sch = sch.ServiceStatus(**result)
    if result_sch.status == 'user_already_signed_in':
        log.warning(f'User already signed in: {credentials.id}')
        return JSONResponse(content=result, status_code=status.HTTP_409_CONFLICT)
    if result_sch.error and result_sch.status == 'http_error':
        error_code = result_sch.details.error_code
        log.error(f'Signin endpoint error: {error_code}')
        return JSONResponse(
            content=result,
            status_code=error_code or 500
        )
    log.info(f'User signed in: {credentials.id}')
    return JSONResponse(content=result, status_code=status.HTTP_201_CREATED)


@app.post('/login')
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> JSONResponse:
    credentials =oauth2form_to_credentials(form_data=form)
    login_data = srv.authentication(credentials=credentials)
    login_status = sch.ServiceStatus(**login_data)
    match login_status:
        case (sch.ServiceStatus(status='incorrect_login_credentials') |
            sch.ServiceStatus(status='email_not_validated') |
            sch.ServiceStatus(status='user_already_signed_in')
        ):
            log.warning(f'Login non authorized: {credentials.id}')
            return JSONResponse(content=login_data, status_code=status.HTTP_401_UNAUTHORIZED)
        case sch.ServiceStatus(status='http_error'):
            error_code = login_status.details.error_code
            log.error(f'Login endpoint error: {error_code}')
            return JSONResponse(
                content=login_data,
                status_code=error_code or 500
            )
        case _:
            log.info(f'User logged in: {credentials.id}')
            return JSONResponse(content=login_data, status_code=status.HTTP_200_OK)


@app.get('/tst')
def teste(token: Annotated[str, Depends(oauth2_scheme)]):
# def teste():
    return {'status': 'OK'}
# @app.post('/stores/add', status_code=status.HTTP_201_CREATED)
# def add_store(store: srlz.StoreIn):
#     """Adiciona uma loja."""
#     try:
#         with db_session:
#             store_name = store.name
#             mdl.Store(name=store_name)
#             return {'msg': f'A loja [{store_name}] foi adicionada.'}
#     except TransactionIntegrityError:
#         content = {
#             'error': f'Loja [{store_name}] já existe.',
#             'code': ErrorCode.store.unique,
#         }
#         status_code = status.HTTP_400_BAD_REQUEST
#         return JSONResponse(content=content, status_code=status_code)
